//! Multi-endpoint connector with failover and optional load balancing.
//!
//! [`ClusterConnector`] wraps a pool of per-endpoint [`Connector`]s and, on
//! every [`connect`](Connector::connect), scans the pool from a *start index*
//! that depends on the [`ClusterMode`]:
//!
//! - [`ClusterMode::Failover`] always starts at the first endpoint, so a healthy
//!   leading endpoint is always preferred;
//! - [`ClusterMode::RoundRobin`] rotates the start index per connection, so
//!   successive connections spread across the pool (connection-level load
//!   balancing).
//!
//! In both modes the scan then behaves identically:
//!
//! - endpoints are visited in order from the start index, wrapping around;
//! - an endpoint whose last dial failed within the cooldown window is skipped;
//! - the first healthy endpoint wins and its cooldown is cleared;
//! - if every endpoint fails this pass, that error is returned; if every
//!   endpoint was instead *skipped* for cooldown, the start endpoint is probed
//!   once as a "came back up" check.
//!
//! Because the [`Client`](super::Client) reconnects through its [`Connector`]
//! on a dropped connection (see `roundtrip_ttlv`), this applies both at
//! session/clone open and on a mid-session reconnect — so the round-robin
//! cursor also advances on reconnect and `try_clone`.

use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use super::{Connector, Transport};
use crate::{Error, Result};

/// Default per-endpoint cooldown window.
pub const DEFAULT_RETRY_COOLDOWN: Duration = Duration::from_secs(5);

/// How a [`ClusterConnector`] picks which endpoint to dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClusterMode {
    /// Always scan endpoints in configured order; the first healthy endpoint
    /// wins. A leading healthy endpoint is always preferred.
    #[default]
    Failover,
    /// Rotate the scan's start index per connection so successive connections
    /// spread across the pool (connection-level load balancing). Cooled-down
    /// endpoints are still skipped and failover to a healthy endpoint applies.
    ///
    /// Note: a [`Client`](super::Client) reconnect (e.g. after a dropped
    /// connection, see `roundtrip_ttlv`) goes through `connect()` and so
    /// advances the rotation — a reconnect typically lands on a *different*
    /// endpoint than the one the session opened on. This is harmless for
    /// self-contained KMIP requests (the cached protocol version is reused, fine
    /// for a homogeneous cluster), but it is unsuitable for operations that rely
    /// on server-side state pinned to one connection/node (e.g. multi-part
    /// crypto keyed by a correlation value). [`Failover`](Self::Failover) can
    /// also switch nodes on reconnect (it re-prefers a recovered leading
    /// endpoint), so connection-pinned state is fragile across reconnects in
    /// either mode.
    RoundRobin,
}

struct Endpoint {
    connector: Arc<dyn Connector>,
    /// Instant of the last failed dial, or `None` if the last dial succeeded /
    /// none has happened yet. Endpoints inside the cooldown window are skipped.
    last_failure: Mutex<Option<Instant>>,
}

/// A [`Connector`] that dials a pool of endpoints with failover and optional
/// load balancing. See the [`ClusterMode`] variants for the exact selection
/// semantics.
pub struct ClusterConnector {
    endpoints: Vec<Endpoint>,
    cooldown: Duration,
    mode: ClusterMode,
    /// Round-robin cursor; only consulted in [`ClusterMode::RoundRobin`].
    cursor: AtomicUsize,
}

impl ClusterConnector {
    /// Builds a [`ClusterMode::Failover`] connector from per-endpoint connectors
    /// and a cooldown window. Returns an error if `connectors` is empty.
    pub fn new(
        connectors: impl IntoIterator<Item = Arc<dyn Connector>>,
        cooldown: Duration,
    ) -> Result<Self> {
        Self::with_mode(connectors, cooldown, ClusterMode::default())
    }

    /// Like [`Self::new`], but selects the endpoint-selection [`ClusterMode`].
    pub fn with_mode(
        connectors: impl IntoIterator<Item = Arc<dyn Connector>>,
        cooldown: Duration,
        mode: ClusterMode,
    ) -> Result<Self> {
        let endpoints: Vec<_> = connectors
            .into_iter()
            .map(|connector| Endpoint {
                connector,
                last_failure: Mutex::new(None),
            })
            .collect();
        if endpoints.is_empty() {
            return Err(Error::IO(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one endpoint is required for a cluster connector",
            )));
        }
        Ok(Self {
            endpoints,
            cooldown,
            mode,
            cursor: AtomicUsize::new(0),
        })
    }

    /// Index of the endpoint the next scan starts from. Failover always starts
    /// at 0; round-robin advances a cursor so connections spread across the pool.
    fn start_index(&self) -> usize {
        match self.mode {
            ClusterMode::Failover => 0,
            ClusterMode::RoundRobin => {
                self.cursor.fetch_add(1, Ordering::Relaxed) % self.endpoints.len()
            }
        }
    }

    fn in_cooldown(&self, endpoint: &Endpoint) -> bool {
        endpoint
            .last_failure
            .lock()
            .expect("cluster cooldown mutex poisoned")
            .is_some_and(|at| at.elapsed() < self.cooldown)
    }

    /// Dials one endpoint, stamping its cooldown state: cleared on success, set
    /// to the current instant on failure.
    fn attempt(&self, endpoint: &Endpoint) -> Result<Box<dyn Transport>> {
        let result = endpoint.connector.connect();
        *endpoint
            .last_failure
            .lock()
            .expect("cluster cooldown mutex poisoned") = result.is_err().then(Instant::now);
        result
    }
}

impl Connector for ClusterConnector {
    fn connect(&self) -> Result<Box<dyn Transport>> {
        let n = self.endpoints.len();
        let start = self.start_index();
        let mut last_error = None;
        for offset in 0..n {
            let endpoint = &self.endpoints[(start + offset) % n];
            if self.in_cooldown(endpoint) {
                continue;
            }
            match self.attempt(endpoint) {
                Ok(transport) => return Ok(transport),
                Err(e) => last_error = Some(e),
            }
        }

        // If any live endpoint was dialed this pass, its failure is the freshest
        // real error and is returned as-is. Otherwise every endpoint was skipped
        // for cooldown, so give the start endpoint one "came back up" probe
        // (`with_mode` guarantees a non-empty pool).
        match last_error {
            Some(error) => Err(error),
            None => self.attempt(&self.endpoints[start]),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A connector whose successive `connect()` results are scripted; counts
    /// how many times it was dialed.
    struct ScriptedConnector {
        results: Vec<bool>, // true = success, false = failure
        calls: AtomicUsize,
    }

    impl ScriptedConnector {
        fn new(results: Vec<bool>) -> Arc<Self> {
            Arc::new(Self {
                results,
                calls: AtomicUsize::new(0),
            })
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Connector for ScriptedConnector {
        fn connect(&self) -> Result<Box<dyn Transport>> {
            let idx = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.results.get(idx).copied().unwrap_or(false) {
                Ok(Box::new(io::Cursor::new(Vec::new())))
            } else {
                Err(Error::IO(io::Error::other("scripted failure")))
            }
        }
    }

    /// An always-succeeding connector, for the round-robin distribution tests.
    fn healthy() -> Arc<ScriptedConnector> {
        ScriptedConnector::new(vec![true; 4])
    }

    /// Builds a cluster from the given endpoint handles, keeping the concrete
    /// `Arc<ScriptedConnector>` handles so tests can assert on `.calls()`.
    fn cluster(
        endpoints: &[Arc<ScriptedConnector>],
        cooldown: Duration,
        mode: ClusterMode,
    ) -> ClusterConnector {
        ClusterConnector::with_mode(
            endpoints
                .iter()
                .map(|e| e.clone() as Arc<dyn Connector>)
                .collect::<Vec<_>>(),
            cooldown,
            mode,
        )
        .unwrap()
    }

    #[test]
    fn empty_endpoints_is_rejected() {
        let r = ClusterConnector::new(Vec::<Arc<dyn Connector>>::new(), DEFAULT_RETRY_COOLDOWN);
        assert!(r.is_err());
    }

    #[test]
    fn fails_over_to_second_endpoint() {
        let eps = [
            ScriptedConnector::new(vec![false]), // first endpoint down
            ScriptedConnector::new(vec![true]),  // second healthy
        ];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::Failover);
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 1);
        assert_eq!(eps[1].calls(), 1);
    }

    #[test]
    fn cooldown_skips_recently_failed_endpoint() {
        let eps = [
            ScriptedConnector::new(vec![false, true]), // would succeed on 2nd try
            healthy(),
        ];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::Failover);

        // First connect: endpoint 0 fails (enters cooldown), endpoint 1 serves.
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 1);

        // Second connect: endpoint 0 is in cooldown and must be skipped; the
        // healthy endpoint 1 serves again without re-dialing endpoint 0.
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 1);
        assert_eq!(eps[1].calls(), 2);
    }

    #[test]
    fn all_failing_this_pass_returns_the_error_without_re_dialing() {
        // Both endpoints are live (not cooling) and fail: the loop dials each
        // exactly once and the start endpoint is NOT re-probed.
        let eps = [
            ScriptedConnector::new(vec![false, false]),
            ScriptedConnector::new(vec![false, false]),
        ];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::Failover);
        assert!(c.connect().is_err());
        assert_eq!(eps[0].calls(), 1); // dialed once, not twice
        assert_eq!(eps[1].calls(), 1);
    }

    #[test]
    fn probes_start_when_all_in_cooldown() {
        let eps = [
            ScriptedConnector::new(vec![false, true]), // fails, then recovers
            ScriptedConnector::new(vec![false]),       // stays down
        ];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::Failover);

        // #1: both fail this pass and enter cooldown -> error, each dialed once.
        assert!(c.connect().is_err());
        assert_eq!(eps[0].calls(), 1);
        assert_eq!(eps[1].calls(), 1);

        // #2: both are in cooldown, so the loop skips them and the start
        // endpoint gets one "came back up" probe, which now recovers.
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 2); // the probe
        assert_eq!(eps[1].calls(), 1); // skipped, not re-dialed
    }

    #[test]
    fn cooled_start_is_not_reprobed_when_a_live_endpoint_fails() {
        let eps = [
            ScriptedConnector::new(vec![false]),       // ep0: down -> cools
            ScriptedConnector::new(vec![true, false]), // ep1: ok first, then fails
            ScriptedConnector::new(vec![false]),       // ep2: down
        ];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::Failover);

        // #1 setup: ep0 fails (enters cooldown), ep1 succeeds and ends the pass,
        // so ep1/ep2 are left un-cooled.
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 1);
        assert_eq!(eps[1].calls(), 1);
        assert_eq!(eps[2].calls(), 0);

        // #2: ep0 is skipped for cooldown; ep1 and ep2 are live and fail this
        // pass. The fresh live error is returned and the cooled start endpoint
        // must NOT be re-probed (that was the bug the fallback guard caused).
        assert!(c.connect().is_err());
        assert_eq!(eps[0].calls(), 1); // cooled start left alone
        assert_eq!(eps[1].calls(), 2);
        assert_eq!(eps[2].calls(), 1);
    }

    #[test]
    fn zero_cooldown_retries_immediately() {
        let eps = [
            ScriptedConnector::new(vec![false, true]), // fails, then recovers
            ScriptedConnector::new(vec![false]),       // down
        ];
        let c = cluster(&eps, Duration::ZERO, ClusterMode::Failover);

        // #1: both fail this pass -> error; endpoint 0 dialed once.
        assert!(c.connect().is_err());
        assert_eq!(eps[0].calls(), 1);

        // #2: zero cooldown means endpoint 0 is NOT skipped and is dialed again,
        // now succeeding.
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 2);
    }

    #[test]
    fn round_robin_distributes_across_endpoints() {
        let eps = [healthy(), healthy(), healthy()];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::RoundRobin);

        // Three connects rotate the start index 0,1,2: each endpoint dialed once.
        for _ in 0..3 {
            assert!(c.connect().is_ok());
        }
        assert_eq!(eps[0].calls(), 1);
        assert_eq!(eps[1].calls(), 1);
        assert_eq!(eps[2].calls(), 1);
    }

    #[test]
    fn round_robin_wraps_past_the_end() {
        let eps = [healthy(), healthy(), healthy()];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::RoundRobin);

        // Four connects: starts 0,1,2 then wraps back to 0.
        for _ in 0..4 {
            assert!(c.connect().is_ok());
        }
        assert_eq!(eps[0].calls(), 2);
        assert_eq!(eps[1].calls(), 1);
        assert_eq!(eps[2].calls(), 1);
    }

    #[test]
    fn round_robin_skips_cooled_down_endpoint() {
        let eps = [
            ScriptedConnector::new(vec![false, true, true]), // fails first
            healthy(),
        ];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::RoundRobin);

        // #1 start=0: ep0 fails (enters cooldown), ep1 serves.
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 1);
        // #2 start=1: ep1 serves directly.
        assert!(c.connect().is_ok());
        // #3 start=0: ep0 is in cooldown -> skipped, ep1 serves again.
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 1); // never re-dialed
        assert_eq!(eps[1].calls(), 3);
    }

    #[test]
    fn round_robin_fallback_probes_the_start_endpoint() {
        let eps = [
            ScriptedConnector::new(vec![false, false]), // stays down
            ScriptedConnector::new(vec![false, true]),  // recovers on 2nd dial
        ];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::RoundRobin);

        // #1 start=0: both fail this pass -> error; each dialed once.
        assert!(c.connect().is_err());
        assert_eq!(eps[0].calls(), 1);
        assert_eq!(eps[1].calls(), 1);

        // #2 start=1: both in cooldown, so the fallback probes endpoints[start=1]
        // (NOT index 0), which now recovers.
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 1); // untouched: start was 1
        assert_eq!(eps[1].calls(), 2);
    }

    // A `Client` reconnect (roundtrip_ttlv) is just another `connect()` on the
    // same connector, so the open->reconnect sequence is modelled as two
    // consecutive `connect()` calls here.

    #[test]
    fn round_robin_reconnect_lands_on_a_different_endpoint() {
        let eps = [healthy(), healthy()];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::RoundRobin);

        // Session open -> endpoint 0.
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 1);
        assert_eq!(eps[1].calls(), 0);

        // Reconnect rotates the cursor -> endpoint 1, not the one we opened on.
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 1);
        assert_eq!(eps[1].calls(), 1);
    }

    #[test]
    fn failover_reconnect_returns_to_a_recovered_leading_endpoint() {
        let eps = [
            ScriptedConnector::new(vec![false, true]), // down at open, recovers
            healthy(),
        ];
        let c = cluster(&eps, Duration::ZERO, ClusterMode::Failover);

        // Session open: endpoint 0 down -> fail over to endpoint 1.
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 1);
        assert_eq!(eps[1].calls(), 1);

        // Reconnect: Failover scans from 0 again; endpoint 0 has recovered, so
        // the session moves back to it (different node than it was just on).
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 2);
        assert_eq!(eps[1].calls(), 1); // not re-dialed
    }
}
