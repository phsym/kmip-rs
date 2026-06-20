//! Multi-endpoint connector with failover and optional load balancing.
//!
//! [`ClusterConnector`] wraps a list of per-endpoint [`Connector`]s and, on
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
//! - an endpoint whose last dial failed within the cooldown window
//!   (`retry_timeout`) is skipped;
//! - the first healthy endpoint wins and its cooldown is cleared;
//! - if every endpoint is in cooldown or fails, the **start** endpoint is
//!   probed once as a "came back up" check.
//!
//! Because the [`Client`](super::Client) reconnects through its [`Connector`]
//! on a dropped connection (see `roundtrip_ttlv`), this applies both at
//! session/clone open and on a mid-session reconnect — so the round-robin
//! cursor also advances on reconnect and `try_clone`.

use std::{
    io,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use super::Connector;
use crate::{Error, Result};

/// Default per-endpoint cooldown window.
pub const DEFAULT_RETRY_TIMEOUT: Duration = Duration::from_secs(5);

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

struct Endpoint<C: Connector> {
    connector: C,
    /// Instant of the last failed dial, or `None` if the last dial succeeded /
    /// none has happened yet. Endpoints inside the cooldown window are skipped.
    last_error: Mutex<Option<Instant>>,
}

/// A [`Connector`] that dials a pool of endpoints with failover and optional
/// load balancing. See the [`ClusterMode`] variants for the exact selection
/// semantics.
pub struct ClusterConnector<C: Connector> {
    endpoints: Vec<Endpoint<C>>,
    retry_timeout: Duration,
    mode: ClusterMode,
    /// Round-robin cursor; only consulted in [`ClusterMode::RoundRobin`].
    cursor: AtomicUsize,
}

impl<C: Connector> ClusterConnector<C> {
    /// Builds a [`ClusterMode::Failover`] connector from per-endpoint connectors
    /// and a cooldown window. Returns an error if `connectors` is empty.
    pub fn new(connectors: impl IntoIterator<Item = C>, retry_timeout: Duration) -> Result<Self> {
        Self::with_mode(connectors, retry_timeout, ClusterMode::default())
    }

    /// Like [`Self::new`], but selects the endpoint-selection [`ClusterMode`].
    pub fn with_mode(
        connectors: impl IntoIterator<Item = C>,
        retry_timeout: Duration,
        mode: ClusterMode,
    ) -> Result<Self> {
        let endpoints: Vec<_> = connectors
            .into_iter()
            .map(|connector| Endpoint {
                connector,
                last_error: Mutex::new(None),
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
            retry_timeout,
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

    fn in_cooldown(&self, endpoint: &Endpoint<C>) -> bool {
        endpoint
            .last_error
            .lock()
            .expect("cluster cooldown mutex poisoned")
            .is_some_and(|at| at.elapsed() < self.retry_timeout)
    }

    fn dial(&self, endpoint: &Endpoint<C>) -> Result<C::Transport> {
        let result = endpoint.connector.connect();
        // Stamp the failure time on error, clear the cooldown on success.
        *endpoint
            .last_error
            .lock()
            .expect("cluster cooldown mutex poisoned") = result.is_err().then(Instant::now);
        result
    }
}

impl<C: Connector> Connector for ClusterConnector<C> {
    type Transport = C::Transport;

    fn connect(&self) -> Result<Self::Transport> {
        let n = self.endpoints.len();
        let start = self.start_index();
        for offset in 0..n {
            let endpoint = &self.endpoints[(start + offset) % n];
            if self.in_cooldown(endpoint) {
                continue;
            }
            if let Ok(transport) = self.dial(endpoint) {
                return Ok(transport);
            }
        }

        // Every endpoint is in cooldown or just failed: probe the start endpoint
        // once in case it came back up. `with_mode` guarantees a non-empty list.
        self.dial(&self.endpoints[start])
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::client::Transport;

    /// A connector whose successive `connect()` results are scripted; counts
    /// how many times it was dialed.
    struct ScriptedConnector {
        results: Vec<bool>, // true = success, false = failure
        calls: AtomicUsize,
    }

    impl ScriptedConnector {
        fn new(results: Vec<bool>) -> Self {
            Self {
                results,
                calls: AtomicUsize::new(0),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Connector for ScriptedConnector {
        type Transport = Box<dyn Transport>;
        fn connect(&self) -> Result<Self::Transport> {
            let idx = self.calls.fetch_add(1, Ordering::SeqCst);
            let ok = self.results.get(idx).copied().unwrap_or(false);
            if ok {
                Ok(Box::new(io::Cursor::new(Vec::new())))
            } else {
                Err(Error::IO(io::Error::other("scripted failure")))
            }
        }
    }

    #[test]
    fn empty_endpoints_is_rejected() {
        let r = ClusterConnector::<ScriptedConnector>::new([], DEFAULT_RETRY_TIMEOUT);
        assert!(r.is_err());
    }

    #[test]
    fn fails_over_to_second_endpoint() {
        let cluster = ClusterConnector::new(
            [
                ScriptedConnector::new(vec![false]), // first endpoint down
                ScriptedConnector::new(vec![true]),  // second healthy
            ],
            DEFAULT_RETRY_TIMEOUT,
        )
        .unwrap();
        assert!(cluster.connect().is_ok());
        assert_eq!(cluster.endpoints[0].connector.calls(), 1);
        assert_eq!(cluster.endpoints[1].connector.calls(), 1);
    }

    #[test]
    fn cooldown_skips_recently_failed_endpoint() {
        let cluster = ClusterConnector::new(
            [
                ScriptedConnector::new(vec![false, true]), // would succeed on 2nd try
                ScriptedConnector::new(vec![true, true]),  // healthy
            ],
            DEFAULT_RETRY_TIMEOUT, // long cooldown so the first stays skipped
        )
        .unwrap();

        // First connect: endpoint 0 fails (enters cooldown), endpoint 1 serves.
        assert!(cluster.connect().is_ok());
        assert_eq!(cluster.endpoints[0].connector.calls(), 1);

        // Second connect: endpoint 0 is in cooldown and must be skipped; the
        // healthy endpoint 1 serves again without re-dialing endpoint 0.
        assert!(cluster.connect().is_ok());
        assert_eq!(cluster.endpoints[0].connector.calls(), 1);
        assert_eq!(cluster.endpoints[1].connector.calls(), 2);
    }

    #[test]
    fn probes_first_when_all_in_cooldown() {
        let cluster = ClusterConnector::new(
            [
                ScriptedConnector::new(vec![false, true]), // fails, then recovers
                ScriptedConnector::new(vec![false]),       // stays down
            ],
            DEFAULT_RETRY_TIMEOUT,
        )
        .unwrap();

        // First connect: both fail, then the fallback probes endpoint 0 again
        // (2nd scripted result = success).
        assert!(cluster.connect().is_ok());
        assert_eq!(cluster.endpoints[0].connector.calls(), 2);
        assert_eq!(cluster.endpoints[1].connector.calls(), 1);
    }

    #[test]
    fn zero_cooldown_retries_immediately() {
        let cluster = ClusterConnector::new(
            [
                ScriptedConnector::new(vec![false, false, true]), // fails x2, then ok
                ScriptedConnector::new(vec![false, false, false]), // always down
            ],
            Duration::ZERO, // no cooldown: endpoints are re-dialed every connect
        )
        .unwrap();

        // First connect: both fail in the loop, fallback re-probes endpoint 0
        // (still failing) -> overall error. endpoint 0 dialed twice.
        assert!(cluster.connect().is_err());
        assert_eq!(cluster.endpoints[0].connector.calls(), 2);

        // Second connect: zero cooldown means endpoint 0 is dialed again (not
        // skipped) and now succeeds.
        assert!(cluster.connect().is_ok());
        assert_eq!(cluster.endpoints[0].connector.calls(), 3);
    }

    /// A connector that always succeeds, for the round-robin distribution tests.
    fn healthy() -> ScriptedConnector {
        ScriptedConnector::new(vec![true; 4])
    }

    #[test]
    fn round_robin_distributes_across_endpoints() {
        let cluster = ClusterConnector::with_mode(
            [healthy(), healthy(), healthy()],
            DEFAULT_RETRY_TIMEOUT,
            ClusterMode::RoundRobin,
        )
        .unwrap();

        // Three connects rotate the start index 0,1,2: each endpoint dialed once.
        for _ in 0..3 {
            assert!(cluster.connect().is_ok());
        }
        assert_eq!(cluster.endpoints[0].connector.calls(), 1);
        assert_eq!(cluster.endpoints[1].connector.calls(), 1);
        assert_eq!(cluster.endpoints[2].connector.calls(), 1);
    }

    #[test]
    fn round_robin_wraps_past_the_end() {
        let cluster = ClusterConnector::with_mode(
            [healthy(), healthy(), healthy()],
            DEFAULT_RETRY_TIMEOUT,
            ClusterMode::RoundRobin,
        )
        .unwrap();

        // Four connects: starts 0,1,2 then wraps back to 0.
        for _ in 0..4 {
            assert!(cluster.connect().is_ok());
        }
        assert_eq!(cluster.endpoints[0].connector.calls(), 2);
        assert_eq!(cluster.endpoints[1].connector.calls(), 1);
        assert_eq!(cluster.endpoints[2].connector.calls(), 1);
    }

    #[test]
    fn round_robin_skips_cooled_down_endpoint() {
        let cluster = ClusterConnector::with_mode(
            [
                ScriptedConnector::new(vec![false, true, true]), // fails first
                healthy(),
            ],
            DEFAULT_RETRY_TIMEOUT, // long cooldown
            ClusterMode::RoundRobin,
        )
        .unwrap();

        // #1 start=0: ep0 fails (enters cooldown), ep1 serves.
        assert!(cluster.connect().is_ok());
        assert_eq!(cluster.endpoints[0].connector.calls(), 1);
        // #2 start=1: ep1 serves directly.
        assert!(cluster.connect().is_ok());
        // #3 start=0: ep0 is in cooldown -> skipped, ep1 serves again.
        assert!(cluster.connect().is_ok());
        assert_eq!(cluster.endpoints[0].connector.calls(), 1); // never re-dialed
        assert_eq!(cluster.endpoints[1].connector.calls(), 3);
    }

    #[test]
    fn round_robin_fallback_probes_the_start_endpoint() {
        let cluster = ClusterConnector::with_mode(
            [
                ScriptedConnector::new(vec![false, false]), // stays down
                ScriptedConnector::new(vec![false, true]),  // recovers on 2nd dial
            ],
            DEFAULT_RETRY_TIMEOUT,
            ClusterMode::RoundRobin,
        )
        .unwrap();

        // #1 start=0: both fail, fallback probes endpoints[start=0] (still down).
        assert!(cluster.connect().is_err());
        assert_eq!(cluster.endpoints[0].connector.calls(), 2);
        assert_eq!(cluster.endpoints[1].connector.calls(), 1);

        // #2 start=1: both in cooldown, so the fallback probes endpoints[start=1]
        // (NOT index 0), which now recovers.
        assert!(cluster.connect().is_ok());
        assert_eq!(cluster.endpoints[0].connector.calls(), 2); // untouched: start was 1
        assert_eq!(cluster.endpoints[1].connector.calls(), 2);
    }

    // A `Client` reconnect (roundtrip_ttlv) is just another `connect()` on the
    // same connector, so the open->reconnect sequence is modelled as two
    // consecutive `connect()` calls here.

    #[test]
    fn round_robin_reconnect_lands_on_a_different_endpoint() {
        let cluster = ClusterConnector::with_mode(
            [healthy(), healthy()],
            DEFAULT_RETRY_TIMEOUT,
            ClusterMode::RoundRobin,
        )
        .unwrap();

        // Session open -> endpoint 0.
        assert!(cluster.connect().is_ok());
        assert_eq!(cluster.endpoints[0].connector.calls(), 1);
        assert_eq!(cluster.endpoints[1].connector.calls(), 0);

        // Reconnect rotates the cursor -> endpoint 1, not the one we opened on.
        assert!(cluster.connect().is_ok());
        assert_eq!(cluster.endpoints[0].connector.calls(), 1);
        assert_eq!(cluster.endpoints[1].connector.calls(), 1);
    }

    #[test]
    fn failover_reconnect_returns_to_a_recovered_leading_endpoint() {
        let cluster = ClusterConnector::with_mode(
            [
                ScriptedConnector::new(vec![false, true]), // down at open, recovers
                healthy(),
            ],
            Duration::ZERO, // no cooldown: endpoint 0 is retried on reconnect
            ClusterMode::Failover,
        )
        .unwrap();

        // Session open: endpoint 0 down -> fail over to endpoint 1.
        assert!(cluster.connect().is_ok());
        assert_eq!(cluster.endpoints[0].connector.calls(), 1);
        assert_eq!(cluster.endpoints[1].connector.calls(), 1);

        // Reconnect: Failover scans from 0 again; endpoint 0 has recovered, so
        // the session moves back to it (different node than it was just on).
        assert!(cluster.connect().is_ok());
        assert_eq!(cluster.endpoints[0].connector.calls(), 2);
        assert_eq!(cluster.endpoints[1].connector.calls(), 1); // not re-dialed
    }
}
