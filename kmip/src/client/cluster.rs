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
//! - the first endpoint that connects wins and its cooldown is cleared;
//! - if at least one endpoint was dialed and they all failed, the aggregated
//!   error is returned;
//! - if *every* endpoint was skipped for cooldown, they are all probed once
//!   (ignoring cooldown) so a recovered node is found rather than pinning to a
//!   fixed leader.
//!
//! Because the [`Client`](super::Client) reconnects through its [`Connector`]
//! on a dropped connection (see `roundtrip_ttlv`), this applies both at
//! session/clone open and on a mid-session reconnect — so the round-robin
//! cursor also advances on reconnect and `try_clone`.

use std::{
    hash::{BuildHasher, Hasher, RandomState},
    io::{self, ErrorKind, Read, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use super::{Client, ClientBuilder, ClientConfig, Connector, Transport, is_disconnect};
use crate::{Error, Result};

/// Default per-endpoint cooldown window.
pub const DEFAULT_RETRY_COOLDOWN: Duration = Duration::from_secs(5);

/// How a [`ClusterConnector`] picks which endpoint to dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClusterMode {
    /// Always scan endpoints in configured order; the first reachable endpoint
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
    /// endpoint than the one the session opened on. This is unsuitable for
    /// operations that rely on server-side state pinned to one connection/node
    /// (e.g. multi-part crypto keyed by a correlation value), and it means a
    /// request re-sent after an unexpected EOF may be re-executed on another
    /// node — see [`ClientBuilder::connect_cluster`](super::ClientBuilder::connect_cluster).
    /// [`Failover`](Self::Failover) can also switch nodes on reconnect (it
    /// re-prefers a recovered leading endpoint), so this applies in both modes.
    ///
    /// Balancing is best-effort: while a node is cooling, the starts that would
    /// have landed on it spill onto the next healthy endpoint, so a degraded
    /// pool is not perfectly even until the node recovers.
    RoundRobin,
}

/// Configuration for a cluster connection, passed to
/// [`ClientBuilder::connect_cluster`](super::ClientBuilder::connect_cluster).
///
/// Carries the endpoint pool, the [`ClusterMode`], and the per-endpoint cooldown
/// — cluster-only settings that live here rather than on the shared
/// [`ClientBuilder`](super::ClientBuilder), which would silently ignore them for
/// a single-endpoint [`connect`](super::ClientBuilder::connect).
pub struct ClusterConfig {
    pub(crate) endpoints: Vec<(String, String)>, // (addr, domain)
    pub(crate) mode: ClusterMode,
    pub(crate) cooldown: Duration,
}

impl ClusterConfig {
    /// A cluster whose nodes all present the same TLS identity: every endpoint
    /// is validated against the single SNI / certificate `domain`. This is the
    /// common case — a cluster is one logical service behind one certificate.
    ///
    /// An empty `addrs` iterator is accepted here but yields an empty pool,
    /// which is rejected with [`Error::ClusterUnavailable`] at
    /// [`ClientBuilder::connect_cluster`](super::ClientBuilder::connect_cluster).
    pub fn with_shared_domain(
        addrs: impl IntoIterator<Item = impl Into<String>>,
        domain: impl Into<String>,
    ) -> Self {
        let domain = domain.into();
        Self::with_endpoints(addrs.into_iter().map(|addr| (addr.into(), domain.clone())))
    }

    /// A cluster whose nodes present per-host certificates: each endpoint pairs
    /// its `addr` with the SNI / certificate `domain` to validate it against.
    ///
    /// An empty `endpoints` iterator is accepted here but yields an empty pool,
    /// which is rejected with [`Error::ClusterUnavailable`] at
    /// [`ClientBuilder::connect_cluster`](super::ClientBuilder::connect_cluster).
    pub fn with_endpoints(
        endpoints: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        Self {
            endpoints: endpoints
                .into_iter()
                .map(|(addr, domain)| (addr.into(), domain.into()))
                .collect(),
            mode: ClusterMode::default(),
            cooldown: DEFAULT_RETRY_COOLDOWN,
        }
    }

    /// Sets the endpoint-selection [`ClusterMode`] (default
    /// [`ClusterMode::Failover`]).
    #[must_use]
    pub fn mode(mut self, mode: ClusterMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the per-endpoint cooldown window: after a failed dial, an endpoint
    /// is skipped for this duration before being dialed again (default
    /// [`DEFAULT_RETRY_COOLDOWN`]).
    ///
    /// Note: a single-endpoint pool has nothing to fail over to, so its sole
    /// endpoint is always re-probed to allow recovery — the cooldown does not
    /// throttle reconnects in that degenerate case.
    #[must_use]
    pub fn cooldown(mut self, cooldown: Duration) -> Self {
        self.cooldown = cooldown;
        self
    }
}

impl ClientBuilder {
    /// Builds a `ClientConfig` backed by a [`ClusterConnector`] over every
    /// endpoint of `config`. Shared by [`connect_cluster`](Self::connect_cluster)
    /// and, with the `pool` feature, `pool_cluster`. Opens no connection.
    pub(crate) fn build_cluster(&self, config: ClusterConfig) -> Result<ClientConfig> {
        let ClusterConfig {
            endpoints,
            mode,
            cooldown,
        } = config;
        // One prepared TLS state — CA bundle parsed, identity loaded — shared
        // by every endpoint's connector rather than rebuilt per endpoint. The
        // endpoint's address doubles as its label.
        let factory = self.backend.prepare(&self.connector)?;
        let labelled = endpoints.into_iter().map(|(addr, domain)| {
            let connector = factory.connector(addr.clone(), &domain);
            (addr, connector)
        });
        let cluster = ClusterConnector::new(labelled, cooldown, mode)?;
        Ok(self.build_with_connector(Arc::new(cluster)))
    }

    /// Connects to a pool of KMIP endpoints with failover and optional load
    /// balancing, using the configured transport backend for every endpoint. See
    /// [`ClusterConfig`] for the endpoints, [`ClusterMode`], and cooldown.
    ///
    /// Each endpoint address is a `"host:port"` string, re-resolved on every
    /// connection like [`Self::connect`].
    ///
    /// Note on retries: a mid-session reconnect (`roundtrip_ttlv` after an
    /// unexpected EOF, or [`Client::try_clone`]) re-runs endpoint selection and
    /// may land on a *different* node. A request re-sent after the peer closed
    /// mid-exchange can therefore be re-executed on another node — for a
    /// non-idempotent operation (e.g. `Create`/`Destroy`) that means a possible
    /// duplicate side effect while the caller still sees success. Prefer
    /// idempotent operations, or a single-endpoint [`Self::connect`], where that
    /// matters.
    pub fn connect_cluster(&self, config: ClusterConfig) -> Result<Client> {
        self.build_cluster(config)?.connect()
    }
}

/// Instant of one endpoint's last observed failure, `None` if healthy. Shared
/// with the connections handed out for that endpoint so a node that fails after
/// the dial still cools down.
type Health = Arc<Mutex<Option<Instant>>>;

fn mark_failed(health: &Health) {
    *health.lock().expect("cluster cooldown mutex poisoned") = Some(Instant::now());
}

fn clear_failed(health: &Health) {
    *health.lock().expect("cluster cooldown mutex poisoned") = None;
}

struct Endpoint {
    /// Human-readable identifier (the `host:port` address) for logs and errors.
    label: String,
    connector: Arc<dyn Connector>,
    health: Health,
}

/// A cluster connection that reports its failures to the endpoint it came from.
///
/// A successful dial only proves the node accepts TCP and TLS. Without this, a
/// node whose listener is up but whose service is wedged would clear its
/// cooldown on every dial and [`ClusterMode::Failover`] would pin to it while
/// healthy nodes sit idle.
///
/// Only failures before the connection has served a byte count against the
/// node. After that a drop is the connection's own (an idle reaper, a
/// mid-session reset) and says nothing about node health.
struct MonitoredTransport {
    inner: Box<dyn Transport>,
    health: Health,
    served: bool,
}

impl MonitoredTransport {
    /// Whether `e` means the connection failed, rather than an application
    /// level or transient condition.
    ///
    /// The shared [`is_disconnect`] set, plus the kinds that mean the node
    /// accepted and then went silent — which a dial cannot see and the cooldown
    /// exists for, but which the client's retry loop deliberately does not
    /// treat as recoverable.
    fn is_connection_failure(e: &io::Error) -> bool {
        is_disconnect(e)
            || matches!(
                e.kind(),
                ErrorKind::NotConnected | ErrorKind::TimedOut | ErrorKind::WouldBlock
            )
    }

    /// Blames the node for a read until the connection has served something.
    fn observe(&mut self, result: &io::Result<usize>) {
        match result {
            // A zero read is the peer hanging up. On a connection that never
            // answered, that is the node.
            Ok(0) if !self.served => mark_failed(&self.health),
            Ok(_) => self.served = true,
            Err(e) if !self.served && Self::is_connection_failure(e) => mark_failed(&self.health),
            Err(_) => {}
        }
    }
}

impl Read for MonitoredTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let result = self.inner.read(buf);
        self.observe(&result);
        result
    }
}

impl Write for MonitoredTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let result = self.inner.write(buf);
        // A write never proves the node answered, so it can only report failure.
        if let Err(e) = &result
            && !self.served
            && Self::is_connection_failure(e)
        {
            mark_failed(&self.health);
        }
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A [`Connector`] that dials a pool of endpoints with failover and optional
/// load balancing. See the [`ClusterMode`] variants for the exact selection
/// semantics.
pub struct ClusterConnector {
    endpoints: Vec<Endpoint>,
    cooldown: Duration,
    mode: ClusterMode,
    /// Round-robin cursor; only consulted in [`ClusterMode::RoundRobin`]. Seeded
    /// to a random start so single-connection processes do not all open on
    /// endpoint 0.
    cursor: AtomicUsize,
}

impl ClusterConnector {
    /// Builds a connector over `connectors`. Each item is a `(label, connector)`
    /// pair, where `label` is the endpoint's `host:port` address (used in logs
    /// and errors). `mode` selects the endpoint-selection strategy; pass
    /// [`ClusterMode::default`] for plain failover. Returns an error if the pool
    /// is empty.
    pub fn new(
        connectors: impl IntoIterator<Item = (String, Arc<dyn Connector>)>,
        cooldown: Duration,
        mode: ClusterMode,
    ) -> Result<Self> {
        let endpoints: Vec<_> = connectors
            .into_iter()
            .map(|(label, connector)| Endpoint {
                label,
                connector,
                health: Arc::new(Mutex::new(None)),
            })
            .collect();
        if endpoints.is_empty() {
            return Err(Error::ClusterUnavailable(
                "at least one endpoint is required".to_string(),
            ));
        }
        // Random start so that with one long-lived Client per process every
        // process does not open its first connection on endpoint 0.
        let seed = RandomState::new().build_hasher().finish() as usize;
        Ok(Self {
            endpoints,
            cooldown,
            mode,
            cursor: AtomicUsize::new(seed),
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
            .health
            .lock()
            .expect("cluster cooldown mutex poisoned")
            .is_some_and(|at| at.elapsed() < self.cooldown)
    }

    /// Dials one endpoint, stamping its cooldown state: cleared on success, set
    /// to the current instant on failure.
    ///
    /// Clearing on success is provisional: a dial cannot see whether the node
    /// serves KMIP. [`MonitoredTransport`] re-stamps the endpoint if the
    /// exchange it carries fails.
    fn attempt(&self, endpoint: &Endpoint) -> Result<Box<dyn Transport>> {
        let result = endpoint.connector.connect();
        match &result {
            Ok(_) => clear_failed(&endpoint.health),
            Err(_) => mark_failed(&endpoint.health),
        }
        result.map(|inner| {
            Box::new(MonitoredTransport {
                inner,
                health: endpoint.health.clone(),
                served: false,
            }) as Box<dyn Transport>
        })
    }

    #[cfg(test)]
    fn reset_cursor(&self) {
        self.cursor.store(0, Ordering::Relaxed);
    }
}

impl Connector for ClusterConnector {
    fn connect(&self) -> Result<Box<dyn Transport>> {
        let n = self.endpoints.len();
        let start = self.start_index();
        let (live, cooling): (Vec<_>, Vec<_>) = (0..n)
            .map(|offset| &self.endpoints[(start + offset) % n])
            .partition(|endpoint| {
                let cooling = self.in_cooldown(endpoint);
                if cooling {
                    tracing::debug!(endpoint = %endpoint.label, "skipping cluster endpoint in cooldown");
                }
                !cooling
            });

        // With nothing live, every endpoint is cooling: probe them all once
        // (ignoring cooldown) so a recovered node — not just the start endpoint
        // — can bring the cluster back.
        let all_cooling = live.is_empty();
        if all_cooling {
            tracing::debug!("all cluster endpoints cooling; probing each once");
        }

        let mut failures: Vec<String> = Vec::new();
        for endpoint in if all_cooling { &cooling } else { &live } {
            match self.attempt(endpoint) {
                Ok(transport) => {
                    tracing::debug!(endpoint = %endpoint.label, "cluster endpoint connected");
                    return Ok(transport);
                }
                Err(error) => {
                    tracing::warn!(endpoint = %endpoint.label, %error, "cluster endpoint dial failed");
                    failures.push(format!("{}: {error}", endpoint.label));
                }
            }
        }

        // Name the endpoints we skipped too: an error listing only what we
        // happened to dial reads as a smaller outage than it is. When all were
        // cooling they were all just dialed, so there is nothing to add.
        if !all_cooling {
            failures.extend(
                cooling
                    .iter()
                    .map(|endpoint| format!("{}: skipped (in cooldown)", endpoint.label)),
            );
        }

        Err(Error::ClusterUnavailable(failures.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use std::{io, sync::atomic::AtomicUsize};

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

    /// Builds a cluster from the given endpoint handles (labelled `ep0`, `ep1`,
    /// …), keeping the concrete `Arc<ScriptedConnector>` handles so tests can
    /// assert on `.calls()`. The round-robin cursor is reset to 0 so start
    /// indices are deterministic.
    fn cluster(
        endpoints: &[Arc<ScriptedConnector>],
        cooldown: Duration,
        mode: ClusterMode,
    ) -> ClusterConnector {
        let c = ClusterConnector::new(
            endpoints
                .iter()
                .enumerate()
                .map(|(i, e)| (format!("ep{i}"), e.clone() as Arc<dyn Connector>))
                .collect::<Vec<_>>(),
            cooldown,
            mode,
        )
        .unwrap();
        c.reset_cursor();
        c
    }

    #[test]
    fn config_defaults_and_builders() {
        let cfg = ClusterConfig::with_shared_domain(["a:5696", "b:5696"], "kms.example.com");
        assert_eq!(cfg.endpoints.len(), 2);
        assert_eq!(
            cfg.endpoints[0],
            ("a:5696".to_string(), "kms.example.com".to_string())
        );
        assert_eq!(cfg.mode, ClusterMode::Failover);
        assert_eq!(cfg.cooldown, DEFAULT_RETRY_COOLDOWN);

        let cfg = ClusterConfig::with_endpoints([("a:5696", "n1"), ("b:5696", "n2")])
            .mode(ClusterMode::RoundRobin)
            .cooldown(Duration::from_secs(2));
        assert_eq!(cfg.endpoints[1], ("b:5696".to_string(), "n2".to_string()));
        assert_eq!(cfg.mode, ClusterMode::RoundRobin);
        assert_eq!(cfg.cooldown, Duration::from_secs(2));
    }

    #[test]
    fn empty_endpoints_is_rejected() {
        let r = ClusterConnector::new(
            Vec::<(String, Arc<dyn Connector>)>::new(),
            DEFAULT_RETRY_COOLDOWN,
            ClusterMode::default(),
        );
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
        // exactly once and no endpoint is re-probed.
        let eps = [
            ScriptedConnector::new(vec![false, false]),
            ScriptedConnector::new(vec![false, false]),
        ];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::Failover);
        assert!(c.connect().is_err());
        assert_eq!(eps[0].calls(), 1);
        assert_eq!(eps[1].calls(), 1);
    }

    #[test]
    fn cooled_start_is_not_reprobed_when_a_live_endpoint_fails() {
        let eps = [
            ScriptedConnector::new(vec![false]),       // ep0: down -> cools
            ScriptedConnector::new(vec![true, false]), // ep1: ok first, then fails
            ScriptedConnector::new(vec![false]),       // ep2: down
        ];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::Failover);

        // #1 setup: ep0 fails (enters cooldown), ep1 succeeds and ends the pass.
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 1);
        assert_eq!(eps[1].calls(), 1);
        assert_eq!(eps[2].calls(), 0);

        // #2: ep0 is skipped for cooldown; ep1 and ep2 are live and fail this
        // pass. A live endpoint was dialed, so the cooled start (ep0) must NOT
        // be re-probed.
        assert!(c.connect().is_err());
        assert_eq!(eps[0].calls(), 1); // cooled start left alone
        assert_eq!(eps[1].calls(), 2);
        assert_eq!(eps[2].calls(), 1);
    }

    #[test]
    fn all_cooling_probes_every_endpoint_and_finds_a_recovered_non_leader() {
        // ep0 (start) stays down; ep1 recovers. When both are cooling, the
        // fallback must probe past the down leader and find ep1.
        let eps = [
            ScriptedConnector::new(vec![false, false]), // stays down
            ScriptedConnector::new(vec![false, true]),  // recovers on 2nd dial
        ];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::Failover);

        // #1: both fail this pass and enter cooldown.
        assert!(c.connect().is_err());
        assert_eq!(eps[0].calls(), 1);
        assert_eq!(eps[1].calls(), 1);

        // #2: both cooling -> probe-all finds the recovered ep1 despite ep0
        // (the leader) still being down.
        assert!(c.connect().is_ok());
        assert_eq!(eps[0].calls(), 2); // probed, still down
        assert_eq!(eps[1].calls(), 2); // probed, recovered
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

    /// Connects fine, then fails every exchange: a node whose listener is up
    /// but whose KMIP service is wedged.
    struct WedgedTransport;

    impl io::Read for WedgedTransport {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(ErrorKind::ConnectionReset))
        }
    }

    impl io::Write for WedgedTransport {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Always accepts, always hands back a wedged transport.
    struct WedgedConnector(AtomicUsize);

    impl WedgedConnector {
        fn new() -> Arc<Self> {
            Arc::new(Self(AtomicUsize::new(0)))
        }
        fn calls(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl Connector for WedgedConnector {
        fn connect(&self) -> Result<Box<dyn Transport>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(WedgedTransport))
        }
    }

    #[test]
    fn endpoint_that_connects_but_never_serves_enters_cooldown() {
        // The failure a dial cannot see: ep0 accepts every connection, so
        // `attempt` alone would clear its cooldown forever and Failover would
        // pin to it.
        let wedged = WedgedConnector::new();
        let healthy = healthy();
        let c = ClusterConnector::new(
            vec![
                ("ep0".to_string(), wedged.clone() as Arc<dyn Connector>),
                ("ep1".to_string(), healthy.clone() as Arc<dyn Connector>),
            ],
            DEFAULT_RETRY_COOLDOWN,
            ClusterMode::Failover,
        )
        .unwrap();
        c.reset_cursor();

        // Failover picks ep0, which connects. Nothing looks wrong yet.
        let mut conn = c.connect().unwrap();
        assert_eq!(wedged.calls(), 1);
        assert_eq!(healthy.calls(), 0);

        // Request goes out, response never comes: the node is at fault.
        let mut buf = [0u8; 8];
        assert!(conn.write_all(b"request").is_ok());
        assert!(conn.read(&mut buf).is_err());

        // ep0 is now cooling, so the reconnect reaches the healthy node.
        c.connect().unwrap();
        assert_eq!(wedged.calls(), 1, "wedged endpoint must not be re-dialed");
        assert_eq!(healthy.calls(), 1, "failover must reach the healthy node");
    }

    #[test]
    fn connection_that_already_served_does_not_cool_its_endpoint() {
        // A reaped idle connection dies like a wedged node's. Having served a
        // response is what tells them apart.
        let health: Health = Arc::new(Mutex::new(None));
        let mut t = MonitoredTransport {
            inner: Box::new(io::Cursor::new(b"response".to_vec())),
            health: health.clone(),
            served: false,
        };

        let mut buf = [0u8; 8];
        assert!(t.read(&mut buf).unwrap() > 0);
        assert!(t.served);

        // Now the peer hangs up. The endpoint stays healthy.
        t.inner = Box::new(WedgedTransport);
        assert!(t.read(&mut buf).is_err());
        assert!(
            health.lock().unwrap().is_none(),
            "a connection that served a response must not cool its endpoint"
        );
    }

    #[test]
    fn error_names_endpoints_skipped_for_cooldown() {
        // ep0 cools, ep1 is live and fails. Reporting only ep1 would read as a
        // one node outage.
        let eps = [
            ScriptedConnector::new(vec![false]),
            ScriptedConnector::new(vec![true, false]),
        ];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::Failover);

        // #1: ep0 fails (cools), ep1 serves.
        assert!(c.connect().is_ok());

        // #2: ep0 is skipped for cooldown, ep1 is dialed and fails.
        let msg = match c.connect() {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected the cluster to be unreachable"),
        };
        assert!(msg.contains("ep0"), "cooled endpoint missing from {msg:?}");
        assert!(msg.contains("cooldown"), "no cooldown reason in {msg:?}");
        assert!(msg.contains("ep1"), "dialed endpoint missing from {msg:?}");
    }

    #[test]
    fn probe_all_error_reports_dial_failures_not_cooldown_notes() {
        // All cooling means all re-dialed, so the error carries real dial
        // failures rather than stale cooldown notes.
        let eps = [
            ScriptedConnector::new(vec![false, false]),
            ScriptedConnector::new(vec![false, false]),
        ];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::Failover);

        assert!(c.connect().is_err()); // both fail, both cool
        let msg = match c.connect() {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected the cluster to be unreachable"),
        };
        assert!(msg.contains("ep0") && msg.contains("ep1"), "{msg:?}");
        assert!(
            !msg.contains("cooldown"),
            "probe-all must report real dial errors, got {msg:?}"
        );
    }

    #[test]
    fn error_aggregates_all_endpoint_failures() {
        let eps = [
            ScriptedConnector::new(vec![false]),
            ScriptedConnector::new(vec![false]),
        ];
        let c = cluster(&eps, DEFAULT_RETRY_COOLDOWN, ClusterMode::Failover);
        let msg = match c.connect() {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected all endpoints to fail"),
        };
        assert!(msg.contains("ep0"), "missing ep0 in {msg:?}");
        assert!(msg.contains("ep1"), "missing ep1 in {msg:?}");
    }
}
