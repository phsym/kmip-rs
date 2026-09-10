//! Synchronous connection pooling for the KMIP [`Client`], built on
//! [`r2d2`](https://docs.rs/r2d2).
//!
//! A [`Client`] owns a single connection, so a pool holds a bounded set of
//! independent clients and hands them out on demand. Create one from a
//! [`ClientBuilder`] via [`pool`](ClientBuilder::pool), without having to name
//! `r2d2` yourself.
//!
//! Because the client's request path already recovers a connection that dropped
//! between uses (it re-dials and retries once the next request hits a
//! closed/reset connection), the pool does not attempt its own liveness
//! checking: checkout validation is disabled by default. Recovery is best
//! effort: if the re-dial itself fails (say the server is still down), that
//! error is returned to the caller rather than retried.
//!
//! # Example
//!
//! ```no_run
//! use kmip::{client::Client, CryptographicUsageMask};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // `.pool(addr, domain)` finishes the transport setup (opening no connection
//! // yet) and returns a pool builder; `.build()` then opens the initial
//! // connections.
//! let pool = Client::builder()
//!     .add_root_certificate_file("ca.pem")?
//!     .identity_file("client.pem", "client.key")?
//!     .pool("kmip.example.com:5696", "kmip.example.com")?  // -> ClientPoolBuilder
//!     .max_size(8)
//!     .build()?; // -> ClientPool
//!
//! // `ClientPool` is `Clone + Send + Sync`; share it across threads.
//! let mut client = pool.get()?; // owned guard, derefs to `&mut Client`
//! let response = client
//!     .create()
//!     .aes(256, CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt)
//!     .exec()?;
//! // The connection returns to the pool when `client` is dropped.
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

pub use r2d2;

use super::{Client, ClientBuilder, ClientConfig, ClusterConfig};
use crate::{RequestMessage, payloads::DiscoverVersionsRequestPayload, types::ProtocolVersion};

impl Client {
    /// Actively verifies the connection is usable by issuing a lightweight
    /// `DiscoverVersions` round trip, bypassing the cached negotiated version so
    /// a socket that died while idle is actually detected. The reconnect and
    /// retry loop transparently re-dials a dropped connection, so a successful
    /// return means the client is live. Used by the pool's optional checkout
    /// validation ([`KmipConnectionManager::is_valid`]).
    fn probe(&mut self) -> crate::Result<()> {
        self.roundtrip(RequestMessage::new(
            ProtocolVersion::V1_1,
            DiscoverVersionsRequestPayload {
                protocol_version: Vec::new(),
            },
        ))
        .map(|_| ())
    }
}

/// An [`r2d2::ManageConnection`] that opens KMIP [`Client`] connections.
///
/// This is an implementation detail of [`ClientPool`]; construct pools through
/// [`ClientBuilder::pool`] rather than naming this type directly.
#[doc(hidden)]
#[derive(Clone)]
pub struct KmipConnectionManager {
    config: ClientConfig,
}

impl KmipConnectionManager {
    pub(crate) fn new(config: ClientConfig) -> Self {
        Self { config }
    }
}

impl r2d2::ManageConnection for KmipConnectionManager {
    type Connection = Client;
    type Error = crate::Error;

    fn connect(&self) -> Result<Client, Self::Error> {
        self.config.connect()
    }

    fn is_valid(&self, conn: &mut Client) -> Result<(), Self::Error> {
        // Not called under the pool's default `test_on_check_out(false)`; it only
        // runs if a caller re-enables checkout validation via `test_on_check_out`.
        // When they do, `probe` issues a real `DiscoverVersions` round trip
        // (bypassing the cached/pinned version) so a socket that died while idle
        // is actually detected. The client's reconnect and retry loop re-dials
        // it, so a successful return means the checked-out client is live.
        conn.probe()
    }

    fn has_broken(&self, conn: &mut Client) -> bool {
        // A client whose last exchange failed after the request went out may
        // hold an unread response. Recycling it would let the next caller
        // decode the *previous* caller's response as its own.
        conn.is_broken()
    }
}

/// A pool of KMIP clients. `Clone + Send + Sync`; share it across threads.
///
/// Build one with [`ClientBuilder::pool`]. Check out a client with
/// [`get`](r2d2::Pool::get); it returns a [`PooledClient`] guard that derefs to
/// [`Client`] and returns its connection to the pool when dropped.
pub type ClientPool = r2d2::Pool<KmipConnectionManager>;

/// An owned, pooled [`Client`] handle. Dereferences to [`Client`] and returns
/// its connection to the pool when dropped.
pub type PooledClient = r2d2::PooledConnection<KmipConnectionManager>;

impl ClientBuilder {
    /// Builds the transport and starts a connection [`ClientPool`] builder
    /// targeting the KMIP server at `addr`/`domain`.
    ///
    /// Convenience for the crate-internal `build(addr, domain)?.pool()`: it
    /// finishes the TLS/socket setup (so a bad certificate or backend error
    /// surfaces here) and hands back a [`ClientPoolBuilder`] carrying the pool
    /// sizing and timeout knobs. Any protocol settings staged via
    /// `with_middleware` / `with_version` / `with_supported_versions` apply to
    /// every pooled connection.
    pub fn pool(&self, addr: impl Into<String>, domain: &str) -> crate::Result<ClientPoolBuilder> {
        let config = self.build(addr, domain)?;
        Ok(ClientPoolBuilder::new(KmipConnectionManager::new(config)))
    }

    /// Builds the transport and starts a [`ClientPool`] builder over a
    /// *cluster* of endpoints, combining pooling with the failover and load
    /// balancing of [`connect_cluster`](ClientBuilder::connect_cluster).
    ///
    /// Every connection the pool opens runs endpoint selection independently,
    /// so the pool spreads across the cluster under
    /// [`RoundRobin`](super::ClusterMode::RoundRobin) and drains away from a
    /// failing node under [`Failover`](super::ClusterMode::Failover). See
    /// [`ClusterConfig`] for the endpoints, mode, and cooldown.
    ///
    /// The reconnect caveat of
    /// [`connect_cluster`](ClientBuilder::connect_cluster) applies: a pooled
    /// client that reconnects mid-session may resume on a different node, so a
    /// re-sent non-idempotent request can be executed twice.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use kmip::client::{Client, ClusterConfig, ClusterMode};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let pool = Client::builder()
    ///     .add_root_certificate_file("ca.pem")?
    ///     .pool_cluster(
    ///         ClusterConfig::with_shared_domain(
    ///             ["kmip-1.example.com:5696", "kmip-2.example.com:5696"],
    ///             "kmip.example.com",
    ///         )
    ///         .mode(ClusterMode::RoundRobin),
    ///     )?
    ///     .max_size(8)
    ///     .build()?;
    /// # let _ = pool;
    /// # Ok(())
    /// # }
    /// ```
    pub fn pool_cluster(&self, config: ClusterConfig) -> crate::Result<ClientPoolBuilder> {
        let config = self.build_cluster(config)?;
        Ok(ClientPoolBuilder::new(KmipConnectionManager::new(config)))
    }
}

/// Builder for a [`ClientPool`], returned by [`ClientBuilder::pool`].
///
/// Wraps an [`r2d2::Builder`] so the common knobs are available without naming
/// `r2d2`; reach for [`configure`](Self::configure) for anything not surfaced
/// here (custom error/event handlers, thread pool, …).
pub struct ClientPoolBuilder {
    manager: KmipConnectionManager,
    builder: r2d2::Builder<KmipConnectionManager>,
    // `max_size` and `min_idle` are held here (rather than forwarded straight to
    // `r2d2::Builder`) so `build` can validate them and return an error, instead
    // of tripping r2d2's `assert!`s (`max_size == 0`, `min_idle > max_size`).
    max_size: u32,
    min_idle: Option<u32>,
    // First deferred validation error from a setter (e.g. a zero timeout),
    // surfaced by `build` so the fallible API never panics on plausible input.
    error: Option<String>,
}

impl ClientPoolBuilder {
    fn new(manager: KmipConnectionManager) -> Self {
        // Default to no checkout validation: the client self-heals a dropped
        // connection on its next use, so probing on every checkout is wasted
        // work. Callers who want it can re-enable it via `test_on_check_out`.
        //
        // Default `min_idle` to 1 rather than r2d2's `max_size`: `build()`
        // eagerly dials `min_idle` connections and fails if any cannot be
        // established, so prewarming the whole pool would make startup
        // all-or-nothing against a briefly-unavailable server. One successful
        // dial is enough; the pool grows to `max_size` on demand.
        Self {
            manager,
            builder: r2d2::Pool::builder().test_on_check_out(false),
            max_size: 8,
            min_idle: Some(1),
            error: None,
        }
    }

    /// Records the first deferred configuration error; later ones are ignored so
    /// the earliest problem is the one `build` reports.
    fn record_error(&mut self, msg: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some(msg.into());
        }
    }

    /// Sets the maximum number of connections the pool will hold. Defaults to 8.
    /// Must be greater than 0, otherwise [`build`](Self::build) returns an error.
    #[must_use]
    pub fn max_size(mut self, max_size: u32) -> Self {
        self.max_size = max_size;
        self
    }

    /// Sets the minimum number of idle connections the pool tries to maintain.
    /// Defaults to `Some(1)`; `None` keeps up to `max_size` idle. Must not exceed
    /// `max_size`, otherwise [`build`](Self::build) returns an error.
    #[must_use]
    pub fn min_idle(mut self, min_idle: Option<u32>) -> Self {
        self.min_idle = min_idle;
        self
    }

    /// Sets how long [`ClientPool::get`] waits for a connection before failing.
    /// A zero duration makes [`build`](Self::build) return an error.
    #[must_use]
    pub fn connection_timeout(mut self, timeout: Duration) -> Self {
        if timeout.is_zero() {
            self.record_error("connection_timeout must be greater than zero");
        } else {
            self.builder = self.builder.connection_timeout(timeout);
        }
        self
    }

    /// Sets how long an idle connection may live before being reaped. `None`
    /// disables idle reaping. A zero duration makes [`build`](Self::build) return
    /// an error.
    #[must_use]
    pub fn idle_timeout(mut self, idle_timeout: Option<Duration>) -> Self {
        if idle_timeout == Some(Duration::ZERO) {
            self.record_error("idle_timeout must be greater than zero");
        } else {
            self.builder = self.builder.idle_timeout(idle_timeout);
        }
        self
    }

    /// Sets the maximum lifetime of any connection. `None` disables the limit. A
    /// zero duration makes [`build`](Self::build) return an error.
    #[must_use]
    pub fn max_lifetime(mut self, max_lifetime: Option<Duration>) -> Self {
        if max_lifetime == Some(Duration::ZERO) {
            self.record_error("max_lifetime must be greater than zero");
        } else {
            self.builder = self.builder.max_lifetime(max_lifetime);
        }
        self
    }

    /// Enables or disables validating each connection before it is handed out.
    ///
    /// Disabled by default: the client transparently reconnects and retries on a
    /// dropped connection, so validating on every checkout is usually wasted
    /// work. When enabled, each [`ClientPool::get`] issues a lightweight
    /// `DiscoverVersions` round trip so a connection that died while idle is
    /// detected (or transparently re-dialed) before the caller receives it, at
    /// the cost of one round trip per checkout.
    #[must_use]
    pub fn test_on_check_out(mut self, test_on_check_out: bool) -> Self {
        self.builder = self.builder.test_on_check_out(test_on_check_out);
        self
    }

    /// Escape hatch for [`r2d2::Builder`] options not surfaced above (custom
    /// error/event handlers, connection customizer, thread pool, …).
    ///
    /// # Panics
    ///
    /// The raw [`r2d2::Builder`] validates eagerly with `assert!`, unlike the
    /// wrapper's setters which defer to [`build`](Self::build). An out of range
    /// `max_size`, `connection_timeout`, `idle_timeout` or `max_lifetime` set
    /// inside this closure panics *here*, before `build` runs, so `build`'s
    /// no-panic promise does not cover values routed through it. Prefer the
    /// dedicated setters for those four, especially for values derived at
    /// runtime where `0` is plausible:
    ///
    /// ```no_run
    /// # use kmip::client::ClientPoolBuilder;
    /// # fn f(builder: ClientPoolBuilder, secs: u64) -> kmip::Result<()> {
    /// # let pool =
    /// // `Duration::from_secs(0)` returns an error here …
    /// builder.connection_timeout(std::time::Duration::from_secs(secs)).build()?;
    /// // … but would panic inside `.configure(|b| b.connection_timeout(..))`.
    /// # let _ = pool; Ok(()) }
    /// ```
    ///
    /// `max_size` and `min_idle` are re-applied at [`build`](Self::build) time,
    /// so a value set for them here is overwritten (a valid one is silently
    /// discarded; an invalid one still panics first).
    #[must_use]
    pub fn configure(
        mut self,
        f: impl FnOnce(r2d2::Builder<KmipConnectionManager>) -> r2d2::Builder<KmipConnectionManager>,
    ) -> Self {
        self.builder = f(self.builder);
        self
    }

    /// Builds the pool, eagerly opening the initial connections (up to
    /// `min_idle`, which defaults to 1). The initial connections are dialed but
    /// not validated on checkout.
    ///
    /// Returns an error if the sizing/timeout configuration is invalid
    /// (`max_size == 0`, `min_idle > max_size`, or a zero timeout) or if any of
    /// the initial connections cannot be established. It never panics on
    /// out-of-range input the way the raw `r2d2::Builder` setters do.
    pub fn build(self) -> crate::Result<ClientPool> {
        if let Some(err) = self.error {
            return Err(crate::Error::PoolConfig(err));
        }
        if self.max_size == 0 {
            return Err(crate::Error::PoolConfig(
                "max_size must be greater than zero".into(),
            ));
        }
        if let Some(min_idle) = self.min_idle
            && min_idle > self.max_size
        {
            return Err(crate::Error::PoolConfig(format!(
                "min_idle ({min_idle}) must not exceed max_size ({})",
                self.max_size
            )));
        }
        let builder = self.builder.max_size(self.max_size).min_idle(self.min_idle);
        Ok(builder.build(self.manager)?)
    }
}

#[cfg(test)]
mod tests {
    use std::{net::TcpListener, sync::Arc, time::Duration};

    use super::*;
    use crate::client::LocalConnector;

    /// A pool builder over a plain-TCP `LocalConnector`, mirroring what
    /// `ClientBuilder::pool` produces but without needing a TLS backend.
    fn pool_builder(addr: String) -> ClientPoolBuilder {
        let config = ClientConfig::new(Arc::new(LocalConnector(addr)));
        ClientPoolBuilder::new(KmipConnectionManager::new(config))
    }

    /// Gives up on a silent server quickly, so the stalled-response case does
    /// not need a 30s wait.
    struct ImpatientConnector(String);

    impl crate::client::Connector for ImpatientConnector {
        fn connect(&self) -> crate::Result<Box<dyn crate::client::Transport>> {
            let stream = std::net::TcpStream::connect(self.0.as_str())?;
            stream.set_read_timeout(Some(Duration::from_millis(200)))?;
            Ok(Box::new(stream))
        }
    }

    /// Accepts and then stalls: the request lands, the response never comes,
    /// and the caller gives up while still owed one.
    fn stalling_server() -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            // Hold the connection open without ever replying.
            if let Ok((stream, _)) = listener.accept() {
                std::thread::sleep(Duration::from_secs(2));
                drop(stream);
            }
        });
        (addr, handle)
    }

    #[test]
    fn a_client_whose_response_never_arrived_is_not_recycled() {
        // A connection with an unread response must not reach the next caller:
        // the queued response belongs to the previous request, and nothing in
        // the protocol path would notice the mismatch.
        let (addr, server) = stalling_server();

        let config = ClientConfig::new(Arc::new(ImpatientConnector(addr)));
        let manager = KmipConnectionManager::new(config);

        use r2d2::ManageConnection as _;

        let mut client = manager.connect().unwrap();
        assert!(
            !manager.has_broken(&mut client),
            "a fresh connection is reusable"
        );

        // The request goes out; the response never comes.
        assert!(client.probe().is_err(), "expected the exchange to time out");

        assert!(
            manager.has_broken(&mut client),
            "a connection left holding an unread response must not be recycled"
        );

        drop(client);
        let _ = server.join();
    }

    /// Counts the connections one cluster endpoint was asked to open.
    struct CountingConnector {
        inner: LocalConnector,
        dials: std::sync::atomic::AtomicUsize,
    }

    impl CountingConnector {
        fn new(addr: &str) -> Arc<Self> {
            Arc::new(Self {
                inner: LocalConnector(addr.to_string()),
                dials: std::sync::atomic::AtomicUsize::new(0),
            })
        }
        fn dials(&self) -> usize {
            self.dials.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl crate::client::Connector for CountingConnector {
        fn connect(&self) -> crate::Result<Box<dyn crate::client::Transport>> {
            self.dials.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.connect()
        }
    }

    #[test]
    fn pool_over_a_cluster_spreads_connections_across_endpoints() {
        use crate::client::{ClusterConnector, ClusterMode, Connector};

        // The combination `pool_cluster` exists to make reachable. Both
        // endpoints dial the same listener, so this asserts on the selection,
        // not the socket. Plain TCP, so no TLS server is needed.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (ep_a, ep_b) = (CountingConnector::new(&addr), CountingConnector::new(&addr));

        let cluster = ClusterConnector::with_mode(
            vec![
                ("ep_a".to_string(), ep_a.clone() as Arc<dyn Connector>),
                ("ep_b".to_string(), ep_b.clone() as Arc<dyn Connector>),
            ],
            Duration::from_secs(5),
            ClusterMode::RoundRobin,
        )
        .unwrap();

        let config = ClientConfig::new(Arc::new(cluster));
        let pool = ClientPoolBuilder::new(KmipConnectionManager::new(config))
            .max_size(2)
            .min_idle(Some(2))
            .build()
            .unwrap();

        assert_eq!(pool.state().connections, 2);
        // The start index advances per connection, so two land one on each
        // endpoint whatever the random seed.
        assert_eq!(ep_a.dials(), 1, "endpoint A got no connection");
        assert_eq!(ep_b.dials(), 1, "endpoint B got no connection");
    }

    #[cfg(feature = "default-tls-rustls")]
    #[test]
    fn pool_cluster_builds_a_pool_builder_without_connecting() {
        use crate::client::ClusterConfig;

        // Nothing is dialed until `build()`, so this succeeds with nothing
        // listening.
        assert!(
            Client::builder()
                .pool_cluster(ClusterConfig::with_shared_domain(
                    ["127.0.0.1:1", "127.0.0.2:1"],
                    "localhost",
                ))
                .is_ok()
        );
    }

    #[cfg(feature = "default-tls-rustls")]
    #[test]
    fn pool_cluster_rejects_an_empty_endpoint_list() {
        assert!(matches!(
            Client::builder().pool_cluster(ClusterConfig::with_shared_domain(
                Vec::<String>::new(),
                "localhost",
            )),
            Err(crate::Error::ClusterUnavailable(_))
        ));
    }

    #[test]
    fn build_prewarms_min_idle_by_default() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let pool = pool_builder(addr).max_size(3).build().unwrap();

        // min_idle defaults to 1, so build eagerly opens a single connection
        // rather than the full max_size. One successful dial is enough for
        // build() to succeed even against a briefly unavailable server.
        assert_eq!(pool.state().connections, 1);
    }

    #[test]
    fn build_prewarms_up_to_min_idle() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let pool = pool_builder(addr)
            .max_size(3)
            .min_idle(Some(3))
            .build()
            .unwrap();

        // An explicit min_idle prewarms that many connections up front.
        assert_eq!(pool.state().connections, 3);
    }

    #[test]
    fn guard_returns_connection_to_pool_on_drop() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        // Pin min_idle == max_size so the pool holds a fixed set of connections
        // and never replenishes mid-test, keeping the counts deterministic.
        let pool = pool_builder(addr)
            .max_size(2)
            .min_idle(Some(2))
            .build()
            .unwrap();

        let before = pool.state().connections;
        {
            let _c = pool.get().unwrap();
            assert_eq!(pool.state().idle_connections, before - 1);
        }
        // Dropping the guard checks the same connection back in, with no new one opened.
        assert_eq!(pool.state().connections, before);
        assert_eq!(pool.state().idle_connections, before);
    }

    #[test]
    fn get_times_out_when_pool_is_exhausted() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let pool = pool_builder(addr)
            .max_size(1)
            .connection_timeout(Duration::from_millis(200))
            .build()
            .unwrap();

        let held = pool.get().unwrap();
        // The single connection is checked out, so a second checkout must time out.
        assert!(pool.get().is_err());
        drop(held);
        // Once returned, a checkout succeeds again.
        assert!(pool.get().is_ok());
    }

    #[test]
    fn concurrent_checkouts_stay_within_bounds() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let pool = pool_builder(addr).max_size(4).build().unwrap();

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let pool = pool.clone();
                std::thread::spawn(move || {
                    let _c = pool.get().unwrap();
                    // Hold the connection briefly to force contention.
                    std::thread::sleep(Duration::from_millis(5));
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert!(pool.state().connections <= 4);
    }

    #[test]
    fn build_rejects_zero_max_size() {
        // r2d2's `max_size(0)` panics; the wrapper defers it to a build-time
        // error so a runtime-derived size of 0 does not abort the caller.
        let res = pool_builder("unused:0".to_string()).max_size(0).build();
        assert!(matches!(res, Err(crate::Error::PoolConfig(_))));
    }

    #[test]
    fn build_rejects_min_idle_exceeding_max_size() {
        // r2d2's `build` panics when min_idle > max_size; surface it as an error.
        let res = pool_builder("unused:0".to_string())
            .max_size(2)
            .min_idle(Some(4))
            .build();
        assert!(matches!(res, Err(crate::Error::PoolConfig(_))));
    }

    #[test]
    fn build_rejects_zero_connection_timeout() {
        // r2d2's timeout setters panic on a zero duration; deferred to an error.
        let res = pool_builder("unused:0".to_string())
            .connection_timeout(Duration::ZERO)
            .build();
        assert!(matches!(res, Err(crate::Error::PoolConfig(_))));
    }

    #[test]
    fn test_on_check_out_does_not_probe_at_build_time() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        // Enabling checkout validation only affects `get()`; `build()` just dials
        // the initial connections without a probe round trip, so it succeeds and
        // prewarms even though nothing answers on the listener.
        let pool = pool_builder(addr)
            .max_size(2)
            .test_on_check_out(true)
            .build()
            .unwrap();
        assert_eq!(pool.state().connections, 1);
    }
}
