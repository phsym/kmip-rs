use crate::{
    Error, ProtocolError, RequestMessage, ResponseBatchItem, ResponseMessage, Result,
    enums::{BatchErrorContinuationOption, ResultReason},
    middlewares::{Chain, Middleware, Next},
    payloads::{
        DiscoverVersionsRequestPayload, DiscoverVersionsResponsePayload, Request, RequestPayload,
        ResponsePayload,
    },
    types::ProtocolVersion,
};
use std::{
    fs,
    io::{self, ErrorKind, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    sync::{Arc, OnceLock},
    time::Duration,
    vec::IntoIter,
};

use ttlv::{Decodable, Encodable};

mod batch;
pub use batch::*;

mod cluster;
pub use cluster::*;

pub mod exec;

#[cfg(feature = "pool")]
mod pool;
#[cfg(feature = "pool")]
pub use pool::*;

#[cfg(feature = "tls-rustls")]
mod rustls;
#[cfg(feature = "tls-rustls")]
pub use rustls::*;

#[cfg(feature = "tls-native")]
mod nativetls;
#[cfg(feature = "tls-native")]
pub use nativetls::*;

#[cfg(feature = "tls-openssl")]
mod openssl;
#[cfg(feature = "tls-openssl")]
pub use openssl::*;

#[cfg(feature = "tls-boring")]
mod boring;
#[cfg(feature = "tls-boring")]
pub use boring::*;

const DEFAULT_SUPPORTED_VERSIONS: &[ProtocolVersion] = &[
    ProtocolVersion::V1_4,
    ProtocolVersion::V1_3,
    ProtocolVersion::V1_2,
    ProtocolVersion::V1_1,
    ProtocolVersion::V1_0,
];

const DEFAULT_SOCKET_TIMEOUT: Option<Duration> = Some(Duration::from_secs(30));

/// The transport-layer inputs a [`TransportBackend`] needs to build a [`Connector`]:
/// the CA/root certificates and client identity used to authenticate the TLS
/// session, plus the socket options applied to the underlying `TcpStream` before
/// the handshake.
///
/// It carries no protocol-layer state (middleware, protocol versions) and no
/// target address; the address is supplied per connection to
/// [`create_connector`](TransportBackend::create_connector). [`ClientBuilder`] owns one
/// of these and its transport setters (`add_root_certificate`, `identity`,
/// `read_timeout`, …) write through to it.
#[non_exhaustive]
pub struct ConnectorConfig {
    /// PEM-encoded CA/root certificate bundles to trust when verifying the
    /// server.
    ///
    /// Non-empty **replaces** the backend's default trust rather than adding to
    /// it: every backend builds its verifier from these roots alone. Platform
    /// and public roots are no longer trusted, so a client that also reaches
    /// publicly signed endpoints must supply their roots here too. Leave empty
    /// for the backend defaults.
    pub root_certs: Vec<Vec<u8>>,
    /// Optional client certificate chain and private key (both PEM-encoded) used
    /// for TLS client authentication.
    pub identity: Option<(Vec<u8>, Vec<u8>)>,
    /// TCP connect timeout applied per resolved address when dialing. `None`
    /// uses the OS default.
    pub connect_timeout: Option<Duration>,
    /// Read timeout applied to the `TcpStream` before the handshake. `None`
    /// disables it (reads block indefinitely).
    pub read_timeout: Option<Duration>,
    /// Write timeout applied to the `TcpStream` before the handshake. `None`
    /// disables it (writes block indefinitely).
    pub write_timeout: Option<Duration>,
    /// Whether `TCP_NODELAY` (Nagle's algorithm disabled) is set on the socket.
    pub tcp_nodelay: bool,
}

/// The socket-level subset of [`ConnectorConfig`]: the options applied to the
/// `TcpStream` when dialing, and nothing else. The four values always travel
/// together, so connectors store and pass this one `Copy` value rather than four
/// positional `Option<Duration>` / `bool` parameters that transpose silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketOptions {
    /// TCP connect timeout applied per resolved address. `None` uses the OS default.
    pub connect_timeout: Option<Duration>,
    /// Read timeout applied before the handshake. `None` blocks indefinitely.
    pub read_timeout: Option<Duration>,
    /// Write timeout applied before the handshake. `None` blocks indefinitely.
    pub write_timeout: Option<Duration>,
    /// Whether `TCP_NODELAY` is set on the socket.
    pub tcp_nodelay: bool,
}

impl From<&ConnectorConfig> for SocketOptions {
    fn from(config: &ConnectorConfig) -> Self {
        Self {
            connect_timeout: config.connect_timeout,
            read_timeout: config.read_timeout,
            write_timeout: config.write_timeout,
            tcp_nodelay: config.tcp_nodelay,
        }
    }
}

impl Default for ConnectorConfig {
    /// Trusts only the backend's default roots, no client identity, the default
    /// 30s read/write timeouts, and `TCP_NODELAY` enabled.
    fn default() -> Self {
        Self {
            root_certs: Vec::new(),
            identity: None,
            connect_timeout: None,
            read_timeout: DEFAULT_SOCKET_TIMEOUT,
            write_timeout: DEFAULT_SOCKET_TIMEOUT,
            tcp_nodelay: true,
        }
    }
}

/// Stamps out [`Connector`]s that share one backend's already-prepared TLS
/// state, returned by [`TransportBackend::prepare`].
///
/// Building a connector is infallible: everything that can fail — parsing the
/// CA bundle, loading the client identity, validating the socket options — has
/// already happened in `prepare`. That is what lets a cluster pay those costs
/// once for the whole endpoint pool.
pub trait ConnectorFactory: Send + Sync {
    /// Builds a connector for `addr`, validated against `domain`.
    fn connector(&self, addr: String, domain: &str) -> Arc<dyn Connector>;
}

pub trait TransportBackend: 'static + Send + Sync {
    /// Parses the CA bundle and client identity into whatever shared TLS state
    /// this backend needs, returning a factory that builds connectors from it.
    ///
    /// This is the one method a backend implements; both
    /// [`create_connector`](Self::create_connector) and
    /// [`create_connectors`](Self::create_connectors) are derived from it, so
    /// the single- and multi-endpoint paths cannot drift, and "expensive state
    /// is built once" holds by construction rather than by convention.
    fn prepare(&self, config: &ConnectorConfig) -> Result<Box<dyn ConnectorFactory>>;

    /// Builds a single connector for `addr`, validated against `domain`.
    fn create_connector(
        &self,
        config: &ConnectorConfig,
        addr: String,
        domain: &str,
    ) -> Result<Arc<dyn Connector>> {
        Ok(self.prepare(config)?.connector(addr, domain))
    }

    /// Builds a connector for each `(addr, domain)` endpoint, all sharing one
    /// prepared TLS state instead of rebuilding it per endpoint.
    fn create_connectors(
        &self,
        config: &ConnectorConfig,
        endpoints: &[(String, String)],
    ) -> Result<Vec<Arc<dyn Connector>>> {
        let factory = self.prepare(config)?;
        Ok(endpoints
            .iter()
            .map(|(addr, domain)| factory.connector(addr.clone(), domain))
            .collect())
    }
}

/// Rejects a zero socket timeout.
///
/// The `TcpStream` setters refuse `Duration::ZERO`, so zero is not "no timeout"
/// (that is `None`) but a value that fails every dial against a healthy server.
/// Config plumbed as `from_secs(secs)` makes it a plausible input.
fn checked_timeout(name: &str, timeout: Option<Duration>) -> Result<Option<Duration>> {
    if timeout == Some(Duration::ZERO) {
        return Err(Error::Config(format!(
            "{name} must be greater than zero; use `None` to disable it"
        )));
    }
    Ok(timeout)
}

/// Configures how [`Client`] connections are opened (TLS backend, certificates,
/// socket options, protocol settings), independently of which server they
/// target. The address is supplied later, per connection.
///
/// Obtain one from [`Client::builder`] (rustls default backend) or
/// [`ClientBuilder::new`] (explicit backend), set the options, then call
/// [`connect`](Self::connect) to open a [`Client`] or, with the `pool` feature,
/// `pool` to seed a connection pool. A single builder can target several servers
/// by calling [`connect`](Self::connect) more than once with different
/// addresses.
#[must_use = "builder must be used to create a client or pool"]
pub struct ClientBuilder {
    // Transport-layer config handed to the TLS backend to build a connector.
    connector: ConnectorConfig,
    backend: Box<dyn TransportBackend>,
    middlewares: Vec<Arc<dyn Middleware<crate::Error>>>,
    version: Option<ProtocolVersion>,
    // Protocol config forwarded onto the built `ClientConfig`. `None` for
    // `supported_versions` means "use the default list".
    supported_versions: Option<Vec<ProtocolVersion>>,
}

#[cfg(feature = "default-tls-rustls")]
impl Default for ClientBuilder {
    /// A builder using the built-in rustls backend, equivalent to
    /// `ClientBuilder::new(RustlsBackend)`.
    fn default() -> Self {
        Self::new(rustls::RustlsBackend)
    }
}

impl ClientBuilder {
    /// Creates a builder using `backend` as the transport backend. The target
    /// server is chosen later, when calling [`connect`](Self::connect) or `pool`.
    pub fn new(backend: impl TransportBackend) -> Self {
        Self {
            connector: ConnectorConfig::default(),
            backend: Box::new(backend),
            middlewares: Vec::new(),
            version: None,
            supported_versions: None,
        }
    }

    /// Reads a PEM-encoded CA/root bundle from `path`. See
    /// [`add_root_certificate`](Self::add_root_certificate) for trust semantics.
    pub fn add_root_certificate_file(self, path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(self.add_root_certificate(fs::read(path)?))
    }

    /// Reads the client certificate chain and private key from PEM files.
    ///
    /// See [`identity`](Self::identity) for the accepted key formats.
    pub fn identity_file(self, cert: impl AsRef<Path>, key: impl AsRef<Path>) -> io::Result<Self> {
        Ok(self.identity(fs::read(cert)?, fs::read(key)?))
    }

    /// Adds a PEM-encoded CA/root certificate bundle to the trusted roots.
    ///
    /// Adding *any* root **replaces** the backend's default trust store, so
    /// platform and public roots stop being trusted. Add them explicitly if the
    /// client also talks to publicly signed endpoints. See
    /// [`ConnectorConfig::root_certs`].
    pub fn add_root_certificate(mut self, pem: Vec<u8>) -> Self {
        self.connector.root_certs.push(pem);
        self
    }

    /// Sets the client certificate chain and private key (both PEM-encoded)
    /// used for TLS client authentication.
    ///
    /// The accepted private key formats depend on the TLS backend; see the
    /// backend type's documentation (e.g. `NativeTlsBackend`).
    pub fn identity(mut self, cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Self {
        self.connector.identity = Some((cert_pem, key_pem));
        self
    }

    /// Sets the read timeout applied to the underlying `TcpStream` before the
    /// TLS handshake. `None` disables the timeout (reads block indefinitely).
    ///
    /// Returns [`Error::Config`] for a zero duration; use `None` to disable.
    pub fn read_timeout(mut self, timeout: Option<Duration>) -> Result<Self> {
        self.connector.read_timeout = checked_timeout("read_timeout", timeout)?;
        Ok(self)
    }

    /// Sets the write timeout applied to the underlying `TcpStream` before the
    /// TLS handshake. `None` disables the timeout (writes block indefinitely).
    ///
    /// Returns [`Error::Config`] for a zero duration; use `None` to disable.
    pub fn write_timeout(mut self, timeout: Option<Duration>) -> Result<Self> {
        self.connector.write_timeout = checked_timeout("write_timeout", timeout)?;
        Ok(self)
    }

    /// Enables or disables `TCP_NODELAY` (Nagle's algorithm) on the underlying
    /// socket. Enabled by default to minimize request/response latency.
    pub fn tcp_nodelay(mut self, nodelay: bool) -> Self {
        self.connector.tcp_nodelay = nodelay;
        self
    }

    /// Sets the TCP connect timeout applied when opening each connection. `None`
    /// (the default) uses the OS default, which for a dropped/black-holed host
    /// can be well over a minute — set a bound when using
    /// [`Self::connect_cluster`] so failover moves on quickly.
    ///
    /// Returns [`Error::Config`] for a zero duration (`TcpStream::connect_timeout`
    /// refuses it, failing every dial); use `None` for the OS default.
    pub fn connect_timeout(mut self, timeout: Option<Duration>) -> Result<Self> {
        self.connector.connect_timeout = checked_timeout("connect_timeout", timeout)?;
        Ok(self)
    }

    /// Appends a middleware to the chain of every client built here. The
    /// middleware chain is shared cheaply (via `Arc`) across all clients built
    /// from this configuration.
    pub fn with_middleware(mut self, middleware: impl Middleware<crate::Error> + 'static) -> Self {
        self.middlewares.push(Arc::new(middleware));
        self
    }

    /// Pins the protocol version, skipping version negotiation on built clients.
    pub fn with_version(mut self, version: ProtocolVersion) -> Self {
        self.version = Some(version);
        self
    }

    /// Sets the list of protocol versions offered during version negotiation
    /// (normalized newest-first and deduped when the config is built).
    pub fn with_supported_versions(mut self, versions: &[ProtocolVersion]) -> Self {
        self.supported_versions = Some(versions.to_vec());
        self
    }

    /// Finishes the transport configuration into the crate-internal
    /// `ClientConfig` recipe for the KMIP server at `addr`/`domain` that
    /// [`connect`](Self::connect) and, with the `pool` feature, `pool` build
    /// from, carrying over the protocol settings staged via the `with_*`
    /// methods. No connection is opened here.
    pub(crate) fn build(&self, addr: impl Into<String>, domain: &str) -> Result<ClientConfig> {
        let connector = self
            .backend
            .create_connector(&self.connector, addr.into(), domain)?;
        Ok(self.build_with_connector(connector))
    }

    /// Builds a `ClientConfig` backed by a [`ClusterConnector`] over every
    /// endpoint of `config`. Shared by [`connect_cluster`](Self::connect_cluster)
    /// and, with the `pool` feature, `pool_cluster`. Opens no connection.
    pub(crate) fn build_cluster(&self, config: ClusterConfig) -> Result<ClientConfig> {
        let ClusterConfig {
            endpoints,
            mode,
            cooldown,
        } = config;
        let connectors = self
            .backend
            .create_connectors(&self.connector, &endpoints)?;
        let labelled = endpoints
            .into_iter()
            .map(|(addr, _domain)| addr)
            .zip(connectors);
        let cluster = ClusterConnector::new(labelled, cooldown, mode)?;
        Ok(self.build_with_connector(Arc::new(cluster)))
    }

    /// Builds the `ClientConfig` for an already-created `connector`, carrying
    /// over the protocol settings staged via the `with_*` methods. Shared by
    /// [`build`](Self::build) and [`connect_cluster`](Self::connect_cluster),
    /// which supplies a [`ClusterConnector`] spanning several endpoints.
    fn build_with_connector(&self, connector: Arc<dyn Connector>) -> ClientConfig {
        let mut config = ClientConfig::new(connector);
        if let Some(versions) = &self.supported_versions {
            config = config.with_supported_versions(versions);
        }
        if let Some(v) = self.version {
            // `config` is freshly built above, so its `OnceLock` is empty and
            // this set always succeeds; a pinned version skips negotiation.
            let _ = config.version.set(v);
        }
        // `config` is freshly built above (its middleware `Arc` is uniquely
        // owned), so `make_mut` never clones, and extending with an empty chain
        // is a no-op. No need to guard on `is_empty`.
        Arc::make_mut(&mut config.middlewares).extend(self.middlewares.iter().cloned());
        config
    }

    /// Connects to the KMIP server at `addr` (a `"host:port"` string),
    /// performing the TLS handshake with `domain` as the SNI hostname.
    ///
    /// The address is passed as-is to the connector and re-resolved on every
    /// connection it opens (this call, [`Client::try_clone`], and reconnects
    /// after a dropped connection), so a server that fails over to a new IP
    /// behind the same hostname is picked up automatically. A literal IP such as
    /// `"10.0.0.1:5696"` is accepted too (it is parsed, not resolved).
    ///
    /// A single builder can be reused to target several servers by calling this
    /// more than once with different addresses.
    pub fn connect(&self, addr: impl Into<String>, domain: &str) -> Result<Client> {
        self.build(addr, domain)?.connect()
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

    // TODO: Add KMIP authentication
    // TODO: Fine tune TLS cipher suites when/if possible
}

fn configure_stream(
    stream: &TcpStream,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
) -> io::Result<()> {
    stream.set_read_timeout(read_timeout)?;
    stream.set_write_timeout(write_timeout)?;
    stream.set_nodelay(tcp_nodelay)?;
    Ok(())
}

/// Whether `e` means the connection itself died, rather than an application
/// level or transient condition. Single-sourced here because both the client's
/// reconnect-and-retry guard and the cluster connector's endpoint health
/// tracking classify the same errors; see
/// [`MonitoredTransport`](cluster::MonitoredTransport), which treats these plus
/// a few "never answered" kinds as the endpoint's fault.
pub(crate) fn is_disconnect(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
    )
}

/// Opens a TCP connection to `addr` (a `"host:port"` string, re-resolved on
/// every call) and applies the shared socket options. Used by every TLS
/// backend to dial the server before running its handshake.
///
/// With `connect_timeout` set, each resolved address is tried with a bounded
/// [`TcpStream::connect_timeout`] so a black-holed host does not block for the
/// OS default (which can exceed a minute). The bound is *per resolved address*:
/// a host that resolves to N addresses (e.g. a dual-stack IPv4/IPv6 name) can
/// take up to N × `connect_timeout` before `dial` gives up, but each address
/// gets a full budget so a black-holed one does not consume another's. `None`
/// uses the OS default.
pub(crate) fn dial(addr: &str, opts: &SocketOptions) -> io::Result<TcpStream> {
    let stream = match opts.connect_timeout {
        Some(timeout) => {
            // Seeded with the "resolved to nothing" error, then overwritten by
            // each address's real failure, so the fallback needs no second
            // layer of `unwrap_or_else`.
            let mut last_err = io::Error::new(
                ErrorKind::InvalidInput,
                format!("no addresses resolved for {addr}"),
            );
            addr.to_socket_addrs()?
                .find_map(|sa| {
                    TcpStream::connect_timeout(&sa, timeout)
                        .map_err(|e| last_err = e)
                        .ok()
                })
                .ok_or(last_err)?
        }
        None => TcpStream::connect(addr)?,
    };
    configure_stream(
        &stream,
        opts.read_timeout,
        opts.write_timeout,
        opts.tcp_nodelay,
    )?;
    Ok(stream)
}

pub trait Transport: Read + Write + Send {}
impl<T> Transport for T where T: Read + Write + Send {}

/// Establishes connections on behalf of a [`Client`].
///
/// The client keeps its connector and calls [`connect`](Connector::connect)
/// again whenever a fresh connection is needed (e.g. [`Client::try_clone`]).
pub trait Connector: Send + Sync {
    /// Opens a new connection, returning a stream ready for KMIP traffic:
    /// connected and, for TLS backends, with the handshake already completed.
    fn connect(&self) -> Result<Box<dyn Transport>>;
}

pub struct Client {
    // The shared, cheap-to-clone configuration this client was opened with. Its
    // `version` field doubles as the cache for the negotiated protocol version
    // (populated on first use when the version was not pinned).
    config: ClientConfig,
    conn: ttlv::Stream<Box<dyn Transport>>,
    // Set when an exchange left `conn` unusable. The dangerous case is a
    // request written whose response was never read (a read timeout, a decode
    // failure): the next bytes on the wire belong to the *previous* request, so
    // reusing the stream pairs a response with the wrong request. For a pooled
    // client that means handing one caller's response to another.
    broken: bool,
}

/// The crate-internal, cheap-to-clone recipe for opening [`Client`]
/// connections.
///
/// A `ClientConfig` holds the shared, `Send + Sync` pieces needed to build a
/// client (the [`Connector`], middleware chain, supported-version list, and an
/// optional pinned protocol version) but no live connection of its own. Each
/// [`connect`](Self::connect) call opens a fresh connection via the connector,
/// so a single config can spawn many independent clients (and seed a connection
/// pool). It is not part of the public API: users configure via
/// [`ClientBuilder`] and hold [`Client`]s (or a `ClientPool`).
#[derive(Clone)]
pub(crate) struct ClientConfig {
    connector: Arc<dyn Connector>,
    // Shared via `Arc` so cloning a config (once per pooled connection and on
    // every `try_clone`/reconnect) is a refcount bump rather than a deep copy.
    supported_versions: Arc<Vec<ProtocolVersion>>,
    // Shared via `Arc` so the negotiated version is cached once across every
    // client cloned from this config (all pooled connections + `try_clone`),
    // not re-discovered per connection. A pinned version (`with_version`) is
    // pre-set here at build time, which skips negotiation entirely.
    version: Arc<OnceLock<ProtocolVersion>>,
    middlewares: Arc<Vec<Arc<dyn Middleware<crate::Error>>>>,
}

impl ClientConfig {
    /// Creates a config from a [`Connector`], using the default supported
    /// protocol versions, no middleware, and no pinned version.
    ///
    /// The connector is not dialed here; a connection is only opened when
    /// [`connect`](Self::connect) is called.
    pub fn new(connector: Arc<dyn Connector>) -> Self {
        Self {
            connector,
            supported_versions: Arc::new(DEFAULT_SUPPORTED_VERSIONS.to_vec()),
            version: Arc::new(OnceLock::new()),
            middlewares: Arc::new(Vec::new()),
        }
    }

    /// Normalizes and stores the list of protocol versions offered during
    /// version negotiation (sorted newest-first and deduped). Used by
    /// [`ClientBuilder::build`] to apply the builder's staged list.
    #[must_use]
    pub(crate) fn with_supported_versions(mut self, versions: &[ProtocolVersion]) -> Self {
        let list = Arc::make_mut(&mut self.supported_versions);
        list.clear();
        list.extend_from_slice(versions);
        list.sort_by(|a, b| b.cmp(a));
        list.dedup();
        self
    }

    /// Opens a new connection and assembles a [`Client`] from this config.
    /// Fallible and may block on the TCP/TLS handshake. Call it repeatedly to
    /// open independent connections that share this config.
    pub fn connect(&self) -> Result<Client> {
        Ok(Client {
            conn: ttlv::Stream::new(self.connector.connect()?),
            config: self.clone(),
            broken: false,
        })
    }
}

impl Client {
    /// Starts building a client using the built-in rustls backend.
    ///
    /// Returns a [`ClientBuilder`]; set TLS/socket and protocol options on
    /// it, then call [`connect(addr, domain)`](ClientBuilder::connect)
    /// (or, with the `pool` feature, `pool`) to target a specific server. See
    /// [`ClientBuilder::new`] to choose a different TLS backend.
    #[cfg(feature = "default-tls-rustls")]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Returns a new `Client` that opens its own connection but reuses this
    /// client's configuration.
    ///
    /// A fresh transport is established via [`Connector::connect`], which is
    /// fallible and may block on the TCP/TLS handshake. The connector,
    /// middleware chain, and supported-version list are shared cheaply via
    /// `Arc` (the whole client configuration is cloned by a few refcount bumps).
    ///
    /// The negotiated protocol version is carried over and **not** renegotiated.
    /// A single-endpoint client reconnects to the same server, so this holds. A
    /// clustered client (see [`ClientBuilder::connect_cluster`]) may open the
    /// clone — and later reconnects — on a *different* node
    /// ([`ClusterMode::RoundRobin`] always rotates; [`ClusterMode::Failover`]
    /// re-prefers a recovered leader), so on a version-skewed cluster (e.g. a
    /// rolling upgrade) the cached version can be one the new node does not
    /// support. Keep cluster nodes on a common protocol version.
    pub fn try_clone(&self) -> Result<Self> {
        self.config.connect()
    }

    pub fn version(&mut self) -> crate::Result<ProtocolVersion> {
        if let Some(v) = self.config.version.get() {
            return Ok(*v);
        }
        tracing::debug!("Negotiating protocol version with server...");
        let resp = self.roundtrip(RequestMessage::new(
            ProtocolVersion::V1_1,
            DiscoverVersionsRequestPayload {
                protocol_version: if self.config.supported_versions.is_empty() {
                    tracing::trace!(
                        "Client supported version list is empty, using default: {:?}",
                        DEFAULT_SUPPORTED_VERSIONS
                    );
                    DEFAULT_SUPPORTED_VERSIONS.to_vec()
                } else {
                    tracing::trace!(
                        "Client supported versions: {:?}",
                        self.config.supported_versions
                    );
                    self.config.supported_versions.as_ref().clone()
                },
            },
        ))?;

        let negotiated = match resp
            .batch_item
            .into_iter()
            .next()
            .ok_or(Error::MissingBatchItem)?
            .success()
        {
            Ok(pl) => {
                let pl: DiscoverVersionsResponsePayload =
                    pl.ok_or(Error::MissingResponsePayload)?.try_into()?;
                tracing::trace!("Server supported versions: {:?}", pl.protocol_version);
                pl.protocol_version.into_iter().next().unwrap_or_default()
            }
            Err(ProtocolError {
                reason: Some(ResultReason::OperationNotSupported),
                ..
            }) => {
                // TODO: Check that default version is in the supported version list before using it
                tracing::debug!(
                    "DiscoverVersions operation not supported, falling back to default protocol version"
                );
                ProtocolVersion::default()
            }
            Err(other) => return Err(other.into()),
        };

        // Publish the negotiated version to the cache shared (via `Arc`) by
        // every client built from this config: all pooled connections,
        // `try_clone` descendants, and any client opened from it later.
        // `get_or_init` makes the first negotiation win: if a sibling raced us
        // it keeps its value and we adopt it, so every current and future
        // client converges on a single version instead of each returning its
        // own. The pinned version staged on `ClientBuilder` is never touched;
        // it only seeds this cell up front in `build`.
        let version = *self.config.version.get_or_init(|| negotiated);
        tracing::debug!("Negotiated protocol version: {version}");
        Ok(version)
    }

    /// Sends `msg` and returns its response, re-dialing and retrying if the
    /// connection died.
    ///
    /// Any error here marks the connection `broken`: once a request is written,
    /// an error leaves us unsure how much of its response is still queued, so
    /// the stream can no longer be trusted to sit at a message boundary.
    fn roundtrip_ttlv<D: Decodable>(&mut self, msg: &impl Encodable) -> Result<D> {
        // Replace a stream left dead or mid-message, so this request cannot be
        // answered by the tail of the previous one.
        if self.broken {
            tracing::debug!("Re-dialing a connection left unusable by a previous exchange");
            self.conn = ttlv::Stream::new(self.config.connector.connect()?);
            self.broken = false;
        }
        let result = self.exchange(msg);
        self.broken = result.is_err();
        result
    }

    fn exchange<D: Decodable>(&mut self, msg: &impl Encodable) -> Result<D> {
        //TODO: Better reconnection loop. Do we really need a retry counter here ?
        let mut retry = 3;
        loop {
            match self.conn.roundtrip(msg) {
                // A connection dropped while idle surfaces as a graceful EOF or,
                // when the peer resets it, as a reset/aborted/broken-pipe error.
                // All of these are recoverable by re-dialing and retrying, which
                // is what lets pooled clients self-heal a connection that died
                // between checkouts.
                Err(ttlv::Error::Io(e)) if retry > 0 && is_disconnect(&e) => {
                    tracing::warn!("I/O error during request/response roundtrip: {e:?}");
                    tracing::warn!(
                        "Attempting to reconnect and retry the request ({retry} retries left)",
                    );
                    //FIXME: If connect fails, there's no retry as the error is returned immediately.
                    self.conn = ttlv::Stream::new(self.config.connector.connect()?);
                    retry -= 1;
                    continue;
                }
                Err(e) => return Err(e.into()),
                Ok(resp) => return Ok(resp),
            }
        }
    }

    /// Validates that the `batch_count` field in a response header matches the
    /// actual number of batch items in the message, as required by the KMIP spec.
    #[inline]
    fn validate_batch_count(resp: &ResponseMessage) -> Result<()> {
        let expected = resp.header.batch_count;
        let got = resp.batch_item.len();
        if expected < 0 || (expected as usize) != got {
            return Err(Error::BatchCountMismatch { expected, got });
        }
        Ok(())
    }

    pub fn roundtrip(&mut self, msg: RequestMessage) -> Result<ResponseMessage> {
        let resp = Next {
            idx: 0,
            chain: self,
        }
        .run(msg)?;
        Self::validate_batch_count(&resp)?;
        Ok(resp)
    }

    pub fn request<R: Request>(&mut self, pl: R) -> Result<R::Response> {
        let msg = RequestMessage::new(self.version()?, pl);
        let resp = self.roundtrip(msg)?;
        resp.batch_item
            .into_iter()
            .next()
            .ok_or(Error::MissingBatchItem)?
            .success()?
            .ok_or(Error::MissingResponsePayload)?
            .try_into()
    }

    fn raw_batch<I, E>(
        &mut self,
        items: I,
        cont: Option<BatchErrorContinuationOption>,
    ) -> Result<ResponseBatchIter>
    where
        I: IntoIterator<Item = E>,
        E: Into<RequestPayload>,
    {
        let mut msg = RequestMessage::new_batched(self.version()?, items)?;
        msg.header.batch_error_continuation_option = cont;

        let resp = self.roundtrip(msg)?;
        Ok(ResponseBatchIter(resp.batch_item.into_iter()))
    }

    pub fn batch<I>(&mut self, batch: I) -> Result<I::Response>
    where
        I: Batch,
    {
        let resp = self.raw_batch(batch.into_iter(), None)?;
        I::map_response(resp)
    }

    pub fn batch_opt<I>(
        &mut self,
        batch: I,
        on_err: BatchErrorContinuationOption,
    ) -> Result<I::Response>
    where
        I: Batch,
    {
        let resp = self.raw_batch(batch.into_iter(), Some(on_err))?;
        I::map_response(resp)
    }
}

pub struct ResponseBatchIter(IntoIter<ResponseBatchItem>);

impl Iterator for ResponseBatchIter {
    type Item = Result<Option<ResponsePayload>>;
    fn next(&mut self) -> Option<Self::Item> {
        let next = self.0.next()?;
        Some(next.success().map_err(Into::into))
    }
}

impl Chain for Client {
    type Error = crate::Error;
    fn get_middleware(&self, idx: usize) -> Option<Arc<dyn Middleware<Self::Error>>> {
        self.config.middlewares.get(idx).cloned()
    }

    fn final_handler(&mut self, req: RequestMessage) -> Result<ResponseMessage> {
        self.roundtrip_ttlv(&req)
    }
}

#[cfg(test)]
impl ConnectorConfig {
    /// A config trusting a single PEM root-certificate bundle. Shared by the TLS
    /// backends' tests, which each feed `create_connector` a known-good and a
    /// malformed CA bundle.
    pub(crate) fn with_root(root: Vec<u8>) -> Self {
        Self {
            root_certs: vec![root],
            ..Self::default()
        }
    }
}

/// A plain (non-TLS) [`Connector`] that dials a re-resolvable `"host:port"`
/// string on every `connect()`, mirroring how the real TLS connectors reach the
/// server. Shared by this module's tests and the `pool` module's tests.
#[cfg(test)]
pub(crate) struct LocalConnector(pub(crate) String);

#[cfg(test)]
impl Connector for LocalConnector {
    fn connect(&self) -> Result<Box<dyn Transport>> {
        Ok(Box::new(TcpStream::connect(self.0.as_str())?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[cfg(feature = "default-tls-rustls")]
    #[test]
    fn test_client_builder_defaults() {
        let builder = Client::builder();
        assert_eq!(
            builder.connector.read_timeout,
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            builder.connector.write_timeout,
            Some(Duration::from_secs(30))
        );
        assert!(builder.connector.tcp_nodelay);
        assert_eq!(builder.connector.connect_timeout, None);
    }

    #[cfg(feature = "default-tls-rustls")]
    #[test]
    fn test_client_builder_connect_timeout() {
        let builder = Client::builder()
            .connect_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        assert_eq!(
            builder.connector.connect_timeout,
            Some(Duration::from_secs(3))
        );
    }

    #[cfg(feature = "default-tls-rustls")]
    #[test]
    fn zero_socket_timeouts_are_rejected() {
        // The socket setters all reject `Duration::ZERO`, so a zero here fails
        // every dial against a healthy server. Config plumbed as `from_secs(n)`
        // makes 0 plausible, so it must not reach the socket.
        for (name, result) in [
            (
                "connect_timeout",
                Client::builder().connect_timeout(Some(Duration::ZERO)),
            ),
            (
                "read_timeout",
                Client::builder().read_timeout(Some(Duration::ZERO)),
            ),
            (
                "write_timeout",
                Client::builder().write_timeout(Some(Duration::ZERO)),
            ),
        ] {
            match result {
                Err(Error::Config(msg)) => {
                    assert!(msg.contains(name), "{name}: unexpected message {msg:?}");
                }
                Err(e) => panic!("{name}: expected Error::Config, got {e:?}"),
                Ok(_) => panic!("{name}: expected Error::Config, got a builder"),
            }
        }
    }

    #[cfg(feature = "default-tls-rustls")]
    #[test]
    fn none_disables_socket_timeouts_without_error() {
        // `None` is the documented way to disable a timeout.
        let builder = Client::builder()
            .connect_timeout(None)
            .and_then(|b| b.read_timeout(None))
            .and_then(|b| b.write_timeout(None))
            .expect("`None` must be accepted");
        assert_eq!(builder.connector.connect_timeout, None);
        assert_eq!(builder.connector.read_timeout, None);
        assert_eq!(builder.connector.write_timeout, None);
    }

    #[test]
    fn cluster_config_defaults_and_builders() {
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

    #[cfg(feature = "default-tls-rustls")]
    #[test]
    fn test_client_builder_custom_timeouts() {
        let builder = Client::builder()
            .read_timeout(Some(Duration::from_secs(10)))
            .unwrap()
            .write_timeout(Some(Duration::from_secs(60)))
            .unwrap()
            .tcp_nodelay(false);

        assert_eq!(
            builder.connector.read_timeout,
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            builder.connector.write_timeout,
            Some(Duration::from_secs(60))
        );
        assert!(!builder.connector.tcp_nodelay);
    }

    #[cfg(feature = "default-tls-rustls")]
    #[test]
    fn test_client_builder_disable_timeouts() {
        let builder = Client::builder()
            .read_timeout(None)
            .unwrap()
            .write_timeout(None)
            .unwrap();

        assert_eq!(builder.connector.read_timeout, None);
        assert_eq!(builder.connector.write_timeout, None);
    }

    #[cfg(feature = "default-tls-rustls")]
    #[test]
    fn builder_with_shortcuts_forward_to_built_config() {
        let config = Client::builder()
            .with_middleware(NoopMiddleware)
            .with_middleware(NoopMiddleware)
            .with_version(ProtocolVersion::V1_2)
            .with_supported_versions(&[ProtocolVersion::V1_2, ProtocolVersion::V1_4])
            .build("localhost:5696", "localhost")
            .unwrap();

        // Both middlewares, the pinned version, and the supported-version list
        // (sorted descending + deduped by ClientConfig::with_supported_versions)
        // land on the built config.
        assert_eq!(config.middlewares.len(), 2);
        assert_eq!(config.version.get(), Some(&ProtocolVersion::V1_2));
        assert_eq!(
            *config.supported_versions,
            vec![ProtocolVersion::V1_4, ProtocolVersion::V1_2],
        );
    }

    #[test]
    fn test_configure_stream_applies_settings() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();

        configure_stream(
            &stream,
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(10)),
            true,
        )
        .unwrap();

        assert_eq!(stream.read_timeout().unwrap(), Some(Duration::from_secs(5)));
        assert_eq!(
            stream.write_timeout().unwrap(),
            Some(Duration::from_secs(10))
        );
        assert!(stream.nodelay().unwrap());
    }

    #[test]
    fn test_configure_stream_no_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();

        configure_stream(&stream, None, None, false).unwrap();

        assert_eq!(stream.read_timeout().unwrap(), None);
        assert_eq!(stream.write_timeout().unwrap(), None);
        assert!(!stream.nodelay().unwrap());
    }

    fn make_response(batch_count: i32, item_count: usize) -> ResponseMessage {
        let items: Vec<ResponseBatchItem> = (0..item_count)
            .map(|_| ResponseBatchItem {
                operation: None,
                response_payload: None,
                unique_batch_item_id: None,
                result_status: crate::enums::ResultStatus::Success,
                result_reason: None,
                result_message: None,
                asynchronous_correlation_value: None,
                message_extension: None,
            })
            .collect();
        ResponseMessage {
            header: crate::ResponseHeader {
                protocol_version: ProtocolVersion::V1_4,
                timestamp: chrono::Local::now(),
                nonce: None,
                attestation_type: None,
                client_correlation_value: None,
                server_correlation_value: None,
                batch_count,
            },
            batch_item: items,
        }
    }

    #[test]
    fn validate_batch_count_matches() {
        let resp = make_response(2, 2);
        assert!(Client::validate_batch_count(&resp).is_ok());
    }

    #[test]
    fn validate_batch_count_zero_empty() {
        let resp = make_response(0, 0);
        assert!(Client::validate_batch_count(&resp).is_ok());
    }

    #[test]
    fn validate_batch_count_header_too_large() {
        let resp = make_response(3, 1);
        match Client::validate_batch_count(&resp) {
            Err(Error::BatchCountMismatch {
                expected: 3,
                got: 1,
            }) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn validate_batch_count_header_too_small() {
        let resp = make_response(1, 4);
        match Client::validate_batch_count(&resp) {
            Err(Error::BatchCountMismatch {
                expected: 1,
                got: 4,
            }) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn validate_batch_count_negative_header() {
        let resp = make_response(-1, 0);
        match Client::validate_batch_count(&resp) {
            Err(Error::BatchCountMismatch {
                expected: -1,
                got: 0,
            }) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    struct NoopMiddleware;
    impl<E> Middleware<E> for NoopMiddleware {
        fn call(
            &self,
            next: Next<E>,
            req: RequestMessage,
        ) -> std::result::Result<ResponseMessage, E> {
            next.run(req)
        }
    }

    #[test]
    fn config_clone_shares_middleware_arc() {
        let mut config = ClientConfig::new(Arc::new(LocalConnector("unused:0".to_string())));
        Arc::make_mut(&mut config.middlewares).push(Arc::new(NoopMiddleware));

        let cloned = config.clone();

        // Cloning a config is cheap: it shares the middleware `Arc` rather than
        // deep-copying the chain. This is what makes seeding a pool (which holds
        // a cloned config) cheap.
        assert!(Arc::ptr_eq(&config.middlewares, &cloned.middlewares));
    }

    #[test]
    fn built_client_shares_config_middleware() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mut config = ClientConfig::new(Arc::new(LocalConnector(addr.to_string())));
        Arc::make_mut(&mut config.middlewares).push(Arc::new(NoopMiddleware));

        // Every client built from the same config shares the middleware `Arc`,
        // and `try_clone` (which reuses the client's config) preserves it.
        let client = config.connect().unwrap();
        let clone = client.try_clone().unwrap();

        assert_eq!(client.config.middlewares.len(), 1);
        assert!(Arc::ptr_eq(&config.middlewares, &client.config.middlewares));
        assert!(Arc::ptr_eq(
            &client.config.middlewares,
            &clone.config.middlewares
        ));
    }

    #[test]
    fn negotiated_version_is_shared_across_clients() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // A pool (and `try_clone`) hands out many clients from one config; they
        // must share the negotiated-version cache so a version learned by any
        // one of them is seen by all the others and by clients opened later.
        let config = ClientConfig::new(Arc::new(LocalConnector(addr.to_string())));
        let first = config.connect().unwrap();
        let second = first.try_clone().unwrap();

        // Every client built from the config shares the same version cell.
        assert!(Arc::ptr_eq(&first.config.version, &second.config.version));

        // Publishing a version through one client (as `version()` does via
        // `get_or_init`) is immediately visible to its siblings...
        let shared = *first.config.version.get_or_init(|| ProtocolVersion::V1_2);
        assert_eq!(shared, ProtocolVersion::V1_2);
        assert_eq!(second.config.version.get(), Some(&ProtocolVersion::V1_2));

        // ...and to a client opened from the config *after* it was negotiated.
        let future = config.connect().unwrap();
        assert_eq!(future.config.version.get(), Some(&ProtocolVersion::V1_2));

        // The first negotiation wins: a later racing publish adopts the shared
        // value rather than diverging to its own.
        let adopted = *second.config.version.get_or_init(|| ProtocolVersion::V1_4);
        assert_eq!(adopted, ProtocolVersion::V1_2);
    }

    #[test]
    fn try_clone_reconnects_via_hostname() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // A "host:port" string is re-resolved on every connect(), so both the
        // initial connection and the reconnect performed by try_clone resolve
        // the hostname afresh and succeed.
        let original = ClientConfig::new(Arc::new(LocalConnector(format!("localhost:{port}"))))
            .connect()
            .unwrap();
        let _clone = original.try_clone().unwrap();
    }
}
