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
    sync::Arc,
    time::Duration,
    vec::IntoIter,
};

use ttlv::{Decodable, Encodable};

mod batch;
pub use batch::*;

mod cluster;
pub use cluster::*;

pub mod exec;

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

pub trait TlsBackend: 'static + Send + Sync {
    fn create_connector(
        &self,
        builder: &ClientBuilder,
        addr: String,
        domain: &str,
    ) -> Result<Arc<dyn Connector>>;

    /// Builds a connector for each `(addr, domain)` endpoint of a cluster.
    ///
    /// The default builds each independently via [`Self::create_connector`].
    /// Backends override this to share expensive TLS state (parsed CA bundle /
    /// client identity) across the pool instead of rebuilding it per endpoint.
    fn create_connectors(
        &self,
        builder: &ClientBuilder,
        endpoints: &[(String, String)],
    ) -> Result<Vec<Arc<dyn Connector>>> {
        endpoints
            .iter()
            .map(|(addr, domain)| self.create_connector(builder, addr.clone(), domain))
            .collect()
    }
}

#[must_use = "builder must be used to create a Client"]
pub struct ClientBuilder {
    root_certs: Vec<Vec<u8>>,
    identity: Option<(Vec<u8>, Vec<u8>)>,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
    tls_backend: Box<dyn TlsBackend>,
}

#[cfg(feature = "default-tls-rustls")]
impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new(rustls::RustlsBackend)
    }
}

impl ClientBuilder {
    pub fn new(tls: impl TlsBackend) -> Self {
        Self {
            root_certs: Vec::new(),
            identity: None,
            connect_timeout: None,
            read_timeout: DEFAULT_SOCKET_TIMEOUT,
            write_timeout: DEFAULT_SOCKET_TIMEOUT,
            tcp_nodelay: true,
            tls_backend: Box::new(tls),
        }
    }

    pub fn add_root_certificate_file(self, path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(self.add_root_certificate(fs::read(path)?))
    }

    /// Reads the client certificate chain and private key from PEM files.
    ///
    /// See [`identity`](Self::identity) for the accepted key formats.
    pub fn identity_file(self, cert: impl AsRef<Path>, key: impl AsRef<Path>) -> io::Result<Self> {
        Ok(self.identity(fs::read(cert)?, fs::read(key)?))
    }

    pub fn add_root_certificate(mut self, pem: Vec<u8>) -> Self {
        self.root_certs.push(pem);
        self
    }

    /// Sets the client certificate chain and private key (both PEM-encoded)
    /// used for TLS client authentication.
    ///
    /// The accepted private key formats depend on the TLS backend; see the
    /// backend type's documentation (e.g. `NativeTlsBackend`).
    pub fn identity(mut self, cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Self {
        self.identity = Some((cert_pem, key_pem));
        self
    }

    /// Sets the read timeout applied to the underlying `TcpStream` before the
    /// TLS handshake. `None` disables the timeout (reads block indefinitely).
    pub fn read_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Sets the write timeout applied to the underlying `TcpStream` before the
    /// TLS handshake. `None` disables the timeout (writes block indefinitely).
    pub fn write_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.write_timeout = timeout;
        self
    }

    /// Enables or disables `TCP_NODELAY` (Nagle's algorithm) on the underlying
    /// socket. Enabled by default to minimize request/response latency.
    pub fn tcp_nodelay(mut self, nodelay: bool) -> Self {
        self.tcp_nodelay = nodelay;
        self
    }

    /// Sets the TCP connect timeout applied when opening each connection. `None`
    /// (the default) uses the OS default, which for a dropped/black-holed host
    /// can be well over a minute — set a bound when using
    /// [`Self::connect_cluster`] so failover moves on quickly.
    pub fn connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Connects to the KMIP server at `addr` (a `"host:port"` string),
    /// performing the TLS handshake with `domain` as the SNI hostname.
    ///
    /// The address is stored as-is and re-resolved on every connection the
    /// client opens (initial connect, [`Client::try_clone`], and reconnects
    /// after an unexpected EOF). This means DNS is queried again on each
    /// reconnect, so a server that fails over to a new IP behind the same
    /// hostname is picked up without rebuilding the client. A literal IP such
    /// as `"10.0.0.1:5696"` is accepted too (it is parsed, not resolved).
    pub fn connect(self, addr: impl Into<String>, domain: &str) -> Result<Client> {
        let connector = self
            .tls_backend
            .create_connector(&self, addr.into(), domain)?;
        Client::new(connector)
    }

    /// Connects to a pool of KMIP endpoints with failover and optional load
    /// balancing, using the configured [`TlsBackend`] for every endpoint. See
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
    pub fn connect_cluster(self, config: ClusterConfig) -> Result<Client> {
        let ClusterConfig {
            endpoints,
            mode,
            cooldown,
        } = config;
        let connectors = self.tls_backend.create_connectors(&self, &endpoints)?;
        let labelled = endpoints
            .into_iter()
            .map(|(addr, _domain)| addr)
            .zip(connectors);
        let cluster = ClusterConnector::with_mode(labelled, cooldown, mode)?;
        Client::new(Arc::new(cluster))
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
pub(crate) fn dial(
    addr: &str,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
) -> io::Result<TcpStream> {
    let stream = match connect_timeout {
        Some(timeout) => {
            let mut last_err = None;
            addr.to_socket_addrs()?
                .find_map(|sa| match TcpStream::connect_timeout(&sa, timeout) {
                    Ok(stream) => Some(stream),
                    Err(e) => {
                        last_err = Some(e);
                        None
                    }
                })
                .ok_or_else(|| {
                    last_err.unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("no addresses resolved for {addr}"),
                        )
                    })
                })?
        }
        None => TcpStream::connect(addr)?,
    };
    configure_stream(&stream, read_timeout, write_timeout, tcp_nodelay)?;
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
    connector: Arc<dyn Connector>,
    supported_versions: Vec<ProtocolVersion>,
    version: Option<ProtocolVersion>,
    conn: ttlv::Stream<Box<dyn Transport>>,
    middlewares: Arc<Vec<Arc<dyn Middleware<crate::Error>>>>,
}

impl Client {
    #[cfg(feature = "default-tls-rustls")]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    pub fn new(connector: Arc<dyn Connector>) -> Result<Self> {
        Ok(Self {
            conn: ttlv::Stream::new(connector.connect()?),
            connector,
            supported_versions: DEFAULT_SUPPORTED_VERSIONS.to_vec(),
            version: None,
            middlewares: Arc::new(Vec::new()),
        })
    }

    /// Returns a new `Client` that opens its own connection but reuses this
    /// client's configuration.
    ///
    /// A fresh transport is established via [`Connector::connect`], which is
    /// fallible and may block on TCP/TLS handshake. The connector, middleware
    /// chain, and supported-version list are shared cheaply via `Arc`;
    /// subsequent builder calls like [`Self::with_middleware`] on the clone
    /// diverge via copy-on-write and do not affect the original.
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
        Ok(Self {
            conn: ttlv::Stream::new(self.connector.connect()?),
            connector: self.connector.clone(),
            supported_versions: self.supported_versions.clone(),
            version: self.version,
            middlewares: self.middlewares.clone(),
        })
    }

    #[must_use]
    pub fn with_middleware(mut self, middleware: impl Middleware<crate::Error> + 'static) -> Self {
        Arc::make_mut(&mut self.middlewares).push(Arc::new(middleware));
        self
    }

    #[must_use]
    pub fn with_version(mut self, version: ProtocolVersion) -> Self {
        self.version = Some(version);
        self
    }

    #[must_use]
    pub fn with_supported_versions(mut self, versions: &[ProtocolVersion]) -> Self {
        self.supported_versions.clear();
        self.supported_versions.extend_from_slice(versions);
        self.supported_versions.sort_by(|a, b| b.cmp(a));
        self.supported_versions.dedup();
        self
    }

    pub fn version(&mut self) -> crate::Result<ProtocolVersion> {
        if let Some(v) = &self.version {
            return Ok(*v);
        }
        tracing::debug!("Negotiating protocol version with server...");
        let resp = self.roundtrip(RequestMessage::new(
            ProtocolVersion::V1_1,
            DiscoverVersionsRequestPayload {
                protocol_version: if self.supported_versions.is_empty() {
                    tracing::trace!(
                        "Client supported version list is empty, using default: {:?}",
                        DEFAULT_SUPPORTED_VERSIONS
                    );
                    DEFAULT_SUPPORTED_VERSIONS.to_vec()
                } else {
                    tracing::trace!("Client supported versions: {:?}", self.supported_versions);
                    self.supported_versions.clone()
                },
            },
        ))?;

        let pl: DiscoverVersionsResponsePayload = match resp
            .batch_item
            .into_iter()
            .next()
            .ok_or(Error::MissingBatchItem)?
            .success()
        {
            Ok(pl) => pl.ok_or(Error::MissingResponsePayload)?.try_into()?,
            Err(ProtocolError {
                reason: Some(ResultReason::OperationNotSupported),
                ..
            }) => {
                // TODO: Check that default version is in the supported version list before using it
                tracing::debug!(
                    "DiscoverVersions operation not supported, falling back to default protocol version"
                );
                let version = ProtocolVersion::default();
                self.version = Some(version);
                return Ok(version);
            }
            Err(other) => return Err(other.into()),
        };
        tracing::trace!("Server supported versions: {:?}", pl.protocol_version);
        let version = pl.protocol_version.into_iter().next().unwrap_or_default();
        self.version = Some(version);
        tracing::debug!("Negotiated protocol version: {}", version);
        Ok(version)
    }

    fn roundtrip_ttlv<D: Decodable>(&mut self, msg: &impl Encodable) -> Result<D> {
        //TODO: Better reconnection loop. Do we really need a retry counter here ?
        let mut retry = 3;
        loop {
            match self.conn.roundtrip(msg) {
                Err(ttlv::Error::Io(e)) if retry > 0 && e.kind() == ErrorKind::UnexpectedEof => {
                    tracing::warn!("I/O error during request/response roundtrip: {e:?}");
                    tracing::warn!(
                        "Attempting to reconnect and retry the request ({retry} retries left)",
                    );
                    //FIXME: If connect fails, there's no retry as the error is returned immediately.
                    self.conn = ttlv::Stream::new(self.connector.connect()?);
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
        self.middlewares.get(idx).cloned()
    }

    fn final_handler(&mut self, req: RequestMessage) -> Result<ResponseMessage> {
        self.roundtrip_ttlv(&req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[cfg(feature = "default-tls-rustls")]
    #[test]
    fn test_client_builder_defaults() {
        let builder = ClientBuilder::default();
        assert_eq!(builder.connect_timeout, None);
        assert_eq!(builder.read_timeout, Some(Duration::from_secs(30)));
        assert_eq!(builder.write_timeout, Some(Duration::from_secs(30)));
        assert!(builder.tcp_nodelay);
    }

    #[cfg(feature = "default-tls-rustls")]
    #[test]
    fn test_client_builder_connect_timeout() {
        let builder = ClientBuilder::default().connect_timeout(Some(Duration::from_secs(3)));
        assert_eq!(builder.connect_timeout, Some(Duration::from_secs(3)));
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
        let builder = ClientBuilder::default()
            .read_timeout(Some(Duration::from_secs(10)))
            .write_timeout(Some(Duration::from_secs(60)))
            .tcp_nodelay(false);

        assert_eq!(builder.read_timeout, Some(Duration::from_secs(10)));
        assert_eq!(builder.write_timeout, Some(Duration::from_secs(60)));
        assert!(!builder.tcp_nodelay);
    }

    #[cfg(feature = "default-tls-rustls")]
    #[test]
    fn test_client_builder_disable_timeouts() {
        let builder = ClientBuilder::default()
            .read_timeout(None)
            .write_timeout(None);

        assert_eq!(builder.read_timeout, None);
        assert_eq!(builder.write_timeout, None);
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

    /// Connects via a re-resolvable `"host:port"` string, mirroring how the
    /// real TLS connectors dial the server on every `connect()`.
    struct LocalConnector(String);
    impl Connector for LocalConnector {
        fn connect(&self) -> Result<Box<dyn Transport>> {
            Ok(Box::new(TcpStream::connect(self.0.as_str())?))
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
    fn try_clone_middleware_diverges_via_cow() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let original = Client::new(Arc::new(LocalConnector(addr.to_string())))
            .unwrap()
            .with_middleware(NoopMiddleware);

        let clone = original
            .try_clone()
            .unwrap()
            .with_middleware(NoopMiddleware);

        assert_eq!(original.middlewares.len(), 1);
        assert_eq!(clone.middlewares.len(), 2);
    }

    #[test]
    fn try_clone_shares_middleware_when_unchanged() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let original = Client::new(Arc::new(LocalConnector(addr.to_string())))
            .unwrap()
            .with_middleware(NoopMiddleware);
        let clone = original.try_clone().unwrap();

        assert!(Arc::ptr_eq(&original.middlewares, &clone.middlewares));
    }

    #[test]
    fn try_clone_reconnects_via_hostname() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // A "host:port" string is re-resolved on every connect(), so both the
        // initial connection and the reconnect performed by try_clone resolve
        // the hostname afresh and succeed.
        let original = Client::new(Arc::new(LocalConnector(format!("localhost:{port}")))).unwrap();
        let _clone = original.try_clone().unwrap();
    }
}
