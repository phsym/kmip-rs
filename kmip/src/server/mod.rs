use std::{
    convert::Infallible,
    fs,
    io::{self, Read, Write},
    marker::PhantomData,
    net::{TcpListener, TcpStream},
    path::Path,
    sync::Arc,
    time::Duration,
};

use crate::{
    ProtocolVersion, RequestMessage, ResponseBatchItem, ResponseHeader, ResponseMessage,
    ResultReason, ResultStatus,
    middlewares::{Chain, Middleware, Next},
};

mod router;
use chrono::Local;
pub use router::*;

#[cfg(feature = "tls-rustls")]
mod rustls;
#[cfg(feature = "tls-rustls")]
pub use rustls::*;

#[cfg(feature = "tls-openssl")]
mod openssl;
#[cfg(feature = "tls-openssl")]
pub use openssl::*;

#[cfg(feature = "tls-boring")]
mod boring;
#[cfg(feature = "tls-boring")]
pub use boring::*;

use tracing::{debug, error_span, field, trace, warn};

pub trait RequestHandler: Send + Sync {
    fn handle(&self, req: RequestMessage) -> ResponseMessage;
}

pub trait Transport: Read + Write + Send {
    fn remote_address(&self) -> std::io::Result<std::net::SocketAddr>;
}

pub trait Acceptor: Send + Sync {
    type Transport: Transport;
    fn accept(&self) -> crate::Result<Self::Transport>;
}

impl Acceptor for TcpListener {
    type Transport = TcpStream;

    fn accept(&self) -> crate::Result<Self::Transport> {
        let (conn, _) = TcpListener::accept(self)?;
        Ok(conn)
    }
}

impl Transport for TcpStream {
    fn remote_address(&self) -> std::io::Result<std::net::SocketAddr> {
        self.peer_addr()
    }
}

pub struct WantServerCert;
pub struct Ready;

const DEFAULT_SOCKET_TIMEOUT: Option<Duration> = Some(Duration::from_secs(30));

#[must_use = "builder must be used to create an Acceptor"]
pub struct AcceptorBuilder<T> {
    root_certs: Vec<Vec<u8>>,
    identity: Option<(Vec<u8>, Vec<u8>)>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
    _st: PhantomData<T>,
}

impl AcceptorBuilder<WantServerCert> {
    pub fn identity_file(
        self,
        cert: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> io::Result<AcceptorBuilder<Ready>> {
        Ok(self.identity(fs::read(cert)?, fs::read(key)?))
    }

    pub fn identity(mut self, cert_pem: Vec<u8>, key_pem: Vec<u8>) -> AcceptorBuilder<Ready> {
        self.identity = Some((cert_pem, key_pem));
        AcceptorBuilder {
            root_certs: self.root_certs,
            identity: self.identity,
            read_timeout: self.read_timeout,
            write_timeout: self.write_timeout,
            tcp_nodelay: self.tcp_nodelay,
            _st: PhantomData,
        }
    }
}

impl Default for AcceptorBuilder<WantServerCert> {
    fn default() -> Self {
        Self::new()
    }
}

impl AcceptorBuilder<WantServerCert> {
    pub fn new() -> Self {
        Self {
            identity: None,
            root_certs: Vec::new(),
            read_timeout: DEFAULT_SOCKET_TIMEOUT,
            write_timeout: DEFAULT_SOCKET_TIMEOUT,
            tcp_nodelay: true,
            _st: PhantomData,
        }
    }
}

impl<T> AcceptorBuilder<T> {
    pub fn add_root_certificate_file(self, path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(self.add_root_certificate(fs::read(path)?))
    }

    pub fn add_root_certificate(mut self, pem: Vec<u8>) -> Self {
        self.root_certs.push(pem);
        self
    }

    /// Sets the read timeout applied to accepted `TcpStream`s before the TLS
    /// handshake. `None` disables the timeout (reads block indefinitely).
    pub fn read_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Sets the write timeout applied to accepted `TcpStream`s before the TLS
    /// handshake. `None` disables the timeout (writes block indefinitely).
    pub fn write_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.write_timeout = timeout;
        self
    }

    /// Enables or disables `TCP_NODELAY` (Nagle's algorithm) on accepted
    /// sockets. Enabled by default to minimize request/response latency.
    pub fn tcp_nodelay(mut self, nodelay: bool) -> Self {
        self.tcp_nodelay = nodelay;
        self
    }

    // TODO: Add KMIP authentication
    // TODO: Fine tune TLS cipher suites when/if possible
}

#[cfg(any(
    feature = "tls-rustls",
    feature = "tls-openssl",
    feature = "tls-boring"
))]
pub(crate) fn configure_stream(
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

pub struct Server<A: Acceptor, H: RequestHandler> {
    acceptor: A,
    handler: Arc<H>,
    middlewares: Arc<Vec<Arc<dyn Middleware<Infallible>>>>,
}

impl<A: Acceptor + 'static, H: RequestHandler + 'static> Server<A, H> {
    pub fn new(acceptor: A, handler: H) -> std::io::Result<Self> {
        Ok(Self {
            acceptor,
            handler: Arc::new(handler),
            middlewares: Arc::new(Vec::new()),
        })
    }

    #[must_use]
    pub fn with_middleware(mut self, middleware: impl Middleware<Infallible> + 'static) -> Self {
        Arc::make_mut(&mut self.middlewares).push(Arc::new(middleware));
        self
    }

    pub fn run(&self) -> crate::Result<()> {
        debug!("entering server accepting loop");
        loop {
            // Check error and ignore some of them (like TLS errors). IO errors may be quite bad
            let conn = match self.acceptor.accept() {
                Err(e @ crate::Error::TLS(_)) => {
                    //TODO: Add more info to the log, like the field
                    warn!("TLS handshake failed: {e}");
                    continue;
                }
                other => other?,
            };
            let addr = match conn.remote_address() {
                Err(e) => {
                    warn!("failed to get client's address: {e}");
                    continue;
                }
                Ok(addr) => addr,
            };
            debug!(client.ip = %addr, "new connection");
            let hdl = self.handler.clone();
            let middlewares = Arc::clone(&self.middlewares);
            std::thread::Builder::new()
                .name(format!("client[{addr}]"))
                .spawn(move || Self::handle_connection(hdl, middlewares, conn))
                .unwrap();
        }
    }

    fn handle_connection(
        handler: Arc<H>,
        middlewares: Arc<Vec<Arc<dyn Middleware<Infallible>>>>,
        stream: A::Transport,
    ) {
        let span = error_span!("session", client.ip = %stream.remote_address().unwrap());
        let stream = ttlv::Stream::new(stream);
        let mut _sp = span.enter();
        let client = ClientHandler {
            hdl: handler,
            stream,
            middlewares,
        };

        client.run();
    }
}

struct ClientHandler<H: RequestHandler, T: Transport> {
    hdl: Arc<H>,
    stream: ttlv::Stream<T>,
    middlewares: Arc<Vec<Arc<dyn Middleware<Infallible>>>>,
}

impl<H: RequestHandler, T: Transport> Chain for ClientHandler<H, T> {
    type Error = Infallible;
    fn get_middleware(&self, idx: usize) -> Option<Arc<dyn Middleware<Self::Error>>> {
        self.middlewares.get(idx).cloned()
    }

    fn final_handler(
        &mut self,
        req: RequestMessage,
    ) -> std::result::Result<ResponseMessage, Self::Error> {
        Ok(self.hdl.handle(req))
    }
}

impl<H: RequestHandler, T: Transport> ClientHandler<H, T> {
    fn process_next(&mut self) -> ttlv::Result<ResponseMessage> {
        let req = self.stream.receive::<RequestMessage>()?;
        let _span = error_span!("roundtrip", kmip.version = %req.header.protocol_version, req.id=field::Empty)
            .entered();
        if let Some(ccv) = &req.header.client_correlation_value {
            _span.record("req.id", ccv);
        }
        trace!(?req, "recv KMIP request");
        let resp = Next {
            idx: 0,
            chain: self,
        }
        .run(req)?;
        Ok(resp)
    }

    fn run(mut self) {
        loop {
            //TODO: Catch panics
            let resp = match self.process_next() {
                Ok(resp) => resp,
                Err(ttlv::Error::Io(e)) => {
                    warn!("fatal recv error: {e}");
                    return;
                }
                Err(other) => {
                    warn!("recv error: {other}");
                    ResponseMessage {
                        header: ResponseHeader {
                            protocol_version: ProtocolVersion::V1_0,
                            timestamp: Local::now(),
                            batch_count: 1,
                            attestation_type: None,
                            client_correlation_value: None,
                            nonce: None,
                            server_correlation_value: None,
                        },
                        batch_item: vec![ResponseBatchItem {
                            operation: None,
                            result_status: ResultStatus::OperationFailed,
                            result_reason: Some(ResultReason::InvalidMessage),
                            result_message: None,
                            asynchronous_correlation_value: None,
                            unique_batch_item_id: None,
                            message_extension: None,
                            response_payload: None,
                        }],
                    }
                }
            };
            trace!(?resp, "write KMIP response");
            if let Err(e) = self.stream.send(&resp) {
                warn!("failed to write response: {e}");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acceptor_builder_defaults() {
        let builder = AcceptorBuilder::new();
        assert_eq!(builder.read_timeout, Some(Duration::from_secs(30)));
        assert_eq!(builder.write_timeout, Some(Duration::from_secs(30)));
        assert!(builder.tcp_nodelay);
    }

    #[test]
    fn test_acceptor_builder_custom_timeouts() {
        let builder = AcceptorBuilder::new()
            .read_timeout(Some(Duration::from_secs(15)))
            .write_timeout(Some(Duration::from_secs(45)))
            .tcp_nodelay(false);

        assert_eq!(builder.read_timeout, Some(Duration::from_secs(15)));
        assert_eq!(builder.write_timeout, Some(Duration::from_secs(45)));
        assert!(!builder.tcp_nodelay);
    }

    #[test]
    fn test_acceptor_builder_disable_timeouts() {
        let builder = AcceptorBuilder::new()
            .read_timeout(None)
            .write_timeout(None);

        assert_eq!(builder.read_timeout, None);
        assert_eq!(builder.write_timeout, None);
    }

    #[test]
    fn test_acceptor_builder_identity_preserves_socket_opts() {
        let builder = AcceptorBuilder::new()
            .read_timeout(Some(Duration::from_secs(10)))
            .write_timeout(Some(Duration::from_secs(20)))
            .tcp_nodelay(false)
            .identity(b"cert".to_vec(), b"key".to_vec());

        assert_eq!(builder.read_timeout, Some(Duration::from_secs(10)));
        assert_eq!(builder.write_timeout, Some(Duration::from_secs(20)));
        assert!(!builder.tcp_nodelay);
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-openssl"))]
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

    #[cfg(any(feature = "tls-rustls", feature = "tls-openssl"))]
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
}
