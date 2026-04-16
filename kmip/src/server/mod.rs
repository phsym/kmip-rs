use std::{
    fs,
    io::{self, Read, Write},
    marker::PhantomData,
    net::{TcpListener, TcpStream},
    path::Path,
    sync::Arc,
};

use crate::{
    ProtocolVersion, RequestMessage, ResponseBatchItem, ResponseHeader, ResponseMessage,
    ResultReason, ResultStatus,
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

use tracing::{debug, error_span, field, trace, warn};

pub trait RequestHandler: Send + Sync {
    fn handle(&self, req: RequestMessage) -> ResponseMessage;
}

pub trait Transport: Read + Write + Send {
    fn remote_address(&self) -> std::io::Result<std::net::SocketAddr>;
}
// impl<T> Transport for T where T: Read + Write + Send {}

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

pub struct AcceptorBuilder<T> {
    root_certs: Vec<Vec<u8>>,
    identity: Option<(Vec<u8>, Vec<u8>)>,
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

    // TODO: Add KMIP authentication
    // TODO: Fine tune TLS cipher suites when/if possible
}

pub struct Server<A: Acceptor, H: RequestHandler> {
    acceptor: A,
    handler: Arc<H>,
}

impl<A: Acceptor + 'static, H: RequestHandler + 'static> Server<A, H> {
    pub fn new(acceptor: A, handler: H) -> std::io::Result<Self> {
        Ok(Self {
            acceptor,
            handler: Arc::new(handler),
        })
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
            std::thread::Builder::new()
                .name(format!("client[{addr}]"))
                .spawn(move || Self::handle_connection(hdl, conn))
                .unwrap();
        }
    }

    fn handle_connection(handler: Arc<H>, stream: A::Transport) {
        let span = error_span!("session", client.ip = %stream.remote_address().unwrap());
        let mut stream = ttlv::Stream::new(stream);
        let mut _sp = span.enter();
        loop {
            let _span;
            //TODO: Catch panics
            let resp = match stream.receive::<RequestMessage>() {
                Ok(req) => {
                    _span = error_span!("roundtrip", kmip.version = %req.header.protocol_version, req.id=field::Empty)
                        .entered();
                    if let Some(ccv) = &req.header.client_correlation_value {
                        _span.record("req.id", ccv);
                    }
                    trace!(?req, "recv KMIP request");
                    handler.handle(req)
                }
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
            if let Err(e) = stream.send(&resp) {
                warn!("failed to write response: {e}");
                return;
            }
        }
    }
}
