use std::{
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

use native_tls::{Certificate, Identity, Protocol, TlsConnector};

use crate::Result;

use super::{ClientBuilder, Connector, TlsBackend, Transport, configure_stream};

/// TLS backend delegating to the OS implementation via native-tls.
///
/// Unlike the other backends, the client identity private key passed to
/// [`ClientBuilder::identity`] must be PKCS#8-encoded
/// (`-----BEGIN PRIVATE KEY-----`); PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`)
/// and SEC1 (`-----BEGIN EC PRIVATE KEY-----`) keys are rejected. Convert with
/// `openssl pkcs8 -topk8 -nocrypt` if needed.
pub struct NativeTlsBackend;

impl TlsBackend for NativeTlsBackend {
    fn create_connector(
        &self,
        builder: &ClientBuilder,
        addr: Vec<SocketAddr>,
        domain: &str,
    ) -> Result<Arc<dyn Connector>> {
        let mut bld = TlsConnector::builder();
        if !builder.root_certs.is_empty() {
            // If root CAs have been provided, disable system roots
            bld.disable_built_in_roots(true);
        }
        for root in &builder.root_certs {
            let certs = Certificate::stack_from_pem(root)?;
            if certs.is_empty() {
                return Err(crate::Error::TLS("No valid root certificates found".into()));
            }
            for cert in certs {
                bld.add_root_certificate(cert);
            }
        }
        if let Some((cert, key)) = &builder.identity {
            bld.identity(Identity::from_pkcs8(cert, key)?);
        }
        bld.min_protocol_version(Some(Protocol::Tlsv12));

        Ok(Arc::new(NativeTlsConnector::new(
            bld.build()?,
            addr,
            domain,
            builder.read_timeout,
            builder.write_timeout,
            builder.tcp_nodelay,
        )))
    }
}

pub struct NativeTlsConnector {
    inner: TlsConnector,
    domain: String,
    addr: Vec<SocketAddr>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
}

impl NativeTlsConnector {
    pub fn new(
        cfg: TlsConnector,
        addr: Vec<SocketAddr>,
        domain: impl Into<String>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        tcp_nodelay: bool,
    ) -> Self {
        Self {
            inner: cfg,
            domain: domain.into(),
            addr,
            read_timeout,
            write_timeout,
            tcp_nodelay,
        }
    }
}

impl Connector for NativeTlsConnector {
    fn connect(&self) -> Result<Box<dyn Transport>> {
        let sock = TcpStream::connect(&self.addr[..])?;
        configure_stream(
            &sock,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?;
        let tls_stream = self.inner.connect(&self.domain, sock)?;
        Ok(Box::new(tls_stream))
    }
}
