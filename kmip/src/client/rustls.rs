use core::str;
use std::{
    io,
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{
        InvalidDnsNameError, PrivateKeyDer,
        pem::{self, PemObject},
    },
};
use rustls_platform_verifier::BuilderVerifierExt;

use crate::{
    Error, Result,
    client::{TlsBackend, boxed_connector},
};

use super::{ClientBuilder, Connector, configure_stream};

pub type Rustls = StreamOwned<ClientConnection, TcpStream>;

pub struct RustlsConnector {
    cfg: Arc<ClientConfig>,
    domain: String,
    addr: Vec<SocketAddr>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
}

impl RustlsConnector {
    pub fn new(
        cfg: ClientConfig,
        addr: Vec<SocketAddr>,
        domain: impl Into<String>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        tcp_nodelay: bool,
    ) -> io::Result<Self> {
        Ok(Self {
            cfg: Arc::new(cfg),
            domain: domain.into(),
            addr,
            read_timeout,
            write_timeout,
            tcp_nodelay,
        })
    }
}

impl Connector for RustlsConnector {
    type Transport = Rustls;

    fn connect(&self) -> Result<Self::Transport> {
        let mut conn = ClientConnection::new(
            self.cfg.clone(),
            self.domain
                .clone()
                .try_into()
                .map_err(|e: InvalidDnsNameError| Error::TLS(e.into()))?,
        )?;
        let mut sock = TcpStream::connect(&self.addr[..])?;
        configure_stream(
            &sock,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?;
        // Drive the TLS handshake to completion right now
        conn.complete_io(&mut sock)?;
        let stream = StreamOwned::new(conn, sock);
        Ok(stream)
    }
}

pub struct RustlsBackend;

impl TlsBackend for RustlsBackend {
    fn create_connector(
        &self,
        builder: &ClientBuilder,
        addr: Vec<SocketAddr>,
        domain: &str,
    ) -> Result<Arc<dyn Connector<Transport = Box<dyn super::Transport>>>> {
        let cfg = if !builder.root_certs.is_empty() {
            let mut root_store = RootCertStore::empty();
            for root in &builder.root_certs {
                let ca = pem::SliceIter::new(root).collect::<std::result::Result<Vec<_>, _>>()?;
                root_store.add_parsable_certificates(ca);
            }
            ClientConfig::builder().with_root_certificates(root_store)
        } else {
            // If no root CA has been provided, fallback to platform verifier
            //TODO: The platform-verifier dependency should be hidden behind a feature flag. Or at least the client builder should be hidden behind
            ClientConfig::builder().with_platform_verifier()?
        };

        let cfg = if let Some((cert, key)) = &builder.identity {
            let cert_chain =
                pem::SliceIter::new(cert).collect::<std::result::Result<Vec<_>, _>>()?;
            let key_der = PrivateKeyDer::from_pem_slice(key)?;
            cfg.with_client_auth_cert(cert_chain, key_der)?
        } else {
            cfg.with_no_client_auth()
        };
        Ok(boxed_connector(RustlsConnector::new(
            cfg,
            addr,
            domain,
            builder.read_timeout,
            builder.write_timeout,
            builder.tcp_nodelay,
        )?))
    }
}
