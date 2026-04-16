use core::str;
use std::{
    io,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    sync::Arc,
};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{
        InvalidDnsNameError, PrivateKeyDer,
        pem::{self, PemObject},
    },
};
use rustls_platform_verifier::BuilderVerifierExt;

use crate::{Error, Result};

use super::{Client, ClientBuilder, Connector};

pub type Rustls = StreamOwned<ClientConnection, TcpStream>;

pub struct RustlsConnector {
    cfg: Arc<ClientConfig>,
    domain: String,
    addr: Vec<SocketAddr>,
}

impl RustlsConnector {
    pub fn new(
        cfg: ClientConfig,
        addr: impl ToSocketAddrs,
        domain: impl Into<String>,
    ) -> io::Result<Self> {
        Ok(Self {
            cfg: Arc::new(cfg),
            domain: domain.into(),
            addr: addr.to_socket_addrs()?.collect(),
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
        // Drive the TLS handshake to completion right now
        conn.complete_io(&mut sock)?;
        let stream = StreamOwned::new(conn, sock);
        Ok(stream)
    }
}

impl ClientBuilder {
    pub fn connect_rustls(&self, addr: impl ToSocketAddrs, domain: &str) -> Result<Client> {
        let cfg = if !self.root_certs.is_empty() {
            let mut root_store = RootCertStore::empty();
            for root in &self.root_certs {
                let ca = pem::SliceIter::new(root).collect::<std::result::Result<Vec<_>, _>>()?;
                root_store.add_parsable_certificates(ca);
            }
            ClientConfig::builder().with_root_certificates(root_store)
        } else {
            // If no root CA has been provided, fallback to platform verifier
            //TODO: The platform-verifier dependency should be hidden behind a feature flag. Or at least the client builder should be hidden behind
            ClientConfig::builder().with_platform_verifier()?
        };

        let cfg = if let Some((cert, key)) = &self.identity {
            let cert_chain =
                pem::SliceIter::new(cert).collect::<std::result::Result<Vec<_>, _>>()?;
            let key_der = PrivateKeyDer::from_pem_slice(key)?;
            cfg.with_client_auth_cert(cert_chain, key_der)?
        } else {
            cfg.with_no_client_auth()
        };
        Client::new(RustlsConnector::new(cfg, addr, domain)?)
    }
}
