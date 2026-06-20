use core::str;
use std::{
    io,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
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

use crate::{Error, Result};

use super::{
    Client, ClientBuilder, ClusterConnector, Connector, DEFAULT_RETRY_TIMEOUT, configure_stream,
    endpoint_domain,
};

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
        addr: impl ToSocketAddrs,
        domain: impl Into<String>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        tcp_nodelay: bool,
    ) -> io::Result<Self> {
        Self::with_shared_config(
            Arc::new(cfg),
            addr,
            domain,
            read_timeout,
            write_timeout,
            tcp_nodelay,
        )
    }

    /// Like [`Self::new`], but reuses an already-shared [`ClientConfig`] so a
    /// pool of connectors (e.g. a cluster) can share one TLS configuration.
    pub(crate) fn with_shared_config(
        cfg: Arc<ClientConfig>,
        addr: impl ToSocketAddrs,
        domain: impl Into<String>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        tcp_nodelay: bool,
    ) -> io::Result<Self> {
        Ok(Self {
            cfg,
            domain: domain.into(),
            addr: addr.to_socket_addrs()?.collect(),
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

impl ClientBuilder {
    /// Builds the rustls [`ClientConfig`] from the builder's root certificates
    /// and client identity. Shared by the single- and multi-endpoint connectors.
    fn build_rustls_config(&self) -> Result<ClientConfig> {
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
        Ok(cfg)
    }

    pub fn connect_rustls(&self, addr: impl ToSocketAddrs, domain: &str) -> Result<Client> {
        let cfg = self.build_rustls_config()?;
        Client::new(RustlsConnector::new(
            cfg,
            addr,
            domain,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?)
    }

    /// Connects to a pool of KMIP endpoints over rustls with failover and
    /// optional load balancing (see [`ClusterConnector`] /
    /// [`ClientBuilder::cluster_mode`]).
    ///
    /// Each entry in `addrs` is a `host:port` address; its SNI / certificate
    /// domain is derived from the host part, so endpoints may present different
    /// certificates. All endpoints share one [`ClientConfig`] (root CAs +
    /// client identity from this builder). The per-endpoint cooldown is
    /// [`ClientBuilder::retry_timeout`] (default [`DEFAULT_RETRY_TIMEOUT`]).
    pub fn connect_cluster_rustls(&self, addrs: &[String]) -> Result<Client> {
        let cfg = Arc::new(self.build_rustls_config()?);
        let connectors = addrs
            .iter()
            .map(|addr| {
                RustlsConnector::with_shared_config(
                    cfg.clone(),
                    addr.as_str(),
                    endpoint_domain(addr),
                    self.read_timeout,
                    self.write_timeout,
                    self.tcp_nodelay,
                )
            })
            .collect::<io::Result<Vec<_>>>()?;
        let cluster = ClusterConnector::with_mode(
            connectors,
            self.retry_timeout.unwrap_or(DEFAULT_RETRY_TIMEOUT),
            self.cluster_mode,
        )?;
        Client::new(cluster)
    }
}
