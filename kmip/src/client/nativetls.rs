use std::{
    io,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

use native_tls::{Certificate, HandshakeError, Identity, Protocol, TlsConnector, TlsStream};

use crate::Result;

use super::{
    Client, ClientBuilder, ClusterConnector, Connector, DEFAULT_RETRY_TIMEOUT, configure_stream,
    endpoint_domain,
};

pub type NativeTls = TlsStream<TcpStream>;

impl ClientBuilder {
    /// Builds the native-tls [`TlsConnector`] from the builder's root
    /// certificates and client identity. Shared by the single- and
    /// multi-endpoint connectors.
    fn build_native_config(&self) -> Result<TlsConnector> {
        let mut bld = TlsConnector::builder();
        for root in &self.root_certs {
            bld.add_root_certificate(Certificate::from_pem(root)?);
        }
        if let Some((cert, key)) = &self.identity {
            bld.identity(Identity::from_pkcs8(cert, key)?);
        }
        bld.min_protocol_version(Some(Protocol::Tlsv12));
        Ok(bld.build()?)
    }

    pub fn connect_native(&self, addr: impl ToSocketAddrs, domain: &str) -> Result<Client> {
        Client::new(NativeTlsConnector::new(
            self.build_native_config()?,
            addr,
            domain,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?)
    }

    /// Connects to a pool of KMIP endpoints over native-tls with failover and
    /// optional load balancing (see [`ClusterConnector`] /
    /// [`ClientBuilder::cluster_mode`]).
    ///
    /// Each entry in `addrs` is a `host:port` address; its SNI / certificate
    /// domain is derived from the host part, so endpoints may present different
    /// certificates. All endpoints share one [`TlsConnector`] (root CAs +
    /// client identity from this builder). The per-endpoint cooldown is
    /// [`ClientBuilder::retry_timeout`] (default [`DEFAULT_RETRY_TIMEOUT`]).
    pub fn connect_cluster_native(&self, addrs: &[String]) -> Result<Client> {
        let cfg = self.build_native_config()?;
        let connectors = addrs
            .iter()
            .map(|addr| {
                NativeTlsConnector::new(
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
        addr: impl ToSocketAddrs,
        domain: impl Into<String>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        tcp_nodelay: bool,
    ) -> io::Result<Self> {
        Ok(Self {
            inner: cfg,
            domain: domain.into(),
            addr: addr.to_socket_addrs()?.collect(),
            read_timeout,
            write_timeout,
            tcp_nodelay,
        })
    }
}

impl Connector for NativeTlsConnector {
    type Transport = NativeTls;

    fn connect(&self) -> Result<Self::Transport> {
        let sock = TcpStream::connect(&self.addr[..])?;
        configure_stream(
            &sock,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?;
        let tls_stream = match self.inner.connect(&self.domain, sock) {
            Ok(v) => v,
            Err(HandshakeError::Failure(e)) => Err(e)?,
            Err(HandshakeError::WouldBlock(..)) => unreachable!(),
        };
        Ok(tls_stream)
    }
}
