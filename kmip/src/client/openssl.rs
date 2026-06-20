use std::{
    io,
    net::SocketAddr,
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use openssl::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode},
    x509::X509,
};

use crate::{Error, Result};

use super::{
    Client, ClientBuilder, ClusterConnector, Connector, DEFAULT_RETRY_TIMEOUT, configure_stream,
    endpoint_domain,
};

pub type OpenSsl = SslStream<TcpStream>;

impl ClientBuilder {
    /// Builds the openssl [`SslConnector`] from the builder's root certificates
    /// and client identity. Shared by the single- and multi-endpoint connectors.
    fn build_openssl_config(&self) -> Result<SslConnector> {
        let mut bld = SslConnector::builder(SslMethod::tls_client())?;

        for root in &self.root_certs {
            let certs = X509::stack_from_pem(root)?;
            for cert in certs {
                bld.cert_store_mut().add_cert(cert)?;
            }
        }

        if let Some((cert, key)) = &self.identity {
            let mut certs = X509::stack_from_pem(cert)?.into_iter();
            bld.set_certificate(
                certs
                    .next()
                    .ok_or(Error::TLS("Bad client certificate".into()))?
                    .as_ref(),
            )?;
            for cert in certs {
                bld.add_extra_chain_cert(cert)?
            }
            bld.set_private_key(PKey::private_key_from_pem(key)?.as_ref())?;
        }
        bld.set_verify(SslVerifyMode::PEER);
        Ok(bld.build())
    }

    pub fn connect_openssl(&self, addr: impl ToSocketAddrs, domain: &str) -> Result<Client> {
        Client::new(OpenSslConnector::new(
            self.build_openssl_config()?,
            addr,
            domain,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?)
    }

    /// Connects to a pool of KMIP endpoints over openssl with failover and
    /// optional load balancing (see [`ClusterConnector`] /
    /// [`ClientBuilder::cluster_mode`]).
    ///
    /// Each entry in `addrs` is a `host:port` address; its SNI / certificate
    /// domain is derived from the host part, so endpoints may present different
    /// certificates. All endpoints share one [`SslConnector`] (root CAs +
    /// client identity from this builder). The per-endpoint cooldown is
    /// [`ClientBuilder::retry_timeout`] (default [`DEFAULT_RETRY_TIMEOUT`]).
    pub fn connect_cluster_openssl(&self, addrs: &[String]) -> Result<Client> {
        let cfg = self.build_openssl_config()?;
        let connectors = addrs
            .iter()
            .map(|addr| {
                OpenSslConnector::new(
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

pub struct OpenSslConnector {
    inner: SslConnector,
    domain: String,
    addr: Vec<SocketAddr>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
}

impl OpenSslConnector {
    pub fn new(
        cfg: SslConnector,
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

impl Connector for OpenSslConnector {
    type Transport = OpenSsl;

    fn connect(&self) -> Result<Self::Transport> {
        let sock = TcpStream::connect(&self.addr[..])?;
        configure_stream(
            &sock,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?;
        let mut tls_stream = self.inner.connect(&self.domain, sock)?;
        tls_stream.do_handshake()?;
        Ok(tls_stream)
    }
}
