use std::{
    io,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

use native_tls::{Certificate, HandshakeError, Identity, Protocol, TlsConnector, TlsStream};

use crate::Result;

use super::{Client, ClientBuilder, Connector, configure_stream};

pub type NativeTls = TlsStream<TcpStream>;

impl ClientBuilder {
    pub fn connect_native(&self, addr: impl ToSocketAddrs, domain: &str) -> Result<Client> {
        let mut bld = TlsConnector::builder();
        for root in &self.root_certs {
            bld.add_root_certificate(Certificate::from_pem(root)?);
        }
        if let Some((cert, key)) = &self.identity {
            bld.identity(Identity::from_pkcs8(cert, key)?);
        }
        bld.min_protocol_version(Some(Protocol::Tlsv12));

        Client::new(NativeTlsConnector::new(
            bld.build()?,
            addr,
            domain,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?)
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
