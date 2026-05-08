use std::{
    io,
    net::SocketAddr,
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use boring::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode},
    x509::X509,
};

use crate::{Error, Result};

use super::{Client, ClientBuilder, Connector, configure_stream};

pub type BoringSsl = SslStream<TcpStream>;

impl ClientBuilder {
    pub fn connect_boring(&self, addr: impl ToSocketAddrs, domain: &str) -> Result<Client> {
        let mut bld = SslConnector::builder(SslMethod::tls())?;

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
        Client::new(BoringSslConnector::new(
            bld.build(),
            addr,
            domain,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?)
    }
}

pub struct BoringSslConnector {
    inner: SslConnector,
    domain: String,
    addr: Vec<SocketAddr>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
}

impl BoringSslConnector {
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

impl Connector for BoringSslConnector {
    type Transport = BoringSsl;

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
