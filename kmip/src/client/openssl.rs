use std::{
    io,
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

use openssl::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode},
    x509::X509,
};

use crate::{
    Error, Result,
    client::{TlsBackend, boxed_connector},
};

use super::{ClientBuilder, Connector, configure_stream};

pub type OpenSsl = SslStream<TcpStream>;

pub struct OpenSslBackend;

impl TlsBackend for OpenSslBackend {
    fn create_connector(
        &self,
        builder: &ClientBuilder,
        addr: Vec<SocketAddr>,
        domain: &str,
    ) -> Result<Arc<dyn Connector<Transport = Box<dyn super::Transport>>>> {
        let mut bld = SslConnector::builder(SslMethod::tls_client())?;

        for root in &builder.root_certs {
            let certs = X509::stack_from_pem(root)?;
            for cert in certs {
                bld.cert_store_mut().add_cert(cert)?;
            }
        }

        if let Some((cert, key)) = &builder.identity {
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

        Ok(boxed_connector(OpenSslConnector::new(
            bld.build(),
            addr,
            domain,
            builder.read_timeout,
            builder.write_timeout,
            builder.tcp_nodelay,
        )?))
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
        addr: Vec<SocketAddr>,
        domain: impl Into<String>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        tcp_nodelay: bool,
    ) -> io::Result<Self> {
        Ok(Self {
            inner: cfg,
            domain: domain.into(),
            addr,
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
