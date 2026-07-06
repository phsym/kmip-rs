use std::{
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

use boring::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::X509,
};

use crate::{Error, Result};

use super::{ClientBuilder, Connector, TlsBackend, Transport, configure_stream};

pub struct BoringBackend;

impl TlsBackend for BoringBackend {
    fn create_connector(
        &self,
        builder: &ClientBuilder,
        addr: Vec<SocketAddr>,
        domain: &str,
    ) -> Result<Arc<dyn Connector>> {
        let mut bld = SslConnector::builder(SslMethod::tls())?;
        bld.set_min_proto_version(Some(SslVersion::TLS1_2))?;

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
        Ok(Arc::new(BoringSslConnector::new(
            bld.build(),
            addr,
            domain,
            builder.read_timeout,
            builder.write_timeout,
            builder.tcp_nodelay,
        )))
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

impl Connector for BoringSslConnector {
    fn connect(&self) -> Result<Box<dyn Transport>> {
        let sock = TcpStream::connect(&self.addr[..])?;
        configure_stream(
            &sock,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?;
        let mut tls_stream = self.inner.connect(&self.domain, sock)?;
        tls_stream.do_handshake()?;
        Ok(Box::new(tls_stream))
    }
}
