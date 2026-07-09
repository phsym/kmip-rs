use std::{sync::Arc, time::Duration};

use boring::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, store::X509StoreBuilder},
};

use crate::{Error, Result};

use super::{ClientBuilder, Connector, TlsBackend, Transport, dial};

pub struct BoringBackend;

impl BoringBackend {
    /// Builds the shared boring [`SslConnector`] once, so it can be reused
    /// across a cluster's endpoints.
    fn build_config(builder: &ClientBuilder) -> Result<SslConnector> {
        let mut bld = SslConnector::builder(SslMethod::tls())?;
        bld.set_min_proto_version(Some(SslVersion::TLS1_2))?;

        if !builder.root_certs.is_empty() {
            // If root CAs have been provided, disable system roots
            bld.set_cert_store(X509StoreBuilder::new()?.build());
        }
        for root in &builder.root_certs {
            let certs = X509::stack_from_pem(root)?;
            if certs.is_empty() {
                return Err(Error::TLS("No valid root certificates found".into()));
            }
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
        Ok(bld.build())
    }
}

impl TlsBackend for BoringBackend {
    fn create_connector(
        &self,
        builder: &ClientBuilder,
        addr: String,
        domain: &str,
    ) -> Result<Arc<dyn Connector>> {
        Ok(Arc::new(BoringSslConnector::new(
            Self::build_config(builder)?,
            addr,
            domain,
            builder.connect_timeout,
            builder.read_timeout,
            builder.write_timeout,
            builder.tcp_nodelay,
        )))
    }

    fn create_connectors(
        &self,
        builder: &ClientBuilder,
        endpoints: &[(String, String)],
    ) -> Result<Vec<Arc<dyn Connector>>> {
        // `SslConnector` is a cheap, ref-counted handle: build it once and clone
        // it into each endpoint's connector.
        let cfg = Self::build_config(builder)?;
        Ok(endpoints
            .iter()
            .map(|(addr, domain)| {
                Arc::new(BoringSslConnector::new(
                    cfg.clone(),
                    addr.clone(),
                    domain.clone(),
                    builder.connect_timeout,
                    builder.read_timeout,
                    builder.write_timeout,
                    builder.tcp_nodelay,
                )) as Arc<dyn Connector>
            })
            .collect())
    }
}

pub struct BoringSslConnector {
    inner: SslConnector,
    domain: String,
    addr: String,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
}

impl BoringSslConnector {
    pub fn new(
        cfg: SslConnector,
        addr: impl Into<String>,
        domain: impl Into<String>,
        connect_timeout: Option<Duration>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        tcp_nodelay: bool,
    ) -> Self {
        Self {
            inner: cfg,
            domain: domain.into(),
            addr: addr.into(),
            connect_timeout,
            read_timeout,
            write_timeout,
            tcp_nodelay,
        }
    }
}

impl Connector for BoringSslConnector {
    fn connect(&self) -> Result<Box<dyn Transport>> {
        let sock = dial(
            self.addr.as_str(),
            self.connect_timeout,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?;
        let mut tls_stream = self.inner.connect(&self.domain, sock)?;
        tls_stream.do_handshake()?;
        Ok(Box::new(tls_stream))
    }
}
