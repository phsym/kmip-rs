use core::str;
use std::{sync::Arc, time::Duration};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{
        InvalidDnsNameError, PrivateKeyDer,
        pem::{self, PemObject},
    },
};
use rustls_platform_verifier::BuilderVerifierExt;

use crate::{Error, Result};

use super::{ClientBuilder, Connector, TlsBackend, Transport, dial};

pub struct RustlsConnector {
    cfg: Arc<ClientConfig>,
    domain: String,
    addr: String,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
}

impl RustlsConnector {
    pub fn new(
        cfg: ClientConfig,
        addr: impl Into<String>,
        domain: impl Into<String>,
        connect_timeout: Option<Duration>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        tcp_nodelay: bool,
    ) -> Self {
        Self::from_shared(
            Arc::new(cfg),
            addr,
            domain,
            connect_timeout,
            read_timeout,
            write_timeout,
            tcp_nodelay,
        )
    }

    /// Builds a connector reusing an already-shared [`ClientConfig`], so a
    /// cluster pool can share one parsed config instead of one per endpoint.
    fn from_shared(
        cfg: Arc<ClientConfig>,
        addr: impl Into<String>,
        domain: impl Into<String>,
        connect_timeout: Option<Duration>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        tcp_nodelay: bool,
    ) -> Self {
        Self {
            cfg,
            domain: domain.into(),
            addr: addr.into(),
            connect_timeout,
            read_timeout,
            write_timeout,
            tcp_nodelay,
        }
    }
}

impl Connector for RustlsConnector {
    fn connect(&self) -> Result<Box<dyn Transport>> {
        let mut conn = ClientConnection::new(
            self.cfg.clone(),
            self.domain
                .clone()
                .try_into()
                .map_err(|e: InvalidDnsNameError| Error::TLS(e.into()))?,
        )?;
        let mut sock = dial(
            self.addr.as_str(),
            self.connect_timeout,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?;
        // Drive the TLS handshake to completion right now
        conn.complete_io(&mut sock)?;
        let stream = StreamOwned::new(conn, sock);
        Ok(Box::new(stream))
    }
}

pub struct RustlsBackend;

impl RustlsBackend {
    /// Builds the shared rustls [`ClientConfig`] (parsed CA roots + client
    /// identity) once, so it can be reused across a cluster's endpoints.
    fn build_config(builder: &ClientBuilder) -> Result<Arc<ClientConfig>> {
        let cfg = if !builder.root_certs.is_empty() {
            let mut root_store = RootCertStore::empty();
            for root in &builder.root_certs {
                let ca = pem::SliceIter::new(root).collect::<std::result::Result<Vec<_>, _>>()?;
                let (added, _ignored) = root_store.add_parsable_certificates(ca);
                if added == 0 {
                    return Err(Error::TLS("No valid root certificates found".into()));
                }
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
        Ok(Arc::new(cfg))
    }
}

impl TlsBackend for RustlsBackend {
    fn create_connector(
        &self,
        builder: &ClientBuilder,
        addr: String,
        domain: &str,
    ) -> Result<Arc<dyn Connector>> {
        let cfg = Self::build_config(builder)?;
        Ok(Arc::new(RustlsConnector::from_shared(
            cfg,
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
        // Parse the CA bundle + identity once and share the resulting config
        // across every endpoint's connector.
        let cfg = Self::build_config(builder)?;
        Ok(endpoints
            .iter()
            .map(|(addr, domain)| {
                Arc::new(RustlsConnector::from_shared(
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
