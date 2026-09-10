use std::sync::Arc;

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
    Connector, ConnectorConfig, ConnectorFactory, SocketOptions, Transport, TransportBackend, dial,
};

pub struct RustlsConnector {
    cfg: Arc<ClientConfig>,
    domain: String,
    addr: String,
    opts: SocketOptions,
}

impl RustlsConnector {
    /// Builds a connector over an already-shared [`ClientConfig`], so a cluster
    /// shares one parsed config across its endpoints instead of one per endpoint.
    pub fn new(
        cfg: Arc<ClientConfig>,
        addr: impl Into<String>,
        domain: impl Into<String>,
        opts: SocketOptions,
    ) -> Self {
        Self {
            cfg,
            domain: domain.into(),
            addr: addr.into(),
            opts,
        }
    }
}

impl Connector for RustlsConnector {
    fn connect(&self) -> Result<Box<dyn Transport>> {
        // Dial first: building the `ClientConnection` generates a ClientHello
        // and an ephemeral keypair, which a failed dial would throw away. That
        // is the common case in a cluster failover sweep.
        let mut sock = dial(self.addr.as_str(), &self.opts)?;
        let mut conn = ClientConnection::new(
            self.cfg.clone(),
            self.domain
                .clone()
                .try_into()
                .map_err(|e: InvalidDnsNameError| Error::TLS(e.into()))?,
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
    fn build_config(config: &ConnectorConfig) -> Result<Arc<ClientConfig>> {
        let cfg = if !config.root_certs.is_empty() {
            let mut root_store = RootCertStore::empty();
            for root in &config.root_certs {
                let ca = pem::SliceIter::new(root).collect::<std::result::Result<Vec<_>, _>>()?;
                let mut n = 0;
                for cert in ca {
                    root_store.add(cert)?;
                    n += 1;
                }
                if n == 0 {
                    return Err(Error::TLS("No valid root certificates found".into()));
                }
            }
            ClientConfig::builder().with_root_certificates(root_store)
        } else {
            // If no root CA has been provided, fallback to platform verifier
            //TODO: The platform-verifier dependency should be hidden behind a feature flag. Or at least the client builder should be hidden behind
            ClientConfig::builder().with_platform_verifier()?
        };

        let cfg = if let Some((cert, key)) = &config.identity {
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

/// The parsed CA roots + client identity, shared by every connector this
/// backend hands out.
struct RustlsFactory {
    cfg: Arc<ClientConfig>,
    opts: SocketOptions,
}

impl ConnectorFactory for RustlsFactory {
    fn connector(&self, addr: String, domain: &str) -> Arc<dyn Connector> {
        Arc::new(RustlsConnector::new(
            self.cfg.clone(),
            addr,
            domain,
            self.opts,
        ))
    }
}

impl TransportBackend for RustlsBackend {
    fn prepare(&self, config: &ConnectorConfig) -> Result<Box<dyn ConnectorFactory>> {
        Ok(Box::new(RustlsFactory {
            cfg: Self::build_config(config)?,
            opts: SocketOptions::from(config),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectorConfig, RustlsBackend, TransportBackend};

    const VALID: &str = include_str!("../../tests/pykmip/root_certificate.pem");
    // A CERTIFICATE block whose base64 decodes cleanly but is not valid DER.
    const CORRUPT: &str = "-----BEGIN CERTIFICATE-----\nTm90QUNlcnQ=\n-----END CERTIFICATE-----\n";

    // A bundle containing a malformed CERTIFICATE entry must be rejected
    // outright, consistently with the other backends — never silently dropped
    // (regression for the previous add_parsable_certificates leniency).
    #[test]
    fn rejects_bundle_with_malformed_certificate() {
        let good = ConnectorConfig::with_root(VALID.as_bytes().to_vec());
        assert!(
            RustlsBackend
                .create_connector(&good, "kmip.invalid:5696".to_string(), "kmip.invalid")
                .is_ok(),
            "a valid CA certificate should be accepted",
        );

        let mixed = ConnectorConfig::with_root(format!("{VALID}\n{CORRUPT}").into_bytes());
        assert!(
            RustlsBackend
                .create_connector(&mixed, "kmip.invalid:5696".to_string(), "kmip.invalid")
                .is_err(),
            "a bundle containing a malformed certificate must be rejected",
        );
    }
}
