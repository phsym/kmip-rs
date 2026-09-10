use std::sync::Arc;

use native_tls::{Certificate, Identity, Protocol, TlsConnector};

use crate::Result;

use super::{
    Connector, ConnectorConfig, ConnectorFactory, SocketOptions, Transport, TransportBackend, dial,
};

/// TLS backend delegating to the OS implementation via native-tls.
///
/// Unlike the other backends, the client identity private key passed to
/// [`ClientBuilder::identity`](super::ClientBuilder::identity) must be PKCS#8-encoded
/// (`-----BEGIN PRIVATE KEY-----`); PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`)
/// and SEC1 (`-----BEGIN EC PRIVATE KEY-----`) keys are rejected. Convert with
/// `openssl pkcs8 -topk8 -nocrypt` if needed.
pub struct NativeTlsBackend;

impl NativeTlsBackend {
    fn build_config(config: &ConnectorConfig) -> Result<TlsConnector> {
        let mut bld = TlsConnector::builder();
        if !config.root_certs.is_empty() {
            // If root CAs have been provided, disable system roots
            bld.disable_built_in_roots(true);
        }
        for root in &config.root_certs {
            let certs = Certificate::stack_from_pem(root)?;
            if certs.is_empty() {
                return Err(crate::Error::TLS("No valid root certificates found".into()));
            }
            for cert in certs {
                bld.add_root_certificate(cert);
            }
        }
        if let Some((cert, key)) = &config.identity {
            bld.identity(Identity::from_pkcs8(cert, key)?);
        }
        bld.min_protocol_version(Some(Protocol::Tlsv12));
        Ok(bld.build()?)
    }
}

/// The prepared native-tls state, shared by every connector this backend hands
/// out. `TlsConnector` is a cheap ref-counted handle, so connectors clone it.
struct NativeTlsFactory {
    cfg: TlsConnector,
    opts: SocketOptions,
}

impl ConnectorFactory for NativeTlsFactory {
    fn connector(&self, addr: String, domain: &str) -> Arc<dyn Connector> {
        Arc::new(NativeTlsConnector::new(
            self.cfg.clone(),
            addr,
            domain,
            self.opts,
        ))
    }
}

impl TransportBackend for NativeTlsBackend {
    fn prepare(&self, config: &ConnectorConfig) -> Result<Box<dyn ConnectorFactory>> {
        Ok(Box::new(NativeTlsFactory {
            cfg: Self::build_config(config)?,
            opts: SocketOptions::from(config),
        }))
    }
}

pub struct NativeTlsConnector {
    inner: TlsConnector,
    domain: String,
    addr: String,
    opts: SocketOptions,
}

impl NativeTlsConnector {
    pub fn new(
        cfg: TlsConnector,
        addr: impl Into<String>,
        domain: impl Into<String>,
        opts: SocketOptions,
    ) -> Self {
        Self {
            inner: cfg,
            domain: domain.into(),
            addr: addr.into(),
            opts,
        }
    }
}

impl Connector for NativeTlsConnector {
    fn connect(&self) -> Result<Box<dyn Transport>> {
        let sock = dial(self.addr.as_str(), &self.opts)?;
        let tls_stream = self.inner.connect(&self.domain, sock)?;
        Ok(Box::new(tls_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectorConfig, NativeTlsBackend, TransportBackend};

    const VALID: &str = include_str!("../../tests/pykmip/root_certificate.pem");
    // A CERTIFICATE block whose base64 decodes cleanly but is not valid DER.
    const CORRUPT: &str = "-----BEGIN CERTIFICATE-----\nTm90QUNlcnQ=\n-----END CERTIFICATE-----\n";

    // A bundle containing a malformed CERTIFICATE entry must be rejected
    // outright, consistently with the other backends.
    #[test]
    fn rejects_bundle_with_malformed_certificate() {
        let good = ConnectorConfig::with_root(VALID.as_bytes().to_vec());
        assert!(
            NativeTlsBackend
                .create_connector(&good, "kmip.invalid:5696".to_string(), "kmip.invalid")
                .is_ok(),
            "a valid CA certificate should be accepted",
        );

        let mixed = ConnectorConfig::with_root(format!("{VALID}\n{CORRUPT}").into_bytes());
        assert!(
            NativeTlsBackend
                .create_connector(&mixed, "kmip.invalid:5696".to_string(), "kmip.invalid")
                .is_err(),
            "a bundle containing a malformed certificate must be rejected",
        );
    }
}
