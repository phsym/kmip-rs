use std::sync::Arc;

use openssl::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, store::X509StoreBuilder},
};

use crate::{Error, Result};

use super::{
    Connector, ConnectorConfig, ConnectorFactory, SocketOptions, Transport, TransportBackend, dial,
};

pub struct OpenSslBackend;

impl OpenSslBackend {
    /// Builds the shared openssl [`SslConnector`] once, so it can be reused
    /// across a cluster's endpoints.
    fn build_config(config: &ConnectorConfig) -> Result<SslConnector> {
        let mut bld = SslConnector::builder(SslMethod::tls_client())?;
        bld.set_min_proto_version(Some(SslVersion::TLS1_2))?;

        if !config.root_certs.is_empty() {
            // User-supplied CAs replace the system roots. Build the store fully
            // before installing it — mirroring the boring backend and avoiding a
            // post-install `cert_store_mut()` mutation. (openssl has no
            // `set_cert_store_builder`, so install the built store directly.)
            let mut store = X509StoreBuilder::new()?;
            for root in &config.root_certs {
                let certs = X509::stack_from_pem(root)?;
                if certs.is_empty() {
                    return Err(Error::TLS("No valid root certificates found".into()));
                }
                for cert in certs {
                    store.add_cert(cert)?;
                }
            }
            bld.set_cert_store(store.build());
        }

        if let Some((cert, key)) = &config.identity {
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

/// The prepared openssl state, shared by every connector this backend hands
/// out. `SslConnector` is a cheap, ref-counted handle, so each connector clones it
/// rather than rebuilding it.
struct OpenSslFactory {
    cfg: SslConnector,
    opts: SocketOptions,
}

impl ConnectorFactory for OpenSslFactory {
    fn connector(&self, addr: String, domain: &str) -> Arc<dyn Connector> {
        Arc::new(OpenSslConnector::new(
            self.cfg.clone(),
            addr,
            domain,
            self.opts,
        ))
    }
}

impl TransportBackend for OpenSslBackend {
    fn prepare(&self, config: &ConnectorConfig) -> Result<Box<dyn ConnectorFactory>> {
        Ok(Box::new(OpenSslFactory {
            cfg: Self::build_config(config)?,
            opts: SocketOptions::from(config),
        }))
    }
}

pub struct OpenSslConnector {
    inner: SslConnector,
    domain: String,
    addr: String,
    opts: SocketOptions,
}

impl OpenSslConnector {
    pub fn new(
        cfg: SslConnector,
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

impl Connector for OpenSslConnector {
    fn connect(&self) -> Result<Box<dyn Transport>> {
        let sock = dial(self.addr.as_str(), &self.opts)?;
        let mut tls_stream = self.inner.connect(&self.domain, sock)?;
        tls_stream.do_handshake()?;
        Ok(Box::new(tls_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectorConfig, OpenSslBackend, TransportBackend};

    const VALID: &str = include_str!("../../tests/pykmip/root_certificate.pem");
    // A CERTIFICATE block whose base64 decodes cleanly but is not valid DER.
    const CORRUPT: &str = "-----BEGIN CERTIFICATE-----\nTm90QUNlcnQ=\n-----END CERTIFICATE-----\n";

    // A bundle containing a malformed CERTIFICATE entry must be rejected
    // outright, consistently with the other backends.
    #[test]
    fn rejects_bundle_with_malformed_certificate() {
        let good = ConnectorConfig::with_root(VALID.as_bytes().to_vec());
        assert!(
            OpenSslBackend
                .create_connector(&good, "kmip.invalid:5696".to_string(), "kmip.invalid")
                .is_ok(),
            "a valid CA certificate should be accepted",
        );

        let mixed = ConnectorConfig::with_root(format!("{VALID}\n{CORRUPT}").into_bytes());
        assert!(
            OpenSslBackend
                .create_connector(&mixed, "kmip.invalid:5696".to_string(), "kmip.invalid")
                .is_err(),
            "a bundle containing a malformed certificate must be rejected",
        );
    }
}
