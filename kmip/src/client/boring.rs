use std::{sync::Arc, time::Duration};

use boring::{
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, store::X509StoreBuilder},
};

use crate::{Error, Result};

use super::{ClientBuilder, Connector, TlsBackend, Transport, dial};

pub struct BoringBackend;

impl TlsBackend for BoringBackend {
    fn create_connector(
        &self,
        builder: &ClientBuilder,
        addr: String,
        domain: &str,
    ) -> Result<Arc<dyn Connector>> {
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
    addr: String,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
}

impl BoringSslConnector {
    pub fn new(
        cfg: SslConnector,
        addr: impl Into<String>,
        domain: impl Into<String>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        tcp_nodelay: bool,
    ) -> Self {
        Self {
            inner: cfg,
            domain: domain.into(),
            addr: addr.into(),
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
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?;
        let mut tls_stream = self.inner.connect(&self.domain, sock)?;
        tls_stream.do_handshake()?;
        Ok(Box::new(tls_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::{BoringBackend, ClientBuilder, TlsBackend};

    const VALID: &str = include_str!("../../tests/pykmip/root_certificate.pem");
    // A CERTIFICATE block whose base64 decodes cleanly but is not valid DER.
    const CORRUPT: &str = "-----BEGIN CERTIFICATE-----\nTm90QUNlcnQ=\n-----END CERTIFICATE-----\n";

    // A bundle containing a malformed CERTIFICATE entry must be rejected
    // outright, consistently with the other backends.
    #[test]
    fn rejects_bundle_with_malformed_certificate() {
        let good =
            ClientBuilder::new(BoringBackend).add_root_certificate(VALID.as_bytes().to_vec());
        assert!(
            BoringBackend
                .create_connector(&good, "kmip.invalid:5696".to_string(), "kmip.invalid")
                .is_ok(),
            "a valid CA certificate should be accepted",
        );

        let mixed = ClientBuilder::new(BoringBackend)
            .add_root_certificate(format!("{VALID}\n{CORRUPT}").into_bytes());
        assert!(
            BoringBackend
                .create_connector(&mixed, "kmip.invalid:5696".to_string(), "kmip.invalid")
                .is_err(),
            "a bundle containing a malformed certificate must be rejected",
        );
    }
}
