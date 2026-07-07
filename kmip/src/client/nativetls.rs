use std::{sync::Arc, time::Duration};

use native_tls::{Certificate, Identity, Protocol, TlsConnector};

use crate::Result;

use super::{ClientBuilder, Connector, TlsBackend, Transport, dial};

/// TLS backend delegating to the OS implementation via native-tls.
///
/// Unlike the other backends, the client identity private key passed to
/// [`ClientBuilder::identity`] must be PKCS#8-encoded
/// (`-----BEGIN PRIVATE KEY-----`); PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`)
/// and SEC1 (`-----BEGIN EC PRIVATE KEY-----`) keys are rejected. Convert with
/// `openssl pkcs8 -topk8 -nocrypt` if needed.
pub struct NativeTlsBackend;

impl TlsBackend for NativeTlsBackend {
    fn create_connector(
        &self,
        builder: &ClientBuilder,
        addr: String,
        domain: &str,
    ) -> Result<Arc<dyn Connector>> {
        let mut bld = TlsConnector::builder();
        if !builder.root_certs.is_empty() {
            // If root CAs have been provided, disable system roots
            bld.disable_built_in_roots(true);
        }
        for root in &builder.root_certs {
            let certs = Certificate::stack_from_pem(root)?;
            if certs.is_empty() {
                return Err(crate::Error::TLS("No valid root certificates found".into()));
            }
            for cert in certs {
                bld.add_root_certificate(cert);
            }
        }
        if let Some((cert, key)) = &builder.identity {
            bld.identity(Identity::from_pkcs8(cert, key)?);
        }
        bld.min_protocol_version(Some(Protocol::Tlsv12));

        Ok(Arc::new(NativeTlsConnector::new(
            bld.build()?,
            addr,
            domain,
            builder.read_timeout,
            builder.write_timeout,
            builder.tcp_nodelay,
        )))
    }
}

pub struct NativeTlsConnector {
    inner: TlsConnector,
    domain: String,
    addr: String,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
}

impl NativeTlsConnector {
    pub fn new(
        cfg: TlsConnector,
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

impl Connector for NativeTlsConnector {
    fn connect(&self) -> Result<Box<dyn Transport>> {
        let sock = dial(
            self.addr.as_str(),
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?;
        let tls_stream = self.inner.connect(&self.domain, sock)?;
        Ok(Box::new(tls_stream))
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientBuilder, NativeTlsBackend, TlsBackend};

    const VALID: &str = include_str!("../../tests/pykmip/root_certificate.pem");
    // A CERTIFICATE block whose base64 decodes cleanly but is not valid DER.
    const CORRUPT: &str = "-----BEGIN CERTIFICATE-----\nTm90QUNlcnQ=\n-----END CERTIFICATE-----\n";

    // A bundle containing a malformed CERTIFICATE entry must be rejected
    // outright, consistently with the other backends.
    #[test]
    fn rejects_bundle_with_malformed_certificate() {
        let good =
            ClientBuilder::new(NativeTlsBackend).add_root_certificate(VALID.as_bytes().to_vec());
        assert!(
            NativeTlsBackend
                .create_connector(&good, "kmip.invalid:5696".to_string(), "kmip.invalid")
                .is_ok(),
            "a valid CA certificate should be accepted",
        );

        let mixed = ClientBuilder::new(NativeTlsBackend)
            .add_root_certificate(format!("{VALID}\n{CORRUPT}").into_bytes());
        assert!(
            NativeTlsBackend
                .create_connector(&mixed, "kmip.invalid:5696".to_string(), "kmip.invalid")
                .is_err(),
            "a bundle containing a malformed certificate must be rejected",
        );
    }
}
