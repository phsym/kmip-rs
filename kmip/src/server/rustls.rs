use std::{
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::Arc,
};

use rustls::{
    RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};

use super::{Acceptor, AcceptorBuilder, Ready, Transport};

impl Transport for StreamOwned<ServerConnection, TcpStream> {
    fn remote_address(&self) -> std::io::Result<std::net::SocketAddr> {
        self.get_ref().peer_addr()
    }
}

pub struct RustlsAcceptor {
    list: TcpListener,
    cfg: Arc<ServerConfig>,
}

impl RustlsAcceptor {
    pub fn new(cfg: ServerConfig, a: impl ToSocketAddrs) -> std::io::Result<Self> {
        Ok(Self {
            list: TcpListener::bind(a)?,
            cfg: Arc::new(cfg),
        })
    }
}

impl Acceptor for RustlsAcceptor {
    type Transport = StreamOwned<ServerConnection, TcpStream>;

    fn accept(&self) -> crate::Result<Self::Transport> {
        let (mut sock, _) = self.list.accept()?;
        let mut conn = ServerConnection::new(self.cfg.clone())?;
        conn.complete_io(&mut sock)?;
        Ok(StreamOwned::new(conn, sock))
    }
}

impl AcceptorBuilder<Ready> {
    pub fn listen_rustls(&self, addr: impl ToSocketAddrs) -> crate::Result<RustlsAcceptor> {
        let mut root = RootCertStore::empty();
        for cert in &self.root_certs {
            let it = CertificateDer::pem_slice_iter(cert);
            for cert in it {
                root.add(cert?)?;
            }
        }

        let (cert, key) = self.identity.as_ref().unwrap();
        let cfg = ServerConfig::builder()
            .with_client_cert_verifier(
                WebPkiClientVerifier::builder(Arc::new(root))
                    .build()
                    .map_err(|e| crate::Error::TLS(e.into()))?,
            )
            .with_single_cert(
                CertificateDer::pem_slice_iter(cert).collect::<Result<Vec<_>, _>>()?,
                PrivateKeyDer::from_pem_slice(key)?,
            )?;

        Ok(RustlsAcceptor::new(cfg, addr)?)
    }
}
