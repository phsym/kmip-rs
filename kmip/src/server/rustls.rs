use std::{
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use rustls::{
    RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};

use super::{Acceptor, AcceptorBuilder, Ready, Transport, configure_stream};

impl Transport for StreamOwned<ServerConnection, TcpStream> {
    fn remote_address(&self) -> std::io::Result<std::net::SocketAddr> {
        self.get_ref().peer_addr()
    }
}

pub struct RustlsAcceptor {
    list: TcpListener,
    cfg: Arc<ServerConfig>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
}

impl RustlsAcceptor {
    pub fn new(
        cfg: ServerConfig,
        a: impl ToSocketAddrs,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        tcp_nodelay: bool,
    ) -> std::io::Result<Self> {
        Ok(Self {
            list: TcpListener::bind(a)?,
            cfg: Arc::new(cfg),
            read_timeout,
            write_timeout,
            tcp_nodelay,
        })
    }
}

impl Acceptor for RustlsAcceptor {
    type Transport = StreamOwned<ServerConnection, TcpStream>;

    fn accept(&self) -> crate::Result<Self::Transport> {
        let (mut sock, _) = self.list.accept()?;
        configure_stream(
            &sock,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?;
        let mut conn = ServerConnection::new(self.cfg.clone())?;
        conn.complete_io(&mut sock)?;
        Ok(StreamOwned::new(conn, sock))
    }
}

impl AcceptorBuilder<Ready> {
    pub fn listen_rustls(&self, addr: impl ToSocketAddrs) -> crate::Result<RustlsAcceptor> {
        // Client certificates are mandatory (see the verifier below), so an empty
        // CA set would reject every incoming connection. Fail fast instead.
        if self.root_certs.is_empty() {
            return Err(crate::Error::TLS(
                "No root certificates supplied to verify client certificates".into(),
            ));
        }

        let mut root = RootCertStore::empty();
        for cert in &self.root_certs {
            let before = root.len();
            let it = CertificateDer::pem_slice_iter(cert);
            for cert in it {
                root.add(cert?)?;
            }
            if root.len() == before {
                return Err(crate::Error::TLS("No valid root certificates found".into()));
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

        Ok(RustlsAcceptor::new(
            cfg,
            addr,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?)
    }
}
