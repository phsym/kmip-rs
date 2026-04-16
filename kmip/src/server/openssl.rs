use std::net::{TcpListener, TcpStream, ToSocketAddrs};

use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod, SslStream, SslVerifyMode},
    x509::X509,
};

use super::{Acceptor, AcceptorBuilder, Ready, Transport};

impl Transport for SslStream<TcpStream> {
    fn remote_address(&self) -> std::io::Result<std::net::SocketAddr> {
        self.get_ref().peer_addr()
    }
}

pub struct OpenSslAcceptor {
    list: TcpListener,
    cfg: SslAcceptor,
}

impl OpenSslAcceptor {
    pub fn new(cfg: SslAcceptor, a: impl ToSocketAddrs) -> std::io::Result<Self> {
        Ok(Self {
            list: TcpListener::bind(a)?,
            cfg,
        })
    }
}

impl Acceptor for OpenSslAcceptor {
    type Transport = SslStream<TcpStream>;

    fn accept(&self) -> crate::Result<Self::Transport> {
        let (sock, _) = self.list.accept()?;
        let mut stream = self.cfg.accept(sock)?;
        stream.do_handshake()?;
        Ok(stream)
    }
}

impl AcceptorBuilder<Ready> {
    pub fn listen_openssl(&self, addr: impl ToSocketAddrs) -> crate::Result<OpenSslAcceptor> {
        let mut acc = SslAcceptor::mozilla_intermediate(SslMethod::tls_server())?;

        for root in &self.root_certs {
            let certs = X509::stack_from_pem(root)?;
            for cert in certs {
                acc.cert_store_mut().add_cert(cert)?;
            }
        }
        //TODO: This should be configurable
        acc.set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);

        let (cert, key) = self.identity.as_ref().unwrap();
        let mut certs = X509::stack_from_pem(cert)?.into_iter();
        acc.set_certificate(
            certs
                .next()
                .ok_or(crate::Error::TLS("Bad client certificate".into()))?
                .as_ref(),
        )?;
        for cert in certs {
            acc.add_extra_chain_cert(cert)?
        }
        acc.set_private_key(PKey::private_key_from_pem(key)?.as_ref())?;

        Ok(OpenSslAcceptor::new(acc.build(), addr)?)
    }
}
