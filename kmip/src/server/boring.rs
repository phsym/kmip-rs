use std::{
    net::{TcpListener, TcpStream, ToSocketAddrs},
    time::Duration,
};

use boring::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod, SslStream, SslVerifyMode},
    x509::X509,
};

use super::{Acceptor, AcceptorBuilder, Ready, Transport, configure_stream};

impl Transport for SslStream<TcpStream> {
    fn remote_address(&self) -> std::io::Result<std::net::SocketAddr> {
        self.get_ref().peer_addr()
    }
}

pub struct BoringAcceptor {
    list: TcpListener,
    cfg: SslAcceptor,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
}

impl BoringAcceptor {
    pub fn new(
        cfg: SslAcceptor,
        a: impl ToSocketAddrs,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        tcp_nodelay: bool,
    ) -> std::io::Result<Self> {
        Ok(Self {
            list: TcpListener::bind(a)?,
            cfg,
            read_timeout,
            write_timeout,
            tcp_nodelay,
        })
    }
}

impl Acceptor for BoringAcceptor {
    type Transport = SslStream<TcpStream>;

    fn accept(&self) -> crate::Result<Self::Transport> {
        let (sock, _) = self.list.accept()?;
        configure_stream(
            &sock,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?;
        let mut stream = self.cfg.accept(sock)?;
        stream.do_handshake()?;
        Ok(stream)
    }
}

impl AcceptorBuilder<Ready> {
    pub fn listen_boring(&self, addr: impl ToSocketAddrs) -> crate::Result<BoringAcceptor> {
        let mut acc = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;

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
                .ok_or(crate::Error::TLS("Bad server certificate".into()))?
                .as_ref(),
        )?;
        for cert in certs {
            acc.add_extra_chain_cert(cert)?
        }
        acc.set_private_key(PKey::private_key_from_pem(key)?.as_ref())?;

        Ok(BoringAcceptor::new(
            acc.build(),
            addr,
            self.read_timeout,
            self.write_timeout,
            self.tcp_nodelay,
        )?)
    }
}
