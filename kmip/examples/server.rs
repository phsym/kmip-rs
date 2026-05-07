use std::env;

use kmip::{
    ProtocolError,
    enums::ResultReason,
    middlewares::DebugMiddleware,
    payloads::{
        DiscoverVersionsRequestPayload, DiscoverVersionsResponsePayload, QueryRequestPayload,
    },
    server::{AcceptorBuilder, Router, Server},
    types::ProtocolVersion,
};

fn main() {
    let addr = env::var("KMIP_ADDR")
        .expect("KMIP_ADDR must be set to the KMIP server address as host:port");
    let ca = env::var("KMIP_CA")
        .expect("KMIP_CA must be set to the path of a PEM-encoded CA certificate");
    let cert = env::var("KMIP_CERT")
        .expect("KMIP_CERT must be set to the path of a PEM-encoded client certificate");
    let key = env::var("KMIP_KEY")
        .expect("KMIP_KEY must be set to the path of a PEM-encoded client private key");

    let acceptor = AcceptorBuilder::new()
        .identity_file(cert, key)
        .unwrap()
        .add_root_certificate_file(ca)
        .unwrap()
        .listen_rustls(addr)
        .unwrap();

    let mut router = Router::new();

    router.route_fn(|_: DiscoverVersionsRequestPayload| {
        Ok(DiscoverVersionsResponsePayload {
            protocol_version: vec![ProtocolVersion::V1_4],
        })
    });

    router.route_fn(|_: QueryRequestPayload| {
        Err(ProtocolError::new_failed(
            ResultReason::OperationNotSupported,
            Some("Query operation is not supported".to_string()),
        ))
    });

    let srv = Server::new(acceptor, router)
        .unwrap()
        .with_middleware(DebugMiddleware);

    srv.run().unwrap();
}
