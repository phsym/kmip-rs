use std::env;

use kmip::{
    client::{Client, ClientBuilder},
    middlewares::{CorrelationValueMiddleware, DebugMiddleware},
};

pub fn new_client() -> Client {
    let addr = env::var("KMIP_TEST_ADDR")
        .expect("KMIP_TEST_ADDR must be set to the KMIP server address as host:port");
    let domain = env::var("KMIP_TEST_DOMAIN")
        .expect("KMIP_TEST_DOMAIN must be set to the TLS SNI hostname of the KMIP server");
    let ca = env::var("KMIP_TEST_CA")
        .expect("KMIP_TEST_CA must be set to the path of a PEM-encoded CA certificate");
    let cert = env::var("KMIP_TEST_CERT")
        .expect("KMIP_TEST_CERT must be set to the path of a PEM-encoded client certificate");
    let key = env::var("KMIP_TEST_KEY")
        .expect("KMIP_TEST_KEY must be set to the path of a PEM-encoded client private key");

    ClientBuilder::default()
        .add_root_certificate_file(&ca)
        .unwrap()
        .identity_file(&cert, &key)
        .unwrap()
        .connect(&addr, &domain)
        .unwrap()
        .with_middleware(CorrelationValueMiddleware::uuid())
        .with_middleware(DebugMiddleware)
}
