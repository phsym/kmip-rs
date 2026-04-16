use kmip::{Client, ClientBuilder, CorrelationValueMiddleware, DebugMiddleware};

// static ADDR: &str = "localhost:5696";
// static CA: &str = "/Users/psymonea/repos/enablers/kms/cli/kms_config/small-kms/cert/public-ca.crt";
// static CERT: &str =
//     "/Users/psymonea/repos/enablers/kms/cli/kms_config/small-kms/cert/domain/cert.pem";
// static KEY: &str =
//     "/Users/psymonea/repos/enablers/kms/cli/kms_config/small-kms/cert/domain/key.pem";
// static DOMAIN: &str = "localhost";

// static ADDR: &str = "okms.gra.preprod.enablers.ovh:5696";
// static CA: &str = "./certs/preprod/ca.pem";
// static CERT: &str = "./certs/preprod/cert.pem";
// static KEY: &str = "./certs/preprod/key.pem";
// static DOMAIN: &str = "okms.gra.preprod.enablers.ovh";

static ADDR: &str = "eu-west-rbx.okms.ovh.net:5696";
static CA: &str = "../certs/prod/ca.pem";
static CERT: &str = "../certs/prod/cert.pem";
static KEY: &str = "../certs/prod/key.pem";
static DOMAIN: &str = "eu-west-rbx.okms.ovh.net";

// static RESOURCE_ID: &str = "ad4d0cc9-c0e2-4958-b06d-f74c26632b5d";

pub fn new_client() -> Client {
    ClientBuilder::new()
        .add_root_certificate_file(CA)
        .unwrap()
        .identity_file(CERT, KEY)
        .unwrap()
        .connect_rustls(ADDR, DOMAIN)
        // .connect_openssl(ADDR, DOMAIN)
        // .connect_native(ADDR, DOMAIN)
        // .connect_boring(ADDR, DOMAIN)
        .unwrap()
        .with_middleware(CorrelationValueMiddleware::uuid())
        .with_middleware(DebugMiddleware)
}
