use std::{
    fs::File,
    io::{BufReader, Read, Write},
    net::TcpStream,
    sync::Arc,
};

use rustls::{
    RootCertStore,
    pki_types::{
        PrivateKeyDer,
        pem::{self, PemObject},
    },
};

static ADDR: &str = "localhost:5697";
static CA: &str = "/Users/psymonea/repos/enablers/kms/cli/kms_config/small-kms/cert/public-ca.crt";
static CERT: &str =
    "/Users/psymonea/repos/enablers/kms/cli/kms_config/small-kms/cert/domain/cert.pem";
static KEY: &str =
    "/Users/psymonea/repos/enablers/kms/cli/kms_config/small-kms/cert/domain/key.pem";

/*
<RequestMessage>
    <RequestHeader>
        <ProtocolVersion>
            <ProtocolVersionMajor type="Integer" value="49690282"/>
            <ProtocolVersionMinor type="Integer" value="2052496146"/>
        </ProtocolVersion>
        <MaximumResponseSize type="Integer" value="1628602306"/>
        <AsynchronousIndicator type="Boolean" value="false"/>
        <Authentication>
            <Credential>
                <CredentialType type="Enumeration" value="0x00000001"/>
                <CredentialValue>
                    <Username type="TextString" value=""/>
                    <Password type="TextString" value=""/>
                </CredentialValue>
            </Credential>
        </Authentication>
        <BatchOrderOption type="Boolean" value="false"/>
        <TimeStamp type="DateTime" value="+234775-08-29T20:30:07+02:00"/>
        <BatchCount type="Integer" value="-1567517436"/>
    </RequestHeader>
    <BatchItem>
        <Operation type="Enumeration" value="0x0000000C"/>
        <RequestPayload>
            <UniqueIdentifier type="TextString" value="3"/>
        </RequestPayload>
    </BatchItem>
</RequestMessage>
 */
static PAYLOAD: &[u8] = &[
    66, 0, 120, 1, 0, 0, 0, 232, 66, 0, 119, 1, 0, 0, 0, 176, 66, 0, 105, 1, 0, 0, 0, 32, 66, 0,
    106, 2, 0, 0, 0, 4, 2, 246, 54, 170, 0, 0, 0, 0, 66, 0, 107, 2, 0, 0, 0, 4, 122, 86, 155, 18,
    0, 0, 0, 0, 66, 0, 80, 2, 0, 0, 0, 4, 97, 18, 127, 194, 0, 0, 0, 0, 66, 0, 7, 6, 0, 0, 0, 8, 0,
    0, 0, 0, 0, 0, 0, 0, 66, 0, 12, 1, 0, 0, 0, 48, 66, 0, 35, 1, 0, 0, 0, 40, 66, 0, 36, 5, 0, 0,
    0, 4, 0, 0, 0, 1, 0, 0, 0, 0, 66, 0, 37, 1, 0, 0, 0, 16, 66, 0, 153, 7, 0, 0, 0, 0, 66, 0, 161,
    7, 0, 0, 0, 0, 66, 0, 16, 6, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 66, 0, 146, 9, 0, 0, 0, 8, 0,
    0, 6, 174, 133, 176, 56, 47, 66, 0, 13, 2, 0, 0, 0, 4, 162, 145, 149, 4, 0, 0, 0, 0, 66, 0, 15,
    1, 0, 0, 0, 40, 66, 0, 92, 5, 0, 0, 0, 4, 0, 0, 0, 12, 0, 0, 0, 0, 66, 0, 121, 1, 0, 0, 0, 16,
    66, 0, 148, 7, 0, 0, 0, 1, 51, 0, 0, 0, 0, 0, 0, 0,
];

fn main() {
    println!("Testing close-notify");

    let mut root_store = RootCertStore::empty();
    let ca = pem::ReadIter::new(BufReader::new(File::open(CA).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    root_store.add_parsable_certificates(ca);

    let cfg = rustls::ClientConfig::builder().with_root_certificates(root_store);

    let cert_chain = pem::ReadIter::new(BufReader::new(File::open(CERT).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key_der = PrivateKeyDer::from_pem_file(KEY).unwrap();
    let cfg = cfg.with_client_auth_cert(cert_chain, key_der).unwrap();

    let conn =
        rustls::ClientConnection::new(Arc::new(cfg), "localhost".to_owned().try_into().unwrap())
            .unwrap();
    let sock = TcpStream::connect(ADDR).unwrap();
    let mut stream = rustls::StreamOwned::new(conn, sock);

    stream.write_all(PAYLOAD).unwrap();
    let mut resp = Vec::new();
    // Will panic on error with
    // called `Result::unwrap()` on an `Err` value: Custom { kind: UnexpectedEof, error: "peer closed connection without sending TLS close_notify: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof" }
    stream.read_to_end(&mut resp).unwrap();
    println!("Done");
}
