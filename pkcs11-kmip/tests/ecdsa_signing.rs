mod common;

use common::{DeferCleanup, hex_encode, open_session};
use const_oid::db::rfc5912;
use cryptoki::{
    mechanism::Mechanism,
    object::{Attribute, ObjectHandle},
    session::Session,
};
use der::Encode;
use sec1::EcParameters;

fn generate_ecdsa_key_pair(
    sess: &Session,
    cleanup: &mut DeferCleanup<'_>,
) -> (ObjectHandle, ObjectHandle) {
    let pub_attrs = &[
        Attribute::EcParams(
            EcParameters::NamedCurve(rfc5912::SECP_256_R_1)
                .to_der()
                .expect("encode EcParameters"),
        ),
        Attribute::Verify(true),
        Attribute::ValueLen((256 / 8).into()),
    ];
    let priv_attrs = &[
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];
    let (pub_hdl, priv_hdl) = sess
        .generate_key_pair(&Mechanism::EccKeyPairGen, pub_attrs, priv_attrs)
        .expect("ECDSA generate_key_pair");
    cleanup.add_key(pub_hdl);
    cleanup.add_key(priv_hdl);
    (pub_hdl, priv_hdl)
}

#[test]
fn ecdsa_sha256_sign_verify() {
    let sess = open_session();
    let mut cleanup = DeferCleanup::new(&sess);
    let (pub_hdl, priv_hdl) = generate_ecdsa_key_pair(&sess, &mut cleanup);

    let msg = b"hello world";
    let sig = sess
        .sign(&Mechanism::EcdsaSha256, priv_hdl, msg)
        .expect("ECDSA sign");
    println!("ECDSA Signature: {}", hex_encode(&sig));

    sess.verify(&Mechanism::EcdsaSha256, pub_hdl, msg, &sig)
        .expect("ECDSA verify");
}
