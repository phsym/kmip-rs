mod common;

use common::{DeferCleanup, hex_encode, open_session};
use cryptoki::{
    mechanism::{
        Mechanism, MechanismType,
        rsa::{PkcsMgfType, PkcsPssParams},
    },
    object::{Attribute, ObjectHandle},
    session::Session,
};

fn generate_rsa_key_pair(
    sess: &Session,
    cleanup: &mut DeferCleanup<'_>,
) -> (ObjectHandle, ObjectHandle) {
    let pub_attrs = &[
        Attribute::ModulusBits(2048.into()),
        Attribute::Encrypt(true),
        Attribute::Verify(true),
    ];
    let priv_attrs = &[
        Attribute::Decrypt(true),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];
    let (pub_hdl, priv_hdl) = sess
        .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, pub_attrs, priv_attrs)
        .expect("RSA generate_key_pair");
    cleanup.add_key(pub_hdl);
    cleanup.add_key(priv_hdl);
    (pub_hdl, priv_hdl)
}

#[test]
fn rsa_pkcs_sign_verify() {
    let sess = open_session();
    let mut cleanup = DeferCleanup::new(&sess);
    let (pub_hdl, priv_hdl) = generate_rsa_key_pair(&sess, &mut cleanup);

    let msg = b"hello world";
    let sig = sess
        .sign(&Mechanism::Sha256RsaPkcs, priv_hdl, msg)
        .expect("RSA PKCS sign");
    println!("RSA_PKCS Signature: {}", hex_encode(&sig));

    sess.verify(&Mechanism::Sha256RsaPkcs, pub_hdl, msg, &sig)
        .expect("RSA PKCS verify");
}

#[test]
fn rsa_pss_sign_verify() {
    let sess = open_session();
    let mut cleanup = DeferCleanup::new(&sess);
    let (pub_hdl, priv_hdl) = generate_rsa_key_pair(&sess, &mut cleanup);

    let params = Mechanism::Sha256RsaPkcsPss(PkcsPssParams {
        hash_alg: MechanismType::SHA256,
        mgf: PkcsMgfType::MGF1_SHA256,
        s_len: 32.into(),
    });
    let msg = b"hello world";
    let sig = sess.sign(&params, priv_hdl, msg).expect("RSA PSS sign");
    println!("RSA_PSS Signature: {}", hex_encode(&sig));

    sess.verify(&params, pub_hdl, msg, &sig)
        .expect("RSA PSS verify");
}
