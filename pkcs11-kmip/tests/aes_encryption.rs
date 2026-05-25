mod common;

use common::{DeferCleanup, hex_encode, open_session};
use cryptoki::{
    mechanism::{Mechanism, aead::GcmParams},
    object::{Attribute, ObjectHandle},
    session::Session,
};

fn generate_aes_key(sess: &Session, cleanup: &mut DeferCleanup<'_>) -> ObjectHandle {
    let attrs = &[
        Attribute::ValueLen(32.into()),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
    ];
    let hdl = sess
        .generate_key(&Mechanism::AesKeyGen, attrs)
        .expect("AES generate_key");
    cleanup.add_key(hdl);
    hdl
}

fn roundtrip(name: &str, sess: &Session, key: ObjectHandle, mech: &Mechanism<'_>, data: &[u8]) {
    let result = sess.encrypt(mech, key, data).expect("encrypt");
    println!("Encrypted {name}: {}", hex_encode(&result));
    let dec = sess.decrypt(mech, key, &result).expect("decrypt");
    let plain = std::str::from_utf8(&dec).expect("decrypted not utf8");
    assert_eq!(data, dec);
    println!("Decrypted {name}: {plain}");
}

#[test]
fn aes_ecb_roundtrip() {
    let sess = open_session();
    let mut cleanup = DeferCleanup::new(&sess);
    let key = generate_aes_key(&sess, &mut cleanup);
    roundtrip("ECB", &sess, key, &Mechanism::AesEcb, b"foobarbazfoobarb");
}

#[test]
fn aes_cbc_roundtrip() {
    let sess = open_session();
    let mut cleanup = DeferCleanup::new(&sess);
    let key = generate_aes_key(&sess, &mut cleanup);
    let iv: [u8; 16] = *b"1234567890123456";
    roundtrip(
        "CBC",
        &sess,
        key,
        &Mechanism::AesCbc(iv),
        b"foobarbazfoobarb",
    );
}

#[test]
fn aes_cbc_pad_roundtrip() {
    let sess = open_session();
    let mut cleanup = DeferCleanup::new(&sess);
    let key = generate_aes_key(&sess, &mut cleanup);
    let iv: [u8; 16] = *b"1234567890123456";
    roundtrip(
        "CBC_PAD",
        &sess,
        key,
        &Mechanism::AesCbcPad(iv),
        b"foobarbazfoobarbaz",
    );
}

#[test]
fn aes_gcm_roundtrip() {
    let sess = open_session();
    let mut cleanup = DeferCleanup::new(&sess);
    let key = generate_aes_key(&sess, &mut cleanup);
    let mut iv: [u8; 16] = *b"1234567890123456";
    let mech = Mechanism::AesGcm(
        GcmParams::new(&mut iv[..12], b"the aad", 128.into()).expect("GcmParams"),
    );
    roundtrip("GCM", &sess, key, &mech, b"foobarbazfoobarbaz");
}
