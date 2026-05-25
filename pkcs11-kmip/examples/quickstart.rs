use const_oid::db::rfc5912;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{
        Mechanism, MechanismType,
        aead::GcmParams,
        rsa::{PkcsMgfType, PkcsPssParams},
    },
    object::Attribute,
};
use der::Encode;
use sec1::EcParameters;
use std::fmt::Write;

fn mod_path() -> String {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let lib_name = env!("CARGO_PKG_NAME").replace("-", "_");
    format!(
        "{}/../target/{profile}/{}{lib_name}{}",
        env!("CARGO_MANIFEST_DIR"),
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX,
    )
}

/// A helper struct to defer cleanup of generated keys until the end of the main function.
///
/// Keys added to this struct will be automatically destroyed when the struct is dropped.
struct DeferCleanup<'a> {
    sess: &'a cryptoki::session::Session,
    keys: Vec<cryptoki::object::ObjectHandle>,
}

impl<'a> DeferCleanup<'a> {
    /// Create a new DeferCleanup instance for the given session
    fn new(sess: &'a cryptoki::session::Session) -> Self {
        Self {
            sess,
            keys: Vec::new(),
        }
    }

    /// Add a key to the cleanup list
    fn add_key(&mut self, key: cryptoki::object::ObjectHandle) {
        if self.keys.contains(&key) {
            return;
        }
        self.keys.push(key);
    }
}

impl Drop for DeferCleanup<'_> {
    fn drop(&mut self) {
        println!("Cleaning up generated keys");
        for key in &self.keys {
            if let Err(e) = self.sess.destroy_object(*key) {
                eprintln!("Failed to destroy object {key}: {e}");
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mod_path = mod_path();
    println!("Initializing PKCS#11 provider from {mod_path}");
    let pkcs = Pkcs11::new(&mod_path)?;
    pkcs.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    println!("Listing slots");
    let slots = pkcs.get_all_slots()?;
    for slot in &slots {
        let info = pkcs.get_slot_info(*slot)?;
        println!(
            "slot {slot}: manufacturer={} description={}",
            info.manufacturer_id(),
            info.slot_description()
        );
    }

    println!("Listing mechanisms");
    for mech in pkcs.get_mechanism_list(slots[0])? {
        let info = pkcs.get_mechanism_info(slots[0], mech)?;
        println!("mechanism : {mech}, info: {info:?}");
    }

    println!("Opening session");
    let sess = pkcs.open_rw_session(slots[0])?;

    let mut cleanup = DeferCleanup::new(&sess);

    // sess.login(UserType::User, Some(&AuthPin::new("12345".into())))?;

    println!("Generating AES key");
    let attrs = &[
        Attribute::ValueLen(32.into()),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
    ];
    let hdl = sess.generate_key(&Mechanism::AesKeyGen, attrs)?;
    cleanup.add_key(hdl);

    println!("Generating RSA key pair");
    let pub_attrs = &[
        Attribute::ModulusBits(2048.into()),
        // Attribute::PublicExponent(vec![0x01, 0x00, 0x01].into()),
        Attribute::Encrypt(true),
        Attribute::Verify(true),
    ];
    let priv_attrs = &[
        Attribute::Decrypt(true),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];
    let (rsa_pub_hdl, rsa_priv_hdl) =
        sess.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, pub_attrs, priv_attrs)?;

    cleanup.add_key(rsa_pub_hdl);
    cleanup.add_key(rsa_priv_hdl);

    println!("Generating ECDSA key pair");
    let pub_attrs = &[
        Attribute::EcParams(
            EcParameters::NamedCurve(rfc5912::SECP_256_R_1)
                .to_der()
                .unwrap(),
        ), // secp256r1
        Attribute::Verify(true),
        Attribute::ValueLen((256 / 8).into()),
    ];
    let priv_attrs = &[
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];
    let (ecdsa_pub_hdl, ecdsa_priv_hdl) =
        sess.generate_key_pair(&Mechanism::EccKeyPairGen, pub_attrs, priv_attrs)?;

    cleanup.add_key(ecdsa_pub_hdl);
    cleanup.add_key(ecdsa_priv_hdl);

    println!("Encrypting");

    struct Params<'a> {
        name: &'a str,
        mech: Mechanism<'a>,
        data: &'a [u8],
    }

    let mut iv: [u8; 16] = *b"1234567890123456";

    let params = [
        Params {
            name: "ECB",
            mech: Mechanism::AesEcb,
            data: b"foobarbazfoobarb",
        },
        Params {
            name: "CBC",
            mech: Mechanism::AesCbc(iv),
            data: b"foobarbazfoobarb",
        },
        Params {
            name: "CBC_PAD",
            mech: Mechanism::AesCbcPad(iv),
            data: b"foobarbazfoobarbaz",
        },
        Params {
            name: "GCM",
            mech: Mechanism::AesGcm(GcmParams::new(&mut iv[..12], b"the aad", 128.into())?),
            data: b"foobarbazfoobarbaz",
        },
    ];

    for Params { name, mech, data } in params {
        let result = sess.encrypt(&mech, hdl, data)?;
        println!("Encrypted {name}: {}", hex_encode(&result));
        let dec = sess.decrypt(&mech, hdl, &result)?;
        let plain = str::from_utf8(&dec)?;
        assert_eq!(data, dec);
        println!("Decrypted {name}: {plain}");
    }

    println!("Signing RSA PKCS");
    let sig = sess.sign(&Mechanism::Sha256RsaPkcs, rsa_priv_hdl, b"hello world")?;
    println!("RSA_PKCS Signature: {}", hex_encode(&sig));

    println!("Verifying RSA PKCS");
    sess.verify(&Mechanism::Sha256RsaPkcs, rsa_pub_hdl, b"hello world", &sig)?;

    println!("Signing RSA PSS");
    let params = Mechanism::Sha256RsaPkcsPss(PkcsPssParams {
        hash_alg: MechanismType::SHA256,
        mgf: PkcsMgfType::MGF1_SHA256,
        s_len: 32.into(),
    });
    let sig = sess.sign(&params, rsa_priv_hdl, b"hello world")?;
    println!("RSA_PSS Signature: {}", hex_encode(&sig));

    println!("Verifying RSA PSS");
    sess.verify(&params, rsa_pub_hdl, b"hello world", &sig)?;

    println!("Signing ECDSA");
    let sig = sess.sign(&Mechanism::EcdsaSha256, ecdsa_priv_hdl, b"hello world")?;
    println!("ECDSA Signature: {}", hex_encode(&sig));

    println!("Verifying ECDSA");
    sess.verify(&Mechanism::EcdsaSha256, ecdsa_pub_hdl, b"hello world", &sig)?;

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            write!(acc, "{b:02x}").unwrap();
            acc
        })
}
