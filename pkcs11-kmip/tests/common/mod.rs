#![allow(dead_code)]

use std::fmt::Write;
use std::sync::OnceLock;

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    session::Session,
    slot::Slot,
};

pub fn mod_path() -> String {
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

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            write!(acc, "{b:02x}").unwrap();
            acc
        })
}

static PKCS11: OnceLock<Pkcs11> = OnceLock::new();

pub fn pkcs11() -> &'static Pkcs11 {
    PKCS11.get_or_init(|| {
        let path = mod_path();
        let pkcs = Pkcs11::new(&path)
            .unwrap_or_else(|e| panic!("failed to load PKCS#11 module at {path}: {e}"));
        pkcs.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .expect("C_Initialize failed");
        pkcs
    })
}

pub fn first_slot() -> Slot {
    let slots = pkcs11().get_all_slots().expect("get_all_slots failed");
    *slots.first().expect("no PKCS#11 slots available")
}

pub fn open_session() -> Session {
    pkcs11()
        .open_rw_session(first_slot())
        .expect("open_rw_session failed")
}

/// A helper struct to defer cleanup of generated keys until the end of a test.
///
/// Keys added to this struct will be automatically destroyed when the struct is dropped.
pub struct DeferCleanup<'a> {
    sess: &'a Session,
    keys: Vec<cryptoki::object::ObjectHandle>,
}

impl<'a> DeferCleanup<'a> {
    pub fn new(sess: &'a Session) -> Self {
        Self {
            sess,
            keys: Vec::new(),
        }
    }

    pub fn add_key(&mut self, key: cryptoki::object::ObjectHandle) {
        if self.keys.contains(&key) {
            return;
        }
        self.keys.push(key);
    }
}

impl Drop for DeferCleanup<'_> {
    fn drop(&mut self) {
        for key in &self.keys {
            if let Err(e) = self.sess.destroy_object(*key) {
                eprintln!("Failed to destroy object {key}: {e}");
            }
        }
    }
}
