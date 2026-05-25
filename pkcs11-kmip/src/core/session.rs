use std::fmt::{Debug, Display};

use super::{Handle, HandleStore};
use cryptoki_sys::*;
use kmip::client::Client;
use parking_lot::{Mutex, MutexGuard};
use tracing::Level;
use zeroize::Zeroizing;

use crate::{
    errors,
    mapping::{EncryptMode, SignVerifyMode},
};

pub enum SessionState {
    Idle,
    Encrypt(String, EncryptMode),
    Encrypted(Zeroizing<Vec<u8>>, Vec<u8>),
    Decrypt(String, EncryptMode),
    Decrypted(Vec<u8>, Zeroizing<Vec<u8>>),
    Sign(String, SignVerifyMode),
    Signed(Vec<u8>, Vec<u8>),
    Verify(String, SignVerifyMode),
    FindServiceKey(Box<dyn Iterator<Item = Handle> + Send>),
}

impl Debug for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Encrypt(key, mode) => f.debug_tuple("Encrypt").field(key).field(mode).finish(),
            Self::Encrypted(_plain, cipher) => f
                .debug_tuple("Encrypted")
                .field(&"<redacted>")
                .field(cipher)
                .finish(),
            Self::Decrypt(key, mode) => f.debug_tuple("Decrypt").field(key).field(mode).finish(),
            Self::Decrypted(cipher, _plain) => f
                .debug_tuple("Decrypted")
                .field(cipher)
                .field(&"<redacted>")
                .finish(),
            Self::Sign(arg0, arg1) => f.debug_tuple("Sign").field(arg0).field(arg1).finish(),
            Self::Signed(arg0, arg1) => f.debug_tuple("Signed").field(arg0).field(arg1).finish(),
            Self::Verify(arg0, arg1) => f.debug_tuple("Verify").field(arg0).field(arg1).finish(),
            Self::FindServiceKey(..) => f.debug_tuple("FindServiceKey").finish(),
        }
    }
}

impl Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Encrypt { .. } => write!(f, "Encrypt"),
            Self::Encrypted(..) => write!(f, "Encrypted"),
            Self::Decrypt { .. } => write!(f, "Decrypt"),
            Self::Decrypted(..) => write!(f, "Decrypted"),
            Self::Sign(..) => write!(f, "Sign"),
            Self::Signed(..) => write!(f, "Signed"),
            Self::Verify(..) => write!(f, "Verify"),
            Self::FindServiceKey(..) => write!(f, "FindServiceKey"),
        }
    }
}

struct InnerSession {
    handles: HandleStore,
    state: SessionState,
    client: Client,
}

pub struct Session {
    rw: bool,
    inner: Mutex<InnerSession>,
}

pub struct SessionRef<'a> {
    rw: bool,
    inner: MutexGuard<'a, InnerSession>,
}

impl Session {
    pub(super) fn new(rw: bool, client: Client) -> Self {
        Self {
            rw,
            inner: Mutex::new(InnerSession {
                handles: HandleStore::new(),
                state: SessionState::Idle,
                client,
            }),
        }
    }

    pub fn is_rw(&self) -> bool {
        self.rw
    }

    pub fn enter<T>(&self, f: impl FnOnce(SessionRef) -> errors::Result<T>) -> errors::Result<T> {
        f(self.lock())
    }

    pub fn lock(&self) -> SessionRef<'_> {
        SessionRef {
            rw: self.rw,
            inner: self.inner.lock(),
        }
    }
}

impl SessionRef<'_> {
    pub fn new_handle(&mut self, hdl: Handle) -> u64 {
        self.inner.handles.store(hdl)
    }

    pub fn get_handle(&self, key: u64) -> errors::Result<&Handle> {
        self.inner.handles.load(key).ok_or(CKR_KEY_HANDLE_INVALID)
    }

    pub fn remove_handle(&mut self, key: u64) -> errors::Result<Handle> {
        self.inner.handles.remove(key).ok_or(CKR_KEY_HANDLE_INVALID)
    }

    pub fn set_state(&mut self, state: SessionState) {
        if tracing::enabled!(Level::TRACE) {
            tracing::trace!(previous = ?self.inner.state, new = ?state, "State changed");
        } else {
            tracing::debug!(previous = %self.inner.state, new = %state, "State changed");
        }
        self.inner.state = state;
    }

    pub fn get_state(&self) -> &SessionState {
        &self.inner.state
    }

    pub fn get_mut_state(&mut self) -> &mut SessionState {
        &mut self.inner.state
    }

    pub fn is_rw(&self) -> bool {
        self.rw
    }

    pub fn client(&mut self) -> &mut Client {
        &mut self.inner.client
    }
}
