use std::sync::{
    Arc,
    atomic::{self, AtomicBool, Ordering},
};

use cryptoki_sys::*;
use kmip::{
    client::{Client, ClientBuilder},
    objects::Object,
    payloads::GetAttributesResponsePayload,
};
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use slab::Slab;

use crate::{core::Config, errors};

use super::{Handle, Session, SessionRef};

static GLOBAL_STATE: RwLock<Option<Arc<State>>> = RwLock::new(None);

pub struct State {
    logged_in: atomic::AtomicBool,
    sessions: RwLock<Slab<Arc<Session>>>,
    dialer: Box<dyn Fn() -> errors::Result<Client> + Send + Sync>,
    pub cache: Mutex<LruCache<Handle, (GetAttributesResponsePayload, Object)>>,
}
impl State {
    pub fn get() -> errors::Result<Arc<Self>> {
        GLOBAL_STATE
            .read()
            .clone()
            .ok_or(CKR_CRYPTOKI_NOT_INITIALIZED)
    }

    pub fn initialize(cfg: Config) -> errors::Result<()> {
        let mut gstate = GLOBAL_STATE.write();
        if gstate.is_some() {
            return Err(CKR_CRYPTOKI_ALREADY_INITIALIZED);
        }

        let mut client = ClientBuilder::new()
            .identity_file(&cfg.cert, &cfg.key)
            .unwrap();
        if let Some(ca) = &cfg.ca {
            client = client.add_root_certificate_file(ca).unwrap();
        };

        let domain = cfg.endpoint.split(':').next().unwrap().to_string();

        let dialer = Box::new(move || {
            let client = client
                .connect_rustls(&cfg.endpoint, &domain)
                .map_err(|_| CKR_FUNCTION_FAILED)?;
            // .with_middleware(DebugMiddleware);
            Ok(client)
        });

        *gstate = Some(Arc::new(State {
            logged_in: AtomicBool::new(false),
            sessions: RwLock::new(Slab::new()),
            dialer,
            cache: Mutex::new(LruCache::new(256.try_into().unwrap())),
        }));
        Ok(())
    }

    pub fn finalize() -> errors::Result<()> {
        let mut gstate = GLOBAL_STATE.write();
        if gstate.is_none() {
            return Err(CKR_CRYPTOKI_NOT_INITIALIZED);
        }
        *gstate = None;
        Ok(())
    }

    pub fn create_session(&self, rw: bool) -> errors::Result<u64> {
        // Open a new client connection per-session.
        let client = (self.dialer)()?;
        Ok(self
            .sessions
            .write()
            .insert(Arc::new(Session::new(rw, client))) as u64)
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.read().len()
    }

    pub fn rw_session_count(&self) -> usize {
        self.sessions
            .read()
            .iter()
            .filter(|(_, s)| s.is_rw())
            .count()
    }

    pub fn get_session(&self, session: u64) -> errors::Result<Arc<Session>> {
        self.sessions
            .read()
            .get(session as usize)
            .cloned()
            .ok_or(CKR_SESSION_HANDLE_INVALID)
    }

    pub fn close_session(&self, session: u64) -> errors::Result<()> {
        self.sessions
            .write()
            .try_remove(session as usize)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        if self.active_session_count() == 0 {
            self.logout();
        }
        Ok(())
    }

    pub fn close_all_sessions(&self) {
        self.sessions.write().clear();
        self.logout()
    }

    pub fn enter_session<T>(
        &self,
        session: u64,
        f: impl FnOnce(SessionRef) -> errors::Result<T>,
    ) -> errors::Result<T> {
        self.get_session(session)?.enter(f)
    }

    pub fn login(&self) {
        self.logged_in.store(true, Ordering::SeqCst);
    }

    pub fn logout(&self) {
        self.logged_in.store(false, Ordering::SeqCst);
    }

    pub fn is_logged_in(&self) -> bool {
        self.logged_in.load(Ordering::SeqCst)
    }
}
