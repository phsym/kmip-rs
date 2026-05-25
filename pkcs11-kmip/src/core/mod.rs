use std::{
    env::{self, VarError},
    str::FromStr,
};
use tracing::level_filters::LevelFilter;

mod handle;
mod session;
mod state;

pub mod asn1;

pub use handle::*;
pub use session::*;
pub use state::*;

#[derive(Debug, Clone)]
pub struct Config {
    pub log_level: String,
    pub cert: String,
    pub key: String,
    pub endpoint: String,
    pub ca: Option<String>,
}

impl Config {
    fn load_var(name: &str) -> Result<String, String> {
        env::var(name).map_err(|e| match e {
            VarError::NotPresent => format!("{} not set", name),
            VarError::NotUnicode(_) => format!("{} is not valid unicode", name),
        })
    }

    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            log_level: env::var("PKCS11_LOG_LEVEL").unwrap_or("off".to_string()),
            cert: Self::load_var("PKCS11_KMIP_CERT")?,
            key: Self::load_var("PKCS11_KMIP_KEY")?,
            endpoint: Self::load_var("PKCS11_KMIP_ENDPOINT")?,
            ca: match env::var("PKCS11_KMIP_CA") {
                Ok(val) => Some(val),
                Err(VarError::NotPresent) => None,
                Err(e) => return Err(format!("Error loading PKCS11_KMIP_CA: {}", e)),
            },
        })
    }
}

static LOG_INIT: std::sync::Once = std::sync::Once::new();

pub fn setup_logging(cfg: &Config) {
    LOG_INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_max_level(LevelFilter::from_str(&cfg.log_level).unwrap_or(LevelFilter::OFF))
            .with_writer(std::io::stderr)
            .compact()
            .init()
    });
}
