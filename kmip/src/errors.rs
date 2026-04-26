use core::fmt;

use thiserror::Error;

use crate::{ObjectType, ResultReason, ResultStatus};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("TTLV encoding error: {0}")]
    TTLV(#[from] ttlv::Error),
    #[error("TLS error: {0}")]
    TLS(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    KMIP(#[from] ProtocolError),
    #[error("A KMIP batch item is missing")]
    MissingBatchItem,
    #[error("Batch count mismatch (expected: {expected}, got: {got})")]
    BatchCountMismatch { expected: i32, got: usize },
    #[error("Batch count {0} exceeds i32::MAX")]
    BatchCountOverflow(usize),
    #[error("The payload is missing from the response")]
    MissingResponsePayload,
    #[error("Unexpected response payload (want: {want})")]
    UnexpectedResponsePayload { want: &'static str },
    #[error("Unexpected request payload (want: {want})")]
    UnexpectedRequestPayload { want: &'static str },
    #[error(transparent)]
    UnexpectedObject(#[from] UnexpectedObject),
}

#[cfg(feature = "tls-rustls")]
impl From<rustls::Error> for Error {
    fn from(value: rustls::Error) -> Self {
        Self::TLS(value.into())
    }
}

#[cfg(feature = "tls-rustls")]
impl From<rustls::pki_types::pem::Error> for Error {
    fn from(value: rustls::pki_types::pem::Error) -> Self {
        Self::TLS(value.into())
    }
}

#[cfg(feature = "tls-native")]
impl From<native_tls::Error> for Error {
    fn from(value: native_tls::Error) -> Self {
        Self::TLS(value.into())
    }
}

#[cfg(feature = "tls-openssl")]
impl From<openssl::error::ErrorStack> for Error {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::TLS(value.into())
    }
}

#[cfg(feature = "tls-openssl")]
impl From<openssl::ssl::Error> for Error {
    fn from(value: openssl::ssl::Error) -> Self {
        Self::TLS(value.into())
    }
}

#[cfg(feature = "tls-openssl")]
impl<S> From<openssl::ssl::HandshakeError<S>> for Error
where
    S: std::fmt::Debug + Send + Sync + 'static,
{
    fn from(value: openssl::ssl::HandshakeError<S>) -> Self {
        Self::TLS(value.into())
    }
}

#[cfg(feature = "tls-boring")]
impl From<boring::error::ErrorStack> for Error {
    fn from(value: boring::error::ErrorStack) -> Self {
        Self::TLS(value.into())
    }
}

#[cfg(feature = "tls-boring")]
impl From<boring::ssl::Error> for Error {
    fn from(value: boring::ssl::Error) -> Self {
        Self::TLS(value.into())
    }
}

#[derive(Debug)]
pub struct ProtocolError {
    pub status: ResultStatus,
    pub reason: Option<ResultReason>,
    pub message: Option<String>,
}

impl ProtocolError {
    pub fn new_failed(reason: ResultReason, msg: Option<impl Into<String>>) -> Self {
        Self {
            status: ResultStatus::OperationFailed,
            reason: Some(reason),
            message: msg.map(Into::into),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = self.reason.as_ref().map(|r| r.name()).unwrap_or("Unknown");
        let status = self.status.name();
        if let Some(msg) = &self.message {
            return write!(f, "KMIP error: {msg} (status={status}, reason={reason})");
        }
        write!(f, "KMIP error: status={status}, reason={reason}")
    }
}

#[derive(Debug, Error)]
#[error("Unexpected object. Got {got} but want {want}")]
pub struct UnexpectedObject {
    pub got: ObjectType,
    pub want: ObjectType,
}
