use core::fmt;

use thiserror::Error;

use crate::{ResultReason, ResultStatus, enums::ObjectType};

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
    #[error("no cluster endpoint could be reached: {0}")]
    ClusterUnavailable(String),
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

#[cfg(feature = "tls-native")]
impl<S> From<native_tls::HandshakeError<S>> for Error {
    fn from(value: native_tls::HandshakeError<S>) -> Self {
        match value {
            // Preserve the inner `native_tls::Error` instead of boxing the whole
            // `HandshakeError`, so callers can still downcast the boxed TLS error
            // to `native_tls::Error`.
            native_tls::HandshakeError::Failure(e) => e.into(),
            // A stalled handshake surfaces as `WouldBlock` when the socket's
            // read/write timeout fires (the read returns EAGAIN, i.e.
            // `io::ErrorKind::WouldBlock`). Drop the mid-handshake stream
            // (freeing the socket) and surface that same io kind, matching how
            // the rustls backend reports the identical condition.
            native_tls::HandshakeError::WouldBlock(_) => Self::IO(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "TLS handshake would block",
            )),
        }
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
impl<S> From<openssl::ssl::HandshakeError<S>> for Error {
    fn from(value: openssl::ssl::HandshakeError<S>) -> Self {
        match value {
            openssl::ssl::HandshakeError::SetupFailure(e) => e.into(),
            // `Failure` carries a `MidHandshakeSslStream` that owns the socket;
            // take its inner error (dropping the stream) so the boxed TLS error
            // stays downcastable to `openssl::ssl::Error` and the socket is freed.
            openssl::ssl::HandshakeError::Failure(mid) => mid.into_error().into(),
            // A stalled handshake surfaces as `WouldBlock` when the socket read
            // hits its timeout (EAGAIN / `io::ErrorKind::WouldBlock`); drop the
            // stream and surface that same io kind, matching the rustls backend.
            openssl::ssl::HandshakeError::WouldBlock(_) => Self::IO(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "TLS handshake would block",
            )),
        }
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

#[cfg(feature = "tls-boring")]
impl<S> From<boring::ssl::HandshakeError<S>> for Error {
    fn from(value: boring::ssl::HandshakeError<S>) -> Self {
        match value {
            boring::ssl::HandshakeError::SetupFailure(e) => e.into(),
            // `Failure` carries a `MidHandshakeSslStream` that owns the socket;
            // take its inner error (dropping the stream) so the boxed TLS error
            // stays downcastable to `boring::ssl::Error` and the socket is freed.
            boring::ssl::HandshakeError::Failure(mid) => mid.into_error().into(),
            // A stalled handshake surfaces as `WouldBlock` when the socket read
            // hits its timeout (EAGAIN / `io::ErrorKind::WouldBlock`); drop the
            // stream and surface that same io kind, matching the rustls backend.
            boring::ssl::HandshakeError::WouldBlock(_) => Self::IO(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "TLS handshake would block",
            )),
        }
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
