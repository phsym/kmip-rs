use core::fmt;
use std::{
    array::TryFromSliceError,
    convert::Infallible,
    num::ParseIntError,
    str::{ParseBoolError, Utf8Error},
    string::FromUtf8Error,
};

use thiserror::Error;

use crate::{RawTag, Type};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Expected<T> {
    Only(T),
    OneOf(Vec<T>),
}

impl<T: fmt::Display> fmt::Display for Expected<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Only(v) => write!(f, "{v}"),
            Self::OneOf(v) => {
                write!(
                    f,
                    "one of [{}]",
                    v.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("EOF")]
    EOF,
    #[error("invalid TTLV type {0}")]
    InvalidType(u8),
    #[error("invalid TTLV tag {0}")]
    InvalidTag(RawTag),
    #[error("Unexpected TTLV tag. Got {got} but expected {expected}")]
    UnexpectedTag {
        got: RawTag,
        expected: Expected<RawTag>,
    },
    #[error("Unexpected TTLV type on tag {tag}. Got {got} but expected {expected}")]
    UnexpectedType {
        got: Type,
        expected: Expected<Type>,
        tag: RawTag,
    },
    #[error(transparent)]
    FromUtf8(#[from] FromUtf8Error),
    #[error("TTLV value too short: {0}")]
    ValueTooShort(#[from] TryFromSliceError),
    #[error("Value is out of bound")]
    ValueOutOfBound,
    #[error("The value {value} for enum {tag} is invalid")]
    InvalidEnum { tag: RawTag, value: RawTag },
    #[error("Invalid structure (tag = {0}): {1}")]
    InvalidStruct(RawTag, #[source] Box<Error>),
    #[error(transparent)]
    Io(#[from] std::io::Error),

    // XML errors
    #[error(transparent)]
    Utf8(#[from] Utf8Error),
    #[cfg(feature = "xml")]
    #[error("XML decoding error; {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("Tag is missing")]
    MissingTag,
    #[error("Value is missing")]
    MissingValue,
    #[error("tag {tag} has no numeric form (required by encoder)")]
    TagMissingNumeric { tag: RawTag },
    #[cfg(feature = "chrono")]
    #[error("Unix timestamp {0} is out of range")]
    DateTimeOutOfRange(i64),
    #[error(transparent)]
    InvalidInteger(#[from] ParseIntError),
    #[error(transparent)]
    InvalidBool(#[from] ParseBoolError),
    #[error(transparent)]
    #[cfg(any(feature = "xml", feature = "text"))]
    InvalidHex(#[from] data_encoding::DecodeError),
    #[cfg(feature = "chrono")]
    #[error("Invalid date-time format: {0}")]
    InvalidDateTime(#[from] chrono::ParseError),
    #[error("Invalid bitmask value: {0}")]
    InvalidBitmaskValue(String),

    #[error("invalid TTLV type {0}")]
    InvalidTypeStr(String), //TODO: Unify this with InvalidType
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!()
    }
}

// pub trait ResultExt<T> {
//     fn unwrap_eof(self) -> std::result::Result<Option<T>, Error>;

//     // fn unwrap_eof_or_default(self) -> std::result::Result<T, Error>
//     // where
//     //     Self: Sized,
//     //     T: Default,
//     // {
//     //     Ok(self.unwrap_eof()?.unwrap_or_default())
//     // }
// }

// impl<T> ResultExt<T> for std::result::Result<T, Error> {
//     fn unwrap_eof(self) -> std::result::Result<Option<T>, Error> {
//         match self {
//             Ok(v) => Ok(Some(v)),
//             Err(Error::EOF) => Ok(None),
//             Err(e) => Err(e),
//         }
//     }
// }
