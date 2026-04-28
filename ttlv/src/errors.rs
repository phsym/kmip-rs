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

/// Result alias for fallible TTLV operations.
pub type Result<T> = std::result::Result<T, Error>;

/// What an [`Error::UnexpectedTag`] or [`Error::UnexpectedType`] was hoping
/// to find.
///
/// `Only(t)` means a single value was expected; `OneOf(vs)` means any of a
/// set was acceptable.
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

/// All errors that can occur while encoding, decoding, or framing TTLV.
///
/// `EOF` and `UnexpectedTag` are special: the [`Decodable`](crate::Decodable)
/// blanket impls for `Option<T>` and `Vec<T>` interpret them as "no further
/// item of this kind", which lets repeated and optional fields be parsed
/// without lookahead.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_only_display() {
        let e: Expected<&str> = Expected::Only("foo");
        assert_eq!(e.to_string(), "foo");
    }

    #[test]
    fn test_expected_one_of_display() {
        let e: Expected<&str> = Expected::OneOf(vec!["a", "b", "c"]);
        assert_eq!(e.to_string(), "one of [a, b, c]");
    }

    #[test]
    fn test_expected_one_of_single_display() {
        let e: Expected<&str> = Expected::OneOf(vec!["x"]);
        assert_eq!(e.to_string(), "one of [x]");
    }

    #[test]
    fn test_error_eof_display() {
        assert_eq!(Error::EOF.to_string(), "EOF");
    }

    #[test]
    fn test_error_invalid_type_display() {
        assert_eq!(Error::InvalidType(99).to_string(), "invalid TTLV type 99");
    }

    #[test]
    fn test_error_invalid_tag_display() {
        let e = Error::InvalidTag(RawTag::Num(0x420001));
        assert_eq!(e.to_string(), "invalid TTLV tag 0x420001");
    }

    #[test]
    fn test_error_value_out_of_bound_display() {
        assert_eq!(Error::ValueOutOfBound.to_string(), "Value is out of bound");
    }

    #[test]
    fn test_error_missing_tag_display() {
        assert_eq!(Error::MissingTag.to_string(), "Tag is missing");
    }

    #[test]
    fn test_error_missing_value_display() {
        assert_eq!(Error::MissingValue.to_string(), "Value is missing");
    }

    #[test]
    fn test_error_tag_missing_numeric_display() {
        let e = Error::TagMissingNumeric {
            tag: RawTag::Str("MyTag".into()),
        };
        assert_eq!(
            e.to_string(),
            "tag MyTag has no numeric form (required by encoder)"
        );
    }

    #[test]
    fn test_error_invalid_bitmask_value_display() {
        let e = Error::InvalidBitmaskValue("bad".into());
        assert_eq!(e.to_string(), "Invalid bitmask value: bad");
    }

    #[test]
    fn test_error_invalid_type_str_display() {
        let e = Error::InvalidTypeStr("notatype".into());
        assert_eq!(e.to_string(), "invalid TTLV type notatype");
    }

    #[test]
    fn test_error_unexpected_tag_display() {
        let e = Error::UnexpectedTag {
            got: RawTag::Num(0x420001),
            expected: Expected::Only(RawTag::Num(0x420002)),
        };
        assert_eq!(
            e.to_string(),
            "Unexpected TTLV tag. Got 0x420001 but expected 0x420002"
        );
    }

    #[test]
    fn test_error_unexpected_type_display() {
        use crate::Type;
        let e = Error::UnexpectedType {
            got: Type::Integer,
            expected: Expected::Only(Type::Boolean),
            tag: RawTag::Num(0x420001),
        };
        assert_eq!(
            e.to_string(),
            "Unexpected TTLV type on tag 0x420001. Got Integer but expected Boolean"
        );
    }

    #[test]
    fn test_error_invalid_struct_display() {
        let e = Error::InvalidStruct(RawTag::Num(0x420001), Box::new(Error::EOF));
        assert_eq!(e.to_string(), "Invalid structure (tag = 0x420001): EOF");
    }

    #[test]
    fn test_error_invalid_enum_display() {
        let e = Error::InvalidEnum {
            tag: RawTag::Num(0x420001),
            value: RawTag::Num(0xFF),
        };
        assert_eq!(
            e.to_string(),
            "The value 0x0000FF for enum 0x420001 is invalid"
        );
    }
}
