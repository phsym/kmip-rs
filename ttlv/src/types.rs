use core::fmt;

use strum_macros::{AsRefStr, Display, EnumIs, EnumString, EnumTryAs, FromRepr, IntoStaticStr};

use crate::{
    Decodable, Decoder, Encodable, Encoder, Error, RawTag, Tag, TagDecodable, TagEncodable,
};

/// The TTLV item type tag (the "T" in *Type*).
///
/// Encoded on a single byte in the binary format, with values matching those
/// defined in the KMIP TTLV specification.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Display, FromRepr, IntoStaticStr, AsRefStr, EnumString,
)]
#[repr(u8)]
pub enum Type {
    Structure = 1,
    Integer,
    LongInteger,
    BigInteger,
    Enumeration,
    Boolean,
    TextString,
    ByteString,
    DateTime,
    Interval,
}

impl From<Type> for u8 {
    fn from(value: Type) -> Self {
        value as _
    }
}

impl TryFrom<u8> for Type {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Error> {
        Self::from_repr(value).ok_or(Error::InvalidType(value))
    }
}

/// A TTLV `Structure` value: an ordered list of nested [`TTLV`] items.
#[derive(Clone, PartialEq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Struct<T: Tag = RawTag>(pub Vec<TTLV<T>>);

impl<T: Tag> TagEncodable for Struct<T> {
    fn encode<E: Encoder>(&self, tag: impl Tag, encoder: &mut E) -> crate::Result<()> {
        encoder.write_struct(tag, |e| e.encode(&self.0))
    }
}

impl<T: Tag + TryFrom<RawTag>> TagDecodable for Struct<T>
where
    Error: From<T::Error>,
{
    fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> crate::Result<Self> {
        Ok(Self(decoder.read_struct(tag, |d| d.decode())?))
    }
}

impl<T: Tag> fmt::Debug for Struct<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Structure").field(&self.0).finish()
    }
}

/// A dynamically-typed TTLV value (the "V" in *Value*).
///
/// Each variant corresponds to a [`Type`]. `Value` is what you get from a
/// fully generic decode; strongly-typed Rust definitions usually go through
/// the `#[derive(Encodable, Decodable)]` macros instead.
#[derive(Clone, PartialEq, Hash, EnumIs, EnumTryAs)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize),
    serde(untagged)
)]
pub enum Value<T: Tag = RawTag> {
    Structure(Struct<T>),
    Integer(i32),
    LongInteger(i64),
    BigInteger(#[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))] Vec<u8>),
    Enum(RawTag),
    Boolean(bool),
    TextString(String),
    ByteString(#[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))] Vec<u8>),
    DateTime(i64),
    Interval(u32),
}

impl<T: Tag> Value<T> {
    /// Returns the [`Type`] discriminant of this value.
    pub fn get_type(&self) -> Type {
        match self {
            Self::Structure(..) => Type::Structure,
            Self::Integer(..) => Type::Integer,
            Self::BigInteger(..) => Type::BigInteger,
            Self::LongInteger(..) => Type::LongInteger,
            Self::Enum(..) => Type::Enumeration,
            Self::Boolean(..) => Type::Boolean,
            Self::TextString(..) => Type::TextString,
            Self::ByteString(..) => Type::ByteString,
            Self::DateTime(..) => Type::DateTime,
            Self::Interval(..) => Type::Interval,
        }
    }
}

impl<T: Tag> TagEncodable for Value<T> {
    fn encode<E: Encoder>(&self, tag: impl Tag, encoder: &mut E) -> crate::Result<()> {
        match self {
            Self::Structure(st) => encoder.tag_encode(tag, st),
            Self::Integer(i) => encoder.write_integer(tag, *i),
            Self::LongInteger(i) => encoder.write_long(tag, *i),
            Self::BigInteger(i) => encoder.write_bigint(tag, i),
            Self::Enum(e) => encoder.write_enum(tag, e),
            Self::Boolean(b) => encoder.write_bool(tag, *b),
            Self::TextString(s) => encoder.write_string(tag, s),
            Self::ByteString(s) => encoder.write_bytes(tag, s),
            Self::DateTime(dt) => encoder.write_datetime(tag, *dt),
            Self::Interval(secs) => encoder.write_interval(tag, *secs),
        }
    }
}

impl<T: Tag + TryFrom<RawTag>> TagDecodable for Value<T>
where
    Error: From<T::Error>,
{
    fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> crate::Result<Self> {
        Ok(match decoder.get_type()? {
            Type::Structure => Self::Structure(decoder.tag_decode(tag)?),
            Type::Integer => Self::Integer(decoder.read_integer(tag)?),
            Type::LongInteger => Self::LongInteger(decoder.read_long(tag)?),
            Type::BigInteger => Self::BigInteger(decoder.read_bigint(tag)?),
            Type::Enumeration => Self::Enum(decoder.read_enum(tag)?.raw().to_owned()),
            Type::Boolean => Self::Boolean(decoder.read_bool(tag)?),
            Type::TextString => Self::TextString(decoder.read_string(tag)?),
            Type::ByteString => Self::ByteString(decoder.read_bytes(tag)?),
            Type::DateTime => Self::DateTime(decoder.read_datetime(tag)?),
            Type::Interval => Self::Interval(decoder.read_interval(tag)?),
        })
    }
}

impl<T: Tag> fmt::Debug for Value<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Structure(arg0) => fmt::Debug::fmt(arg0, f),
            Self::Integer(arg0) => f.debug_tuple("Integer").field(arg0).finish(),
            Self::LongInteger(arg0) => f.debug_tuple("LongInteger").field(arg0).finish(),
            Self::BigInteger(arg0) => f.debug_tuple("BigInteger").field(arg0).finish(),
            Self::Enum(arg0) => f.debug_tuple("Enum").field(arg0).finish(),
            Self::Boolean(arg0) => f.debug_tuple("Boolean").field(arg0).finish(),
            Self::TextString(arg0) => f.debug_tuple("TextString").field(arg0).finish(),
            Self::ByteString(arg0) => f.debug_tuple("ByteString").field(arg0).finish(),
            Self::DateTime(arg0) => f.debug_tuple("DateTime").field(arg0).finish(),
            Self::Interval(arg0) => f.debug_tuple("Interval").field(arg0).finish(),
        }
    }
}

/// A single dynamically-typed TTLV item: a tag paired with a [`Value`].
///
/// `TTLV` round-trips losslessly through any [`Encoder`]/[`Decoder`] pair and
/// is the natural target when inspecting unknown messages or building tools
/// that operate on the wire format directly.
#[derive(Clone, PartialEq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct TTLV<T: Tag = RawTag> {
    pub tag: T,
    pub val: Value<T>,
}

impl<T: Tag> TTLV<T> {
    /// Returns the [`Type`] of the wrapped value.
    pub fn get_type(&self) -> Type {
        self.val.get_type()
    }
}

// impl <S, D> TryFrom<Field<S>> for Field<D> where S: TryFrom<D>{
//     type Error = S::Error;
//     fn try_from(value: Field<S>) -> Result<Self, Self::Error> {
//         Ok(Self {
//             tag: value.tag.try_into()?,
//             val: Value::Boolean(true),
//         })
//     }
// }

impl<T: Tag> Encodable for TTLV<T> {
    fn encode(&self, encoder: &mut impl Encoder) -> crate::Result<()> {
        encoder.tag_encode(&self.tag, &self.val)
    }
}

impl<T: Tag + TryFrom<RawTag>> Decodable for TTLV<T>
where
    Error: From<T::Error>,
{
    fn decode(decoder: &mut impl Decoder) -> crate::Result<Self> {
        let tag = decoder.tag()?;
        let val = decoder.tag_decode(&tag)?;
        Ok(Self {
            tag: T::try_from(tag.raw().to_owned())?,
            val,
        })
    }
}

impl<T: Tag> fmt::Debug for TTLV<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Field")
            .field("tag", &self.tag.raw())
            .field("val", &self.val)
            .finish()
    }
}
