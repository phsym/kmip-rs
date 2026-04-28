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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TtlvDecoder, TtlvEncoder};

    // -- Type --

    #[test]
    fn test_type_from_repr_all_variants() {
        for (byte, expected) in [
            (1u8, Type::Structure),
            (2, Type::Integer),
            (3, Type::LongInteger),
            (4, Type::BigInteger),
            (5, Type::Enumeration),
            (6, Type::Boolean),
            (7, Type::TextString),
            (8, Type::ByteString),
            (9, Type::DateTime),
            (10, Type::Interval),
        ] {
            let t = Type::try_from(byte).unwrap();
            assert_eq!(t, expected);
        }
    }

    #[test]
    fn test_type_try_from_invalid_returns_error() {
        let err = Type::try_from(0u8).unwrap_err();
        assert!(matches!(err, Error::InvalidType(0)));
        let err2 = Type::try_from(99u8).unwrap_err();
        assert!(matches!(err2, Error::InvalidType(99)));
    }

    #[test]
    fn test_type_from_type_into_u8() {
        assert_eq!(u8::from(Type::Integer), 2u8);
        assert_eq!(u8::from(Type::Structure), 1u8);
    }

    #[test]
    fn test_type_display() {
        assert_eq!(Type::Integer.to_string(), "Integer");
        assert_eq!(Type::TextString.to_string(), "TextString");
    }

    // -- Value::get_type --

    #[test]
    fn test_value_get_type_all_variants() {
        use crate::{RawTag, Struct};
        let cases: Vec<(Value<RawTag>, Type)> = vec![
            (Value::Structure(Struct(vec![])), Type::Structure),
            (Value::Integer(0), Type::Integer),
            (Value::LongInteger(0), Type::LongInteger),
            (Value::BigInteger(vec![0]), Type::BigInteger),
            (Value::Enum(RawTag::Num(1)), Type::Enumeration),
            (Value::Boolean(true), Type::Boolean),
            (Value::TextString("".into()), Type::TextString),
            (Value::ByteString(vec![]), Type::ByteString),
            (Value::DateTime(0), Type::DateTime),
            (Value::Interval(0), Type::Interval),
        ];
        for (val, expected) in cases {
            assert_eq!(val.get_type(), expected, "{val:?}");
        }
    }

    // -- Value Debug --

    #[test]
    fn test_value_debug() {
        let inner: Struct<RawTag> = Struct(vec![TTLV {
            tag: RawTag::Num(0x420001),
            val: Value::Integer(1),
        }]);
        let cases: Vec<(Value<RawTag>, &str)> = vec![
            (Value::Integer(42), "Integer"),
            (Value::Boolean(true), "Boolean"),
            (Value::TextString("hi".into()), "TextString"),
            (Value::ByteString(vec![1]), "ByteString"),
            (Value::LongInteger(1), "LongInteger"),
            (Value::BigInteger(vec![1]), "BigInteger"),
            (Value::DateTime(0), "DateTime"),
            (Value::Interval(0), "Interval"),
            (Value::Enum(RawTag::Num(7)), "Enum"),
            (Value::Structure(inner), "Structure"),
        ];
        for (val, needle) in &cases {
            let dbg = format!("{val:?}");
            assert!(dbg.contains(needle), "missing {needle} in {dbg}");
        }
    }

    // -- Struct Debug --

    #[test]
    fn test_struct_debug() {
        let s: Struct = Struct(vec![]);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Structure"));
    }

    // -- TTLV --

    fn make_ttlv_integer() -> (Vec<u8>, TTLV<RawTag>) {
        let mut enc = TtlvEncoder::new();
        enc.write_integer(0x420001u32, 42).unwrap();
        let bytes = enc.into_inner();
        let mut dec = TtlvDecoder::new(&bytes);
        let item: TTLV<RawTag> = TTLV::decode(&mut dec).unwrap();
        (bytes, item)
    }

    #[test]
    fn test_ttlv_decode_integer() {
        let (_, item) = make_ttlv_integer();
        assert_eq!(item.get_type(), Type::Integer);
        assert_eq!(item.tag, RawTag::Num(0x420001));
        assert_eq!(item.val, Value::Integer(42));
    }

    #[test]
    fn test_ttlv_encode_roundtrip() {
        let (original_bytes, item) = make_ttlv_integer();
        let mut enc = TtlvEncoder::new();
        item.encode(&mut enc).unwrap();
        assert_eq!(enc.bytes(), original_bytes.as_slice());
    }

    #[test]
    fn test_ttlv_debug() {
        let (_, item) = make_ttlv_integer();
        let dbg = format!("{item:?}");
        assert!(dbg.contains("Field"));
    }

    #[test]
    fn test_ttlv_decode_all_value_types() {
        // Structure
        let mut enc = TtlvEncoder::new();
        enc.write_struct(0x420001u32, |e| {
            e.write_integer(0x420002u32, 7)?;
            Ok(())
        })
        .unwrap();
        let mut dec = TtlvDecoder::new(enc.bytes());
        let item: TTLV<RawTag> = TTLV::decode(&mut dec).unwrap();
        assert_eq!(item.get_type(), Type::Structure);

        // Boolean
        let mut enc = TtlvEncoder::new();
        enc.write_bool(0x420001u32, false).unwrap();
        let mut dec = TtlvDecoder::new(enc.bytes());
        let item: TTLV<RawTag> = TTLV::decode(&mut dec).unwrap();
        assert_eq!(item.val, Value::Boolean(false));

        // ByteString
        let mut enc = TtlvEncoder::new();
        enc.write_bytes(0x420001u32, [0xAB]).unwrap();
        let mut dec = TtlvDecoder::new(enc.bytes());
        let item: TTLV<RawTag> = TTLV::decode(&mut dec).unwrap();
        assert_eq!(item.val, Value::ByteString(vec![0xAB]));
    }
}
