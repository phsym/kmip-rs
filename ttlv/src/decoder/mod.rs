#[cfg(feature = "xml")]
mod xml;
use task_local_extensions::Extensions;
#[cfg(feature = "xml")]
pub use xml::*;

mod ttlv;
pub use ttlv::*;

use std::time;

use crate::{Bitmask, Error, Result, Tag, Type};

/// A type that knows its own TTLV tag and can decode itself.
///
/// Typically derived with `#[derive(Decodable)]` and a `#[ttlv(tag = ...)]`
/// attribute. Use [`TagDecodable`] when the tag must be supplied by the
/// caller (typical for primitive fields).
#[diagnostic::on_unimplemented(
    message = "The trait `Decodable` is not implemented for `{Self}`",
    note = "You can automatically derive it with `#[derive(ttlv::Decodable)]` and the `#[ttlv(tag = <tag>)]` attribute",
    note = "Or add the attribute `#[ttlv(tag = <tag>)]` on a derived type's field"
)]
pub trait Decodable: Sized {
    /// Decodes one value of `Self` from `decoder`.
    fn decode(decoder: &mut impl Decoder) -> Result<Self>;
}

/// A type that can decode itself once a tag is provided externally.
///
/// Implemented by primitives and by struct fields: the parent struct holds
/// the tag and passes it to each field. Blanket impls cover `Option<T>` and
/// `Vec<T>`, treating `EOF` and `UnexpectedTag` as "no more values".
#[diagnostic::on_unimplemented(
    message = "The trait `TagDecodable` is not implemented for `{Self}`",
    note = "You can automatically derive it with `#[derive(ttlv::Decodable)]`"
)]
pub trait TagDecodable: Sized {
    /// Decodes a value at `tag` from `decoder`.
    fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> Result<Self>;
}

/// Pull-style reader for TTLV values.
///
/// Each `read_*` method consumes one item of a specific [`Type`] and verifies
/// that its tag matches the expected one, returning [`Error::UnexpectedTag`]
/// or [`Error::UnexpectedType`] otherwise. Implementors include
/// [`TtlvDecoder`](crate::TtlvDecoder) for the binary form and
/// [`XmlDecoder`](crate::XmlDecoder) for the XML form.
pub trait Decoder {
    /// Decoder type used inside [`read_struct`](Self::read_struct).
    type StructDecoder<'b>: Decoder<Tag = Self::Tag>;
    /// Tag representation produced by this decoder.
    type Tag: Tag;

    /// Returns the contextual extension map carried alongside the decode.
    fn extensions(&mut self) -> &mut Extensions;

    /// Returns the tag of the next item without consuming it.
    fn tag(&self) -> Result<Self::Tag>;
    /// Returns the [`Type`] of the next item without consuming it.
    fn get_type(&self) -> Result<Type>;

    /// Consumes a `Structure` item, calling `f` with a sub-decoder positioned
    /// over its body.
    fn read_struct<T>(
        &mut self,
        tag: impl Tag,
        f: impl FnOnce(&mut Self::StructDecoder<'_>) -> Result<T>,
    ) -> Result<T>;
    /// Consumes an `Integer` item.
    fn read_integer(&mut self, tag: impl Tag) -> Result<i32>;
    /// Consumes a `LongInteger` item.
    fn read_long(&mut self, tag: impl Tag) -> Result<i64>;
    /// Consumes a `BigInteger` item, returning its raw big-endian bytes.
    fn read_bigint(&mut self, tag: impl Tag) -> Result<Vec<u8>>;
    /// Consumes an `Enumeration` item, returning the tag identifying the
    /// variant.
    fn read_enum(&mut self, tag: impl Tag) -> Result<Self::Tag>;
    /// Consumes a `Boolean` item.
    fn read_bool(&mut self, tag: impl Tag) -> Result<bool>;
    /// Consumes a `TextString` item.
    fn read_string(&mut self, tag: impl Tag) -> Result<String>;
    /// Consumes a `ByteString` item.
    fn read_bytes(&mut self, tag: impl Tag) -> Result<Vec<u8>>;
    /// Consumes a `DateTime` item, returning a Unix timestamp in seconds.
    fn read_datetime(&mut self, tag: impl Tag) -> Result<i64>;
    /// Consumes an `Interval` item, returning a duration in seconds.
    fn read_interval(&mut self, tag: impl Tag) -> Result<u32>;

    /// Consumes an `Integer` item and reinterprets it as a [`Bitmask`].
    fn read_bitmask<B: Bitmask>(&mut self, tag: impl Tag) -> Result<B>;

    /// Decodes a `T: Decodable` from this decoder. Equivalent to
    /// `T::decode(self)`.
    fn decode<T: Decodable>(&mut self) -> Result<T>
    where
        Self: Sized,
    {
        T::decode(self)
    }

    /// Decodes a `T: TagDecodable` at `tag`. Equivalent to
    /// `T::decode(tag, self)`.
    fn tag_decode<T: TagDecodable>(&mut self, tag: impl Tag) -> Result<T>
    where
        Self: Sized,
    {
        T::decode(tag, self)
    }
}

impl<T: TagDecodable> TagDecodable for Option<T> {
    fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> Result<Self> {
        match T::decode(tag, decoder) {
            Ok(value) => Ok(Some(value)),
            Err(Error::EOF | Error::UnexpectedTag { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl<T: Decodable> Decodable for Option<T> {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        match T::decode(decoder) {
            Ok(value) => Ok(Some(value)),
            Err(Error::EOF | Error::UnexpectedTag { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl<T: TagDecodable> TagDecodable for Vec<T> {
    fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> Result<Self> {
        let mut v = Vec::new();
        loop {
            match T::decode(&tag, decoder) {
                Ok(value) => v.push(value),
                Err(Error::EOF | Error::UnexpectedTag { .. }) => return Ok(v),
                Err(e) => return Err(e),
            }
        }
    }
}

impl<T: Decodable> Decodable for Vec<T> {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        let mut v = Vec::new();
        loop {
            match T::decode(decoder) {
                Ok(value) => v.push(value),
                Err(Error::EOF | Error::UnexpectedTag { .. }) => return Ok(v),
                Err(e) => return Err(e),
            }
        }
    }
}

impl<T: TagDecodable> TagDecodable for Box<T> {
    fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> Result<Self> {
        Ok(Self::new(T::decode(tag, decoder)?))
    }
}

impl<T: Decodable> Decodable for Box<T> {
    fn decode(decoder: &mut impl Decoder) -> Result<Self> {
        Ok(Self::new(T::decode(decoder)?))
    }
}

macro_rules! impl_tag_decodable {
    (<$($ident:ident $(: $tt:path)?), *> $ty:ty, $dec:ident, $expr:expr $(, $cast:ty)?) => {
        impl <$($ident $(: $tt)?), *> TagDecodable for $ty {
            fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> Result<Self> {
                Ok($expr(decoder.$dec(tag)? as _)) // TODO: Use try_into instead of casting, and return an error
                // encoder.$enc(tag, $expr(self) $(as $cast)?);
            }
        }
    };
    (<$($ident:ident: $tt:path), *> $ty:ty, $enc:ident) => {
        impl_tag_decodable!(<$($ident: $tt), *> $ty, $enc, |this: _| this, _);
    };
}

macro_rules! impl_integers {
    ($($ty:ty), *) => {
        $(impl_tag_decodable! {<> $ty, read_integer}) *
    };
}

macro_rules! impl_long_integers {
    ($($ty:ty), *) => {
        $(impl_tag_decodable! {<> $ty, read_long}) *
    };
}

impl_integers!(i8, i16, i32, u16);
impl_long_integers!(u32, i64);
impl_tag_decodable!(<> bool, read_bool);
impl_tag_decodable!(<> String, read_string);
impl_tag_decodable!(<> Vec<u8>, read_bytes);
impl_tag_decodable!(<> crate::BigInteger, read_bigint, crate::BigInteger::signed);

impl TagDecodable for time::Duration {
    fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> Result<Self> {
        let v = decoder.read_interval(tag)?;
        Ok(time::Duration::from_secs(v.into()))
    }
}

#[cfg(feature = "chrono")]
impl TagDecodable for chrono::DateTime<chrono::Utc> {
    fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> Result<Self> {
        let v = decoder.read_datetime(tag)?;
        chrono::DateTime::from_timestamp(v, 0).ok_or(Error::ValueOutOfBound)
    }
}

#[cfg(feature = "chrono")]
impl TagDecodable for chrono::DateTime<chrono::Local> {
    fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> Result<Self> {
        Ok(chrono::DateTime::from(
            <chrono::DateTime<chrono::Utc> as TagDecodable>::decode(tag, decoder)?,
        ))
    }
}

#[cfg(feature = "chrono")]
impl TagDecodable for chrono::DateTime<chrono::FixedOffset> {
    fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> Result<Self> {
        Ok(chrono::DateTime::from(
            <chrono::DateTime<chrono::Utc> as TagDecodable>::decode(tag, decoder)?,
        ))
    }
}

#[cfg(feature = "chrono")]
impl TagDecodable for chrono::Duration {
    fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> Result<Self> {
        let v = decoder.read_interval(tag)?;
        chrono::Duration::new(v.into(), 0).ok_or(Error::ValueOutOfBound)
    }
}

#[cfg(feature = "chrono")]
impl TagDecodable for chrono::NaiveDateTime {
    fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> Result<Self> {
        Ok(<chrono::DateTime<chrono::Utc> as TagDecodable>::decode(tag, decoder)?.naive_utc())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Decodable, Encoder, TagDecodable, TtlvDecoder, TtlvEncoder};
    use std::time;

    fn encode_integer(tag: u32, value: i32) -> Vec<u8> {
        let mut enc = TtlvEncoder::new();
        enc.write_integer(tag, value).unwrap();
        enc.into_inner()
    }

    fn encode_long(tag: u32, value: i64) -> Vec<u8> {
        let mut enc = TtlvEncoder::new();
        enc.write_long(tag, value).unwrap();
        enc.into_inner()
    }

    fn encode_interval(tag: u32, seconds: u32) -> Vec<u8> {
        let mut enc = TtlvEncoder::new();
        enc.write_interval(tag, seconds).unwrap();
        enc.into_inner()
    }

    fn encode_datetime(tag: u32, ts: i64) -> Vec<u8> {
        let mut enc = TtlvEncoder::new();
        enc.write_datetime(tag, ts).unwrap();
        enc.into_inner()
    }

    // -- Option<T> TagDecodable --

    #[test]
    fn test_option_present() {
        let bytes = encode_integer(0x420001, 42);
        let mut dec = TtlvDecoder::new(&bytes);
        let v: Option<i32> = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v, Some(42));
    }

    #[test]
    fn test_option_absent_eof() {
        // Empty buffer → EOF → None
        let mut dec = TtlvDecoder::new(&[]);
        let v: Option<i32> = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v, None);
    }

    #[test]
    fn test_option_absent_wrong_tag() {
        let bytes = encode_integer(0x420002, 99);
        let mut dec = TtlvDecoder::new(&bytes);
        let v: Option<i32> = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v, None);
    }

    // -- Option<T> Decodable (self-tagged) --

    #[test]
    fn test_option_decodable_absent_eof() {
        // TTLV<RawTag> implements Decodable; empty buffer → EOF → None
        use crate::{RawTag, TTLV};
        let mut dec = TtlvDecoder::new(&[]);
        let v: Option<TTLV<RawTag>> = Decodable::decode(&mut dec).unwrap();
        assert!(v.is_none());
    }

    // -- Vec<T> TagDecodable --

    #[test]
    fn test_vec_tag_decodable_empty() {
        let bytes = encode_integer(0x420002, 1); // wrong tag
        let mut dec = TtlvDecoder::new(&bytes);
        let v: Vec<i32> = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v, vec![]);
    }

    #[test]
    fn test_vec_tag_decodable_multiple() {
        let mut enc = TtlvEncoder::new();
        enc.write_integer(0x420001u32, 1).unwrap();
        enc.write_integer(0x420001u32, 2).unwrap();
        enc.write_integer(0x420001u32, 3).unwrap();
        let mut dec = TtlvDecoder::new(enc.bytes());
        let v: Vec<i32> = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v, vec![1, 2, 3]);
    }

    // -- Box<T> Decodable / TagDecodable --

    #[test]
    fn test_box_tag_decodable() {
        let bytes = encode_integer(0x420001, 7);
        let mut dec = TtlvDecoder::new(&bytes);
        let v: Box<i32> = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(*v, 7);
    }

    // -- Primitive integer TagDecodable impls --

    #[test]
    fn test_i8_tag_decodable() {
        let bytes = encode_integer(0x420001, 127);
        let mut dec = TtlvDecoder::new(&bytes);
        let v: i8 = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v, 127);
    }

    #[test]
    fn test_i16_tag_decodable() {
        let bytes = encode_integer(0x420001, 1000);
        let mut dec = TtlvDecoder::new(&bytes);
        let v: i16 = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v, 1000);
    }

    #[test]
    fn test_u16_tag_decodable() {
        let bytes = encode_integer(0x420001, 65535);
        let mut dec = TtlvDecoder::new(&bytes);
        let v: u16 = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v, 65535);
    }

    #[test]
    fn test_u32_tag_decodable_via_long() {
        let bytes = encode_long(0x420001, 4294967295);
        let mut dec = TtlvDecoder::new(&bytes);
        let v: u32 = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v, 4294967295u32);
    }

    // -- time::Duration TagDecodable --

    #[test]
    fn test_duration_tag_decodable() {
        let bytes = encode_interval(0x420001, 3600);
        let mut dec = TtlvDecoder::new(&bytes);
        let v: time::Duration = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v, time::Duration::from_secs(3600));
    }

    // -- chrono TagDecodable impls --

    #[cfg(feature = "chrono")]
    #[test]
    fn test_chrono_datetime_utc_tag_decodable() {
        let ts = 1205495800i64;
        let bytes = encode_datetime(0x420001, ts);
        let mut dec = TtlvDecoder::new(&bytes);
        let v: chrono::DateTime<chrono::Utc> = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v.timestamp(), ts);
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn test_chrono_datetime_utc_out_of_range() {
        let bytes = encode_datetime(0x420001, i64::MAX);
        let mut dec = TtlvDecoder::new(&bytes);
        let err = <chrono::DateTime<chrono::Utc> as TagDecodable>::decode(0x420001u32, &mut dec)
            .unwrap_err();
        assert!(matches!(err, crate::Error::ValueOutOfBound));
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn test_chrono_datetime_local_tag_decodable() {
        let ts = 1205495800i64;
        let bytes = encode_datetime(0x420001, ts);
        let mut dec = TtlvDecoder::new(&bytes);
        let v: chrono::DateTime<chrono::Local> =
            TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v.timestamp(), ts);
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn test_chrono_datetime_fixed_offset_tag_decodable() {
        let ts = 1205495800i64;
        let bytes = encode_datetime(0x420001, ts);
        let mut dec = TtlvDecoder::new(&bytes);
        let v: chrono::DateTime<chrono::FixedOffset> =
            TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v.timestamp(), ts);
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn test_chrono_duration_tag_decodable() {
        let bytes = encode_interval(0x420001, 120);
        let mut dec = TtlvDecoder::new(&bytes);
        let v: chrono::Duration = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v.num_seconds(), 120);
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn test_chrono_naive_datetime_tag_decodable() {
        let ts = 1205495800i64;
        let bytes = encode_datetime(0x420001, ts);
        let mut dec = TtlvDecoder::new(&bytes);
        let v: chrono::NaiveDateTime = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v.and_utc().timestamp(), ts);
    }

    // -- BigInteger TagDecodable --

    #[test]
    fn test_biginteger_tag_decodable() {
        let mut enc = TtlvEncoder::new();
        // write_bigint zero-extends to an 8-byte multiple; [0x01, 0x02] → 8 bytes on wire
        enc.write_bigint(0x420001u32, [0x01, 0x02]).unwrap();
        let mut dec = TtlvDecoder::new(enc.bytes());
        let v: crate::BigInteger = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(&*v, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02]);
    }

    // -- bool TagDecodable --

    #[test]
    fn test_bool_tag_decodable() {
        let mut enc = TtlvEncoder::new();
        enc.write_bool(0x420001u32, true).unwrap();
        let mut dec = TtlvDecoder::new(enc.bytes());
        let v: bool = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert!(v);
    }

    // -- String TagDecodable --

    #[test]
    fn test_string_tag_decodable() {
        let mut enc = TtlvEncoder::new();
        enc.write_string(0x420001u32, "hello").unwrap();
        let mut dec = TtlvDecoder::new(enc.bytes());
        let v: String = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v, "hello");
    }

    // -- Vec<u8> TagDecodable (bytes) --

    #[test]
    fn test_bytes_tag_decodable() {
        let mut enc = TtlvEncoder::new();
        enc.write_bytes(0x420001u32, [0xAB, 0xCD]).unwrap();
        let mut dec = TtlvDecoder::new(enc.bytes());
        let v: Vec<u8> = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
        assert_eq!(v, vec![0xAB, 0xCD]);
    }
}
