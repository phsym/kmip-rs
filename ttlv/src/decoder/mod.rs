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
