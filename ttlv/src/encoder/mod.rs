#[cfg(feature = "xml")]
mod xml;
use task_local_extensions::Extensions;
#[cfg(feature = "xml")]
pub use xml::*;

mod ttlv;
pub use ttlv::*;
#[cfg(feature = "text")]
mod text;
#[cfg(feature = "text")]
pub use text::*;

use std::{ops::Deref, time};

use crate::{Bitmask, Tag};

/// A type that knows its own TTLV tag and can encode itself.
///
/// Typically derived with `#[derive(Encodable)]` and a `#[ttlv(tag = ...)]`
/// attribute. The dual of [`Decodable`](crate::Decodable).
#[diagnostic::on_unimplemented(
    message = "The trait `Encodable` is not implemented for `{Self}`",
    note = "You can automatically derive it with `#[derive(ttlv::Encodable)]` and the `#[ttlv(tag = <tag>)]` attribute",
    note = "Or add the attribute `#[ttlv(tag = <tag>)]` on a derived type's field"
)]
pub trait Encodable {
    /// Writes this value to `encoder`.
    fn encode(&self, encoder: &mut impl Encoder) -> crate::Result<()>;
}

/// A type that can encode itself once a tag is provided externally.
///
/// The dual of [`TagDecodable`](crate::TagDecodable). Blanket impls on
/// `Option<T>` and `Vec<T>` make absent fields elide and repeated fields
/// expand into successive items.
#[diagnostic::on_unimplemented(
    message = "The trait `TagEncodable` is not implemented for `{Self}`",
    note = "You can automatically derive it with `#[derive(ttlv::Encodable)]`"
)]
pub trait TagEncodable {
    /// Writes this value to `encoder` under `tag`.
    fn encode<E: Encoder>(&self, tag: impl Tag, encoder: &mut E) -> crate::Result<()>;
}

// pub struct JsonEncoder {
//     enc: serde_json::Serializer<Vec<u8>>,
// }

// use serde::{ser::SerializeStruct, Serializer, Deserializer};
// use serde_json::ser::Formatter;
// impl JsonEncoder {
//     pub fn write_integer(&mut self, tag: impl TagTrait, value: i32) {
//         let out = &mut Vec::new();
//         // serde_json::Deserializer::new(read).deserialize_map(visitor)
//         let mut fmt = serde_json::ser::PrettyFormatter::new();

//         fmt.begin_object( out).unwrap();
//         fmt.begin_object_key( out, true).unwrap();
//         fmt.begin_string(out).unwrap();
//         fmt.write_string_fragment(out, "Type").unwrap();
//         fmt.end_string(out).unwrap();
//         fmt.end_object_key(out).unwrap();
//         fmt.begin_object_value(out).unwrap();
//         fmt.write_i32(out, value).unwrap();
//         fmt.end_object_value(out).unwrap();
//         fmt.end_object(out).unwrap();

//         let mut enc = self.enc.serialize_map(None).unwrap();
//         self.enc.
//         enc.serialize_field("Type", "Integer").unwrap();
//         enc.serialize_field("Tag", &tag.into().0).unwrap();
//         enc.serialize_field("Value", &value).unwrap();
//         enc.end().unwrap();
//     }
//     pub fn write_struct(&mut self, tag: impl TagTrait, f: impl FnOnce(&mut Self)) {
//         let mut enc = self.enc.serialize_struct("Value", 3).unwrap();
//         enc.serialize_field("Type", "Integer").unwrap();
//         enc.serialize_field("Tag", &tag.into().0).unwrap();
//         enc.serialize_field("Value", &value).unwrap();
//         self.enc.
//         enc.end().unwrap();
//     }
// }

/// Normalizes a BigInteger byte slice so the wire form is never empty.
pub(crate) fn normalize_bigint(num: &[u8]) -> &[u8] {
    if num.is_empty() { &[0] } else { num }
}

/// Computes the sign-extension padding required to align a BigInteger
/// (interpreted as big-endian two's-complement) to a multiple of 8 bytes
/// per the KMIP wire format.
///
/// Returns `(pad_byte, pad_len, num)`. `num` is the input normalized via
/// [`normalize_bigint`] (never empty). Callers should emit `pad_byte`
/// repeated `pad_len` times (always in `0..8`) followed by `num`.
pub(crate) fn bigint_padding(num: &[u8]) -> (u8, usize, &[u8]) {
    let num = normalize_bigint(num);
    let pad_len = crate::pad_for_len(num.len());
    let pad = if num[0] & 0x80 != 0 { 0xFF } else { 0x00 };
    (pad, pad_len, num)
}

/// Hex-encodes a BigInteger sign-extended to a multiple of 8 bytes, per
/// KMIP Additional Message Encodings v1.0 §6.1.6.6 (BigInteger XML form).
#[cfg(any(feature = "xml", feature = "text"))]
pub(crate) fn bigint_hex(num: &[u8]) -> String {
    let (pad, pad_len, num) = bigint_padding(num);
    debug_assert!(pad_len < crate::ITEM_ALIGN);
    let pad_bytes = [pad; crate::ITEM_ALIGN - 1];
    let mut hex = String::with_capacity((pad_len + num.len()) * 2);
    data_encoding::HEXUPPER.encode_append(&pad_bytes[..pad_len], &mut hex);
    data_encoding::HEXUPPER.encode_append(num, &mut hex);
    hex
}

/// Push-style writer for TTLV values.
///
/// Each `write_*` method emits one item of a specific [`Type`](crate::Type). Implementors
/// include [`TtlvEncoder`](crate::TtlvEncoder) for the binary form,
/// [`XmlEncoder`](crate::XmlEncoder) for the XML form, and
/// [`TextEncoder`](crate::TextEncoder) for the human-readable form.
pub trait Encoder {
    /// Encoder type used inside [`write_struct`](Self::write_struct).
    type StructEncoder<'b>: Encoder;
    /// Returns the contextual extension map carried alongside the encode.
    fn extensions(&mut self) -> &mut Extensions;
    /// Writes a `Structure` item, calling `f` to emit its body.
    fn write_struct(
        &mut self,
        tag: impl Tag,
        f: impl FnOnce(&mut Self::StructEncoder<'_>) -> crate::Result<()>,
    ) -> crate::Result<()>;
    /// Writes an `Integer` item.
    fn write_integer(&mut self, tag: impl Tag, value: i32) -> crate::Result<()>;
    /// Writes a `LongInteger` item.
    fn write_long(&mut self, tag: impl Tag, value: i64) -> crate::Result<()>;
    /// Encodes a BigInteger from a big-endian, two's-complement byte slice.
    ///
    /// An empty `num` is normalized to a single zero byte; the wire form is
    /// never empty.
    fn write_bigint(&mut self, _tag: impl Tag, num: impl AsRef<[u8]>) -> crate::Result<()>;
    /// Writes an `Enumeration` item. `value` is the tag identifying the variant.
    fn write_enum(&mut self, tag: impl Tag, value: impl Tag) -> crate::Result<()>;
    /// Writes a `Boolean` item.
    fn write_bool(&mut self, tag: impl Tag, value: bool) -> crate::Result<()>;
    /// Writes a `TextString` item.
    fn write_string(&mut self, tag: impl Tag, s: impl AsRef<str>) -> crate::Result<()>;
    /// Writes a `ByteString` item.
    fn write_bytes(&mut self, tag: impl Tag, s: impl AsRef<[u8]>) -> crate::Result<()>;
    /// Writes a `DateTime` item from a Unix timestamp in seconds.
    fn write_datetime(&mut self, tag: impl Tag, date: i64) -> crate::Result<()>;
    /// Writes an `Interval` item from a duration in seconds.
    fn write_interval(&mut self, tag: impl Tag, seconds: u32) -> crate::Result<()>;
    /// Writes a [`Bitmask`] as an `Integer` item.
    fn write_bitmask(&mut self, tag: impl Tag, value: impl Bitmask) -> crate::Result<()>;

    /// Encodes an [`Encodable`] value. Equivalent to `value.encode(self)`.
    fn encode(&mut self, value: &impl Encodable) -> crate::Result<()>
    where
        Self: Sized,
    {
        value.encode(self)
    }

    /// Encodes a [`TagEncodable`] value at `tag`. Equivalent to
    /// `value.encode(tag, self)`.
    fn tag_encode(&mut self, tag: impl Tag, value: &impl TagEncodable) -> crate::Result<()>
    where
        Self: Sized,
    {
        value.encode(tag, self)
    }
}

impl<T: Encodable> Encodable for Option<T> {
    fn encode(&self, encoder: &mut impl Encoder) -> crate::Result<()> {
        if let Some(v) = self {
            v.encode(encoder)
        } else {
            Ok(())
        }
    }
}

impl<T: TagEncodable> TagEncodable for Option<T> {
    fn encode<E: Encoder>(&self, tag: impl Tag, encoder: &mut E) -> crate::Result<()> {
        if let Some(v) = self {
            v.encode(tag, encoder)
        } else {
            Ok(())
        }
    }
}

// impl<I, T> Encodable for I
// where
//     T: Encodable,
//     for<'a> &'a I: IntoIterator<Item = &'a T>,
// {
//     fn encode(&self, encoder: &mut impl Encoder) {
//         for item in self {
//             item.encode(encoder);
//         }
//     }
// }

impl<T: Encodable> Encodable for Vec<T> {
    fn encode(&self, encoder: &mut impl Encoder) -> crate::Result<()> {
        self.iter().try_for_each(|item| item.encode(encoder))
    }
}

impl<T: TagEncodable> TagEncodable for Vec<T> {
    fn encode<E: Encoder>(&self, tag: impl Tag, encoder: &mut E) -> crate::Result<()> {
        self.iter()
            .try_for_each(|item| encoder.tag_encode(&tag, item))
    }
}

// impl<I, T> TagEncodable for I
// where
//     T: TagEncodable,
//     for<'a> &'a I: IntoIterator<Item = &'a T>,
// {
//     fn encode<E: Encoder>(&self, tag: impl Tag, encoder: &mut E) {
//         for item in self {
//             item.encode(tag, encoder)
//         }
//     }
// }

impl<T: TagEncodable> TagEncodable for Box<T> {
    fn encode<E: Encoder>(&self, tag: impl Tag, encoder: &mut E) -> crate::Result<()> {
        (**self).encode(tag, encoder)
    }
}

impl<T: Encodable> Encodable for Box<T> {
    fn encode(&self, encoder: &mut impl Encoder) -> crate::Result<()> {
        (**self).encode(encoder)
    }
}

macro_rules! impl_tag_encodable {
    (<$($ident:ident $(: $tt:path)?), *> $ty:ty, $enc:ident, $expr:expr $(, $cast:ty)?) => {
        impl <$($ident $(: $tt)?), *> TagEncodable for $ty {
            fn encode<E: Encoder>(&self, tag: impl Tag, encoder: &mut E) -> crate::Result<()> {
                let v = $expr(self);
                $(
                    let v: $cast = ::std::convert::TryInto::try_into(v)
                        .map_err(|_| crate::Error::ValueOutOfBound)?;
                )?
                encoder.$enc(tag, v)
            }
        }
    };
    (<$($ident:ident: $tt:path), *> $ty:ty, $enc:ident) => {
        impl_tag_encodable!(<$($ident: $tt), *> $ty, $enc, |this: &_| *this, _);
    };
}

macro_rules! impl_integers {
    ($($ty:ty), *) => {
        $(impl_tag_encodable! {<> $ty, write_integer}) *
    };
}

macro_rules! impl_long_integers {
    ($($ty:ty), *) => {
        $(impl_tag_encodable! {<> $ty, write_long}) *
    };
}

impl_integers!(i8, i16, i32, u16);
impl_long_integers!(u32, i64);
impl_tag_encodable!(<> bool, write_bool);
impl_tag_encodable!(<> str, write_string, |this| this);
impl_tag_encodable!(<> String, write_string, |this| this);
impl_tag_encodable!(<> Vec<u8>, write_bytes, |this| this);
impl_tag_encodable!(<> [u8], write_bytes, |this| this);
impl_tag_encodable!(<> crate::BigInteger, write_bigint, Deref::deref);

impl_tag_encodable! {<> time::Duration , write_interval, time::Duration::as_secs, _}

#[cfg(feature = "chrono")]
impl_tag_encodable! {<Tz: chrono::TimeZone> chrono::DateTime<Tz> , write_datetime, chrono::DateTime::timestamp, _}
#[cfg(feature = "chrono")]
impl_tag_encodable! {<> chrono::Duration, write_interval, chrono::Duration::num_seconds, _}
#[cfg(feature = "chrono")]
impl_tag_encodable! {<> chrono::NaiveDateTime, write_datetime, |this: &chrono::NaiveDateTime| this.and_utc().timestamp(), _}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, TtlvEncoder};

    #[test]
    fn test_interval_overflow_yields_error() {
        let mut enc = TtlvEncoder::new();
        let too_long = time::Duration::from_secs(u64::from(u32::MAX) + 1);
        let err = enc.tag_encode(0x420020, &too_long).unwrap_err();
        assert!(matches!(err, Error::ValueOutOfBound));
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn test_negative_chrono_duration_yields_error() {
        let mut enc = TtlvEncoder::new();
        let negative = chrono::Duration::seconds(-1);
        let err = enc.tag_encode(0x420020, &negative).unwrap_err();
        assert!(matches!(err, Error::ValueOutOfBound));
    }
}
