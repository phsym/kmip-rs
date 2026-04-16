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

#[diagnostic::on_unimplemented(
    message = "The trait `Encodable` is not implemented for `{Self}`",
    note = "You can automatically derive it with `#[derive(ttlv::Encodable)]` and the `#[ttlv(tag = <tag>)]` attribute",
    note = "Or add the attribute `#[ttlv(tag = <tag>)]` on a derived type's field"
)]
pub trait Encodable {
    fn encode(&self, encoder: &mut impl Encoder);
}

#[diagnostic::on_unimplemented(
    message = "The trait `TagEncodable` is not implemented for `{Self}`",
    note = "You can automatically derive it with `#[derive(ttlv::Encodable)]`"
)]
pub trait TagEncodable {
    fn encode<E: Encoder>(&self, tag: impl Tag, encoder: &mut E);
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

pub trait Encoder {
    type StructEncoder<'b>: Encoder;
    fn extensions(&mut self) -> &mut Extensions;
    fn write_struct(&mut self, tag: impl Tag, f: impl FnOnce(&mut Self::StructEncoder<'_>));
    fn write_integer(&mut self, tag: impl Tag, value: i32);
    fn write_long(&mut self, tag: impl Tag, value: i64);
    fn write_bigint(&mut self, _tag: impl Tag, num: impl AsRef<[u8]>);
    fn write_enum(&mut self, tag: impl Tag, value: impl Tag);
    fn write_bool(&mut self, tag: impl Tag, value: bool);
    fn write_string(&mut self, tag: impl Tag, s: impl AsRef<str>);
    fn write_bytes(&mut self, tag: impl Tag, s: impl AsRef<[u8]>);
    fn write_datetime(&mut self, tag: impl Tag, date: i64);
    fn write_interval(&mut self, tag: impl Tag, seconds: u32);
    fn write_bitmask(&mut self, tag: impl Tag, value: impl Bitmask);

    fn encode(&mut self, value: &impl Encodable)
    where
        Self: Sized,
    {
        value.encode(self);
    }

    fn tag_encode(&mut self, tag: impl Tag, value: &impl TagEncodable)
    where
        Self: Sized,
    {
        value.encode(tag, self);
    }
}

impl<T: Encodable> Encodable for Option<T> {
    fn encode(&self, encoder: &mut impl Encoder) {
        if let Some(v) = self {
            v.encode(encoder);
        }
    }
}

impl<T: TagEncodable> TagEncodable for Option<T> {
    fn encode<E: Encoder>(&self, tag: impl Tag, encoder: &mut E) {
        if let Some(v) = self {
            v.encode(tag, encoder);
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
    fn encode(&self, encoder: &mut impl Encoder) {
        for item in self {
            item.encode(encoder);
        }
    }
}

impl<T: TagEncodable> TagEncodable for Vec<T> {
    fn encode<E: Encoder>(&self, tag: impl Tag, encoder: &mut E) {
        for item in self {
            encoder.tag_encode(&tag, item)
        }
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
    fn encode<E: Encoder>(&self, tag: impl Tag, encoder: &mut E) {
        (**self).encode(tag, encoder);
    }
}

impl<T: Encodable> Encodable for Box<T> {
    fn encode(&self, encoder: &mut impl Encoder) {
        (**self).encode(encoder)
    }
}

macro_rules! impl_tag_encodable {
    (<$($ident:ident $(: $tt:path)?), *> $ty:ty, $enc:ident, $expr:expr $(, $cast:ty)?) => {
        impl <$($ident $(: $tt)?), *> TagEncodable for $ty {
            fn encode<E: Encoder>(&self, tag: impl Tag, encoder: &mut E) {
                encoder.$enc(tag, $expr(self) $(as $cast)?); // TODO: Use try_into instead of casting, and return an error
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
