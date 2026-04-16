#[cfg(feature = "xml")]
mod xml;
use task_local_extensions::Extensions;
#[cfg(feature = "xml")]
pub use xml::*;

mod ttlv;
pub use ttlv::*;

use std::time;

use crate::{Bitmask, Error, Result, Tag, Type};

#[diagnostic::on_unimplemented(
    message = "The trait `Decodable` is not implemented for `{Self}`",
    note = "You can automatically derive it with `#[derive(ttlv::Decodable)]` and the `#[ttlv(tag = <tag>)]` attribute",
    note = "Or add the attribute `#[ttlv(tag = <tag>)]` on a derived type's field"
)]
pub trait Decodable: Sized {
    fn decode(decoder: &mut impl Decoder) -> Result<Self>;
}

#[diagnostic::on_unimplemented(
    message = "The trait `TagDecodable` is not implemented for `{Self}`",
    note = "You can automatically derive it with `#[derive(ttlv::Decodable)]`"
)]
pub trait TagDecodable: Sized {
    fn decode<D: Decoder>(tag: impl Tag, decoder: &mut D) -> Result<Self>;
}

pub trait Decoder {
    type StructDecoder<'b>: Decoder<Tag = Self::Tag>;
    type Tag: Tag;

    fn extensions(&mut self) -> &mut Extensions;

    fn tag(&self) -> Result<Self::Tag>;
    fn get_type(&self) -> Result<Type>;

    fn read_struct<T>(
        &mut self,
        tag: impl Tag,
        f: impl FnOnce(&mut Self::StructDecoder<'_>) -> Result<T>,
    ) -> Result<T>;
    fn read_integer(&mut self, tag: impl Tag) -> Result<i32>;
    fn read_long(&mut self, tag: impl Tag) -> Result<i64>;
    fn read_bigint(&mut self, tag: impl Tag) -> Result<Vec<u8>>;
    fn read_enum(&mut self, tag: impl Tag) -> Result<Self::Tag>;
    fn read_bool(&mut self, tag: impl Tag) -> Result<bool>;
    fn read_string(&mut self, tag: impl Tag) -> Result<String>;
    fn read_bytes(&mut self, tag: impl Tag) -> Result<Vec<u8>>;
    fn read_datetime(&mut self, tag: impl Tag) -> Result<i64>;
    fn read_interval(&mut self, tag: impl Tag) -> Result<u32>;

    fn read_bitmask<B: Bitmask>(&mut self, tag: impl Tag) -> Result<B>;

    fn decode<T: Decodable>(&mut self) -> Result<T>
    where
        Self: Sized,
    {
        T::decode(self)
    }

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
