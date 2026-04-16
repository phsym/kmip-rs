mod decoder;
mod encoder;
mod errors;
mod io;
mod tags;
mod types;

use std::{
    borrow::Cow,
    fmt,
    ops::{Deref, DerefMut, RangeBounds},
};

pub use decoder::*;
pub use encoder::*;
pub use errors::*;
pub use io::*;
pub use tags::*;
use task_local_extensions::Extensions;
pub use types::*;

#[cfg(feature = "derive")]
pub use ttlv_derive::*;

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize),
    serde(transparent)
)]
#[repr(transparent)]
pub struct BigInteger(
    #[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))] Vec<u8>,
);

impl BigInteger {
    fn ensure_not_empty(mut bytes: Vec<u8>) -> Vec<u8> {
        if bytes.is_empty() {
            bytes.push(0);
        }
        bytes
    }

    pub fn signed(bytes: Vec<u8>) -> Self {
        let bytes = Self::ensure_not_empty(bytes);
        Self(bytes)
    }

    pub fn unsigned(bytes: Vec<u8>) -> Self {
        let mut bytes = Self::ensure_not_empty(bytes);
        if (bytes[0] >> 7) & 0x01 == 1 {
            bytes.insert(0, 0);
        }
        Self(bytes)
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl Deref for BigInteger {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BigInteger {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub trait ExtensionsExt {
    // fn get_or_default<'a, T: 'static>(&'a self) -> &'a T
    // where
    //     &'a T: Default;
    fn is_in<T: PartialOrd<T> + 'static, R: RangeBounds<T>>(&self, r: R) -> bool;
}

impl ExtensionsExt for Extensions {
    // fn get_or_default<'a, T: 'static>(&'a self) -> &T
    // where
    //     &'a T: Default,
    // {
    //     self.get().unwrap_or_default()
    // }
    fn is_in<T: PartialOrd<T> + 'static, R: RangeBounds<T>>(&self, r: R) -> bool {
        let Some(t) = self.get() else {
            return false;
        };
        r.contains(t)
    }
}

pub enum BitmaskUnit<'a> {
    Named(Cow<'a, str>),
    Unnamed(u32),
}

impl fmt::Display for BitmaskUnit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitmaskUnit::Named(n) => write!(f, "{n}"),
            BitmaskUnit::Unnamed(i) => write!(f, "{i:#010X}"),
        }
    }
}

pub trait Bitmask: Sized {
    fn empty() -> Self;
    fn units(&self) -> impl Iterator<Item = BitmaskUnit<'_>>;
    fn insert_unit(&mut self, unit: BitmaskUnit) -> Result<()>;
    fn value(&self) -> i32;

    fn from_units<'a>(units: impl Iterator<Item = BitmaskUnit<'a>>) -> Result<Self> {
        let mut v = Self::empty();
        for u in units {
            v.insert_unit(u)?;
        }
        Ok(v)
    }

    fn format(&self, sep: &str) -> String {
        self.units()
            .map(|u| u.to_string())
            .enumerate()
            .fold(String::new(), |mut acc, (i, s)| {
                if i > 0 {
                    acc.push_str(sep);
                }
                acc.push_str(&s);
                acc
            })
    }
}

struct BitIter {
    bits: u32,
    i: u32,
}

impl Iterator for BitIter {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        while self.i < u32::BITS {
            let b = self.bits & (0x01 << self.i);
            self.i += 1;
            if b != 0 {
                return Some(b);
            }
        }
        None
    }
}

impl Bitmask for i32 {
    fn empty() -> Self {
        0
    }

    fn units(&self) -> impl Iterator<Item = BitmaskUnit<'_>> {
        BitIter {
            bits: *self as u32,
            i: 0,
        }
        .map(BitmaskUnit::Unnamed)
    }

    fn insert_unit(&mut self, unit: BitmaskUnit) -> Result<()> {
        match unit {
            BitmaskUnit::Named(n) => return Err(Error::InvalidBitmaskValue(n.to_string())),
            BitmaskUnit::Unnamed(i) => *self |= i as i32,
        }
        Ok(())
    }

    fn value(&self) -> i32 {
        *self
    }
}

#[cfg(feature = "bitflags")]
pub trait BitflagMarker: bitflags::Flags<Bits = u32> + Copy {}

#[cfg(feature = "bitflags")]
impl<T: BitflagMarker> Bitmask for T {
    fn empty() -> Self {
        <Self as bitflags::Flags>::empty()
    }

    fn units(&self) -> impl Iterator<Item = BitmaskUnit<'_>> {
        self.iter_names()
            .map(|(n, _)| BitmaskUnit::Named(n.into()))
            .chain(
                BitIter {
                    bits: self.difference(Self::all()).bits(),
                    i: 0,
                }
                .map(BitmaskUnit::Unnamed),
            )
    }

    fn insert_unit(&mut self, unit: BitmaskUnit) -> Result<()> {
        match unit {
            BitmaskUnit::Unnamed(x) => self.insert(Self::from_bits_retain(x)),
            BitmaskUnit::Named(n) => self.insert(
                Self::from_name(n.as_ref())
                    .ok_or_else(|| Error::InvalidBitmaskValue(n.to_string()))?,
            ),
        }
        Ok(())
    }

    fn value(&self) -> i32 {
        self.bits() as i32
    }
}

#[cfg(feature = "bitflags")]
#[macro_export]
macro_rules! bitmask {
    (
        $(#[$outer:meta])*
        $vis:vis struct $BitFlags:ident: $T:ty {
            $(
                $(#[$inner:ident $($args:tt)*])*
                const $Flag:tt = $value:expr;
            )*
        }

        $($t:tt)*
    ) => {
        ::bitflags::bitflags!{
            $(#[$outer])*
            $vis struct $BitFlags: $T {
                $(
                    $(#[$inner $($args)*])*
                    const $Flag = $value;
                )*
            }

            $($t)*
        }

        impl $crate::BitflagMarker for $BitFlags {}

        impl ::std::fmt::Display for $BitFlags {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::bitflags::parser::to_writer(self, f)
            }
        }

        impl $crate::TagEncodable for $BitFlags {
            fn encode<E: $crate::Encoder>(&self, tag: impl $crate::Tag, encoder: &mut E) {
                encoder.write_bitmask(tag, *self)
            }
        }

        impl $crate::TagDecodable for $BitFlags {
            fn decode<D: $crate::Decoder>(tag: impl $crate::Tag, decoder: &mut D) -> $crate::Result<Self> {
                decoder.read_bitmask(tag)
            }
        }
    };
}
