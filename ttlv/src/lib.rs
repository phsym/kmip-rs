#![doc = include_str!("../README.md")]

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

/// KMIP wire-format item alignment, in bytes.
pub(crate) const ITEM_ALIGN: usize = 8;

/// Bytes of zero-padding needed to round `len` up to [`ITEM_ALIGN`].
pub(crate) const fn pad_for_len(len: usize) -> usize {
    (ITEM_ALIGN - len % ITEM_ALIGN) % ITEM_ALIGN
}

/// Arbitrary-precision integer in KMIP TTLV form.
///
/// The wire representation is a big-endian, two's-complement byte string. This
/// type stores the integer's bytes and guarantees they are never empty.
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

    /// Builds a `BigInteger` from a big-endian, two's-complement byte slice.
    ///
    /// The high bit of `bytes[0]` is interpreted as the sign bit. An empty
    /// input is normalized to a single zero byte.
    pub fn signed(bytes: Vec<u8>) -> Self {
        let bytes = Self::ensure_not_empty(bytes);
        Self(bytes)
    }

    /// Builds a `BigInteger` from a big-endian unsigned magnitude.
    ///
    /// A leading `0x00` byte is prepended when the high bit is set, so that
    /// the value is never reinterpreted as negative under two's-complement.
    pub fn unsigned(bytes: Vec<u8>) -> Self {
        let mut bytes = Self::ensure_not_empty(bytes);
        if (bytes[0] >> 7) & 0x01 == 1 {
            bytes.insert(0, 0);
        }
        Self(bytes)
    }

    /// Consumes the `BigInteger` and returns the underlying bytes.
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

/// Convenience methods on the [`Extensions`] map carried by encoders and
/// decoders. Extensions let callers thread context (for example the
/// negotiated protocol version) through encode/decode without changing
/// trait signatures.
pub trait ExtensionsExt {
    // fn get_or_default<'a, T: 'static>(&'a self) -> &'a T
    // where
    //     &'a T: Default;
    /// Returns whether an extension of type `T` is present and falls within
    /// the given range. Returns `false` if no value of type `T` has been set.
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

/// One bit (or named flag) in a [`Bitmask`] value.
///
/// `Named` is used by encoders that have access to flag names (for example
/// XML and text); `Unnamed` carries a raw bit pattern when no name is known.
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

/// A flag set encodable as a TTLV `Integer`.
///
/// The blanket impl on `i32` accepts unnamed bits only. The `bitflags` impl
/// (feature `bitflags`) accepts both named flags and arbitrary bits, allowing
/// round-trips through the XML and text codecs which use flag names.
pub trait Bitmask: Sized {
    /// Returns an empty bitmask.
    fn empty() -> Self;
    /// Iterates over the set bits, yielding their names where available.
    fn units(&self) -> impl Iterator<Item = BitmaskUnit<'_>>;
    /// Inserts a flag, identified by name or by raw bit value.
    ///
    /// Returns [`Error::InvalidBitmaskValue`] if `unit` is unrecognized.
    fn insert_unit(&mut self, unit: BitmaskUnit) -> Result<()>;
    /// Returns the bitmask as a signed 32-bit integer (the wire form).
    fn value(&self) -> i32;

    /// Builds a bitmask from an iterator of [`BitmaskUnit`]s.
    fn from_units<'a>(units: impl Iterator<Item = BitmaskUnit<'a>>) -> Result<Self> {
        let mut v = Self::empty();
        for u in units {
            v.insert_unit(u)?;
        }
        Ok(v)
    }

    /// Joins the set flags into a string with `sep` between units. Used by
    /// the text encoder to render expressions like `"Encrypt | Decrypt"`.
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

/// Marker trait that opts a `bitflags`-generated type into [`Bitmask`].
///
/// Implemented for you by the [`bitmask!`] macro.
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

/// Declares a `bitflags` flag set wired up for TTLV encoding.
///
/// Mirrors [`bitflags::bitflags!`] syntax and additionally implements
/// [`Bitmask`], [`TagEncodable`], [`TagDecodable`], and `Display` (using the
/// `bitflags` parser format). The underlying storage must be `u32`.
///
/// # Example
///
/// ```
/// ttlv::bitmask! {
///     #[derive(Clone, Copy, PartialEq, Debug)]
///     pub struct UsageMask: u32 {
///         const Encrypt = 0x0000_0004;
///         const Decrypt = 0x0000_0008;
///     }
/// }
/// ```
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
            fn encode<E: $crate::Encoder>(&self, tag: impl $crate::Tag, encoder: &mut E) -> $crate::Result<()> {
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
