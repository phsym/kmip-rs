use std::{
    fmt::{self},
    hash::Hash,
};

use crate::Error;

impl From<u32> for RawTagRef<'_> {
    fn from(value: u32) -> Self {
        Self::Num(value)
    }
}

impl<'a> From<&'a str> for RawTagRef<'a> {
    fn from(value: &'a str) -> Self {
        Self::Str(value)
    }
}

impl<'a> From<(u32, &'a str)> for RawTagRef<'a> {
    fn from(value: (u32, &'a str)) -> Self {
        Self::NumStr(value.0, value.1)
    }
}

impl<T> From<T> for RawTag
where
    for<'a> RawTagRef<'a>: From<T>,
{
    fn from(value: T) -> Self {
        RawTagRef::from(value).to_owned()
    }
}

/// Owned tag identifier.
///
/// A tag may be:
/// - `Num` — a numeric tag (KMIP encodes tags on 3 bytes; the high byte is
///   zero).
/// - `Str` — a name-only tag, used by the XML codec when no numeric form is
///   known.
/// - `NumStr` — both a numeric tag and its name, kept together so the same
///   value can round-trip through any encoder.
///
/// See [`RawTagRef`] for a borrowing counterpart.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(untagged))]
pub enum RawTag {
    Num(u32),
    Str(String),
    NumStr(u32, String),
}

/// Borrowing counterpart of [`RawTag`].
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RawTagRef<'a> {
    Num(u32),
    Str(&'a str),
    NumStr(u32, &'a str),
}

// impl Default for RawTag {
//     fn default() -> Self {
//         Self::Num(0)
//     }
// }

impl RawTagRef<'_> {
    /// Returns an owned [`RawTag`] holding the same numeric and/or string
    /// identification.
    pub fn to_owned(&self) -> RawTag {
        match self {
            Self::Num(n) => RawTag::Num(*n),
            Self::Str(s) => RawTag::Str(s.to_string()),
            Self::NumStr(n, s) => RawTag::NumStr(*n, s.to_string()),
        }
    }
}

impl RawTag {
    /// Borrows this tag as a [`RawTagRef`].
    pub fn get_ref(&self) -> RawTagRef<'_> {
        match self {
            Self::Num(n) => RawTagRef::Num(*n),
            Self::Str(s) => RawTagRef::Str(s),
            Self::NumStr(n, s) => RawTagRef::NumStr(*n, s),
        }
    }
}

impl fmt::Debug for RawTagRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Num(arg0) => write!(f, "{arg0:#08X}"),
            Self::Str(arg0) => write!(f, "{arg0}"),
            Self::NumStr(arg0, arg1) => write!(f, "{arg1}/{arg0:#08X}"),
        }
    }
}

impl fmt::Display for RawTagRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Num(n) => write!(f, "{n:#08X}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::NumStr(n, s) => write!(f, "{s}/{n:#08X}"),
        }
    }
}

impl fmt::Debug for RawTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.get_ref(), f)
    }
}

impl fmt::Display for RawTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.get_ref(), f)
    }
}

/// Anything that identifies a TTLV tag.
///
/// At least one of [`numeric`](Self::numeric) or [`name`](Self::name) must
/// return `Some`. The binary [`Encoder`](crate::Encoder) requires a numeric
/// form; the XML and text encoders prefer a name and fall back to the numeric
/// form rendered as `0xXXXXXX`.
///
/// Common implementations are provided for `u32` (numeric only), `&str` (name
/// only), and `(u32, &str)` (both), as well as for derived tag types.
pub trait Tag {
    /// Returns the numeric form of the tag, if known.
    fn numeric(&self) -> Option<u32>;
    /// Returns the textual name of the tag, if known.
    fn name(&self) -> Option<&str>;
    /// Borrows the tag as a [`RawTagRef`].
    ///
    /// # Panics
    ///
    /// Panics if both [`numeric`](Self::numeric) and [`name`](Self::name)
    /// return `None` — at least one form must be available.
    fn raw(&self) -> RawTagRef<'_> {
        match (self.numeric(), self.name()) {
            (Some(n), Some(s)) => RawTagRef::NumStr(n, s),
            (Some(n), None) => RawTagRef::Num(n),
            (None, Some(s)) => RawTagRef::Str(s),
            (None, None) => {
                panic!("Tag::raw called on a tag with neither a numeric nor a name form")
            }
        }
    }
    /// Returns whether two tags identify the same item.
    ///
    /// Tags match by numeric value when both have one; otherwise by name.
    /// Tags lacking a comparable form on both sides do not match.
    fn matches(&self, other: &impl Tag) -> bool {
        match (self.numeric(), other.numeric()) {
            (Some(a), Some(b)) => a == b,
            _ => match (self.name(), other.name()) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            },
        }
    }
    /// Returns the numeric form of the tag or [`Error::TagMissingNumeric`]
    /// when only a name is available. Used by encoders that need a numeric
    /// tag for the wire format.
    fn numeric_or_err(&self) -> crate::Result<u32> {
        self.numeric().ok_or_else(|| Error::TagMissingNumeric {
            tag: self.raw().to_owned(),
        })
    }
}

impl<T: Tag> Tag for &T {
    fn numeric(&self) -> Option<u32> {
        (*self).numeric()
    }

    fn name(&self) -> Option<&str> {
        (*self).name()
    }
}

impl Tag for RawTagRef<'_> {
    fn numeric(&self) -> Option<u32> {
        match self {
            Self::Num(n) | Self::NumStr(n, ..) => Some(*n),
            _ => None,
        }
    }

    fn name(&self) -> Option<&str> {
        match self {
            Self::Str(s) | Self::NumStr(.., s) => Some(s),
            _ => None,
        }
    }

    fn raw(&self) -> RawTagRef<'_> {
        self.clone()
    }
}

impl Tag for RawTag {
    fn numeric(&self) -> Option<u32> {
        self.get_ref().numeric()
    }

    fn name(&self) -> Option<&str> {
        match self {
            Self::Str(s) | Self::NumStr(.., s) => Some(s),
            _ => None,
        }
    }

    fn raw(&self) -> RawTagRef<'_> {
        self.get_ref()
    }
}

impl Tag for u32 {
    fn numeric(&self) -> Option<u32> {
        Some(*self)
    }

    fn name(&self) -> Option<&str> {
        None
    }
}

impl Tag for &str {
    fn numeric(&self) -> Option<u32> {
        None
    }

    fn name(&self) -> Option<&str> {
        Some(self)
    }
}

impl Tag for (u32, &str) {
    fn numeric(&self) -> Option<u32> {
        Some(self.0)
    }

    fn name(&self) -> Option<&str> {
        Some(self.1)
    }
}

impl Tag for (u32, Option<&str>) {
    fn numeric(&self) -> Option<u32> {
        Some(self.0)
    }

    fn name(&self) -> Option<&str> {
        self.1
    }
}

// impl TryFrom<RawTag> for u32 {
//     type Error = Error;

//     fn try_from(value: RawTag) -> Result<Self, Self::Error> {
//         match value {
//             RawTag::Num(n) | RawTag::NumStr(n, _) => Ok(n),
//             _ => Err(Error::InvalidTag(value)),
//         }
//     }
// }

// impl TryFrom<RawTag> for &str {
//     type Error = Error;

//     fn try_from(value: RawTag) -> Result<Self, Self::Error> {
//         todo!()
//     }
// }
/// Tag that may or may not match a known variant of `T`.
///
/// Useful when decoding values whose tag set is open-ended: a known tag is
/// kept in its strongly-typed form, while unknown tags are preserved as a
/// [`RawTag`] so they can still be re-encoded faithfully.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(untagged))]
#[derive(Debug, Clone, PartialEq)]
pub enum MaybeKnownTag<T: Tag> {
    Known(T),
    Unknown(RawTag),
}

impl<T: Tag> Tag for MaybeKnownTag<T> {
    fn numeric(&self) -> Option<u32> {
        match self {
            MaybeKnownTag::Known(t) => t.numeric(),
            MaybeKnownTag::Unknown(t) => t.numeric(),
        }
    }

    fn name(&self) -> Option<&str> {
        match self {
            MaybeKnownTag::Known(t) => t.name(),
            MaybeKnownTag::Unknown(t) => t.name(),
        }
    }
}

impl<T: Tag + TryFrom<RawTag, Error = Error>> TryFrom<RawTag> for MaybeKnownTag<T> {
    type Error = Error;
    fn try_from(value: RawTag) -> Result<Self, Self::Error> {
        match T::try_from(value) {
            Ok(v) => Ok(Self::Known(v)),
            Err(Error::InvalidTag(raw)) => Ok(Self::Unknown(raw)),
            Err(e) => Err(e),
        }
    }
}
