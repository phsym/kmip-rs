#![allow(deprecated)]

use chrono::{DateTime, Duration, Local};
use ttlv::{Decodable, Decoder, Encodable, Encoder, MaybeKnownTag, Value};

use crate::{
    Tags, TryAsMut, TryAsRef,
    bitmasks::CryptographicUsageMask,
    enums::{
        CertificateType, CryptographicAlgorithm, DigitalSignatureAlgorithm, ObjectType, State,
    },
    types::{
        AlternativeName, ApplicationSpecificInformation, CertificateIdentifier, CertificateIssuer,
        CertificateSubject, CryptographicDomainParameters, CryptographicParameters, Digest,
        KeyValueLocation, Link, Name, RNGParameters, RevocationReason, UsageLimits,
        X509CertificateIdentifier, X509CertificateIssuer, X509CertificateSubject,
    },
};

pub trait AttributeType: Into<AttributeValue> + 'static {
    const NAME: AttributeName;
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("unexpected attribute type")]
pub struct AttributeError;

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable)]
#[ttlv(tag = Tags::Attribute)]
pub struct Attribute {
    #[ttlv(tag = Tags::AttributeName)]
    pub name: String,
    #[ttlv(tag = Tags::AttributeIndex)]
    pub index: Option<i32>,
    pub value: AttributeValue,
}

impl<A: Into<AttributeValue>> From<A> for Attribute {
    fn from(value: A) -> Self {
        Self::new(value)
    }
}

impl Attribute {
    pub fn new(value: impl Into<AttributeValue>) -> Self {
        let value = value.into();
        Self {
            name: value.name().to_string(),
            index: None,
            value,
        }
    }

    pub fn new_indexed(idx: i32, value: impl Into<AttributeValue>) -> Self {
        let value = value.into();
        Self {
            name: value.name().to_string(),
            index: Some(idx),
            value,
        }
    }
}

macro_rules! impl_attributes {
    ($($(#[$meta:meta])* $ident:ident($val:ty) => $name:literal, ) *) => {

        #[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
        pub enum AttributeName {
            $(
                $(#[$meta])*
                $ident,
            ) *
            Unknown(String)
        }

        impl AttributeName {
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$ident => $name, )*
                    Self::Unknown(name) => name
                }
            }
        }

        impl AttributeName {
            pub const ALL: &[Self] = &[$(Self::$ident), *];
        }

        impl From<AttributeName> for String {
            fn from(attr: AttributeName) -> Self {
                match attr {
                    $(AttributeName::$ident => $name.to_string(), )*
                    AttributeName::Unknown(name) => name
                }
            }
        }

        impl From<String> for AttributeName {
            fn from(value: String) -> Self {
                value.as_str().into()
            }
        }

        impl From<&str> for AttributeName {
            fn from(value: &str) -> Self {
                match value {
                    $($name => Self::$ident,) *
                    other => Self::Unknown(other.to_string())
                }
            }
        }

        impl std::fmt::Display for AttributeName {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.as_str().fmt(f)
            }
        }

        impl std::str::FromStr for AttributeName {
            type Err=std::convert::Infallible;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(s.into())
            }
        }

        #[cfg_attr(feature = "arbitrary", derive(::arbitrary::Arbitrary))]
        #[cfg_attr(feature="serde", derive(::serde::Serialize), serde(untagged))]
        #[derive(Debug, Clone, PartialEq, ::strum_macros::EnumIs, ::strum_macros::EnumTryAs)]
        pub enum AttributeValue {
            $(
                $(#[$meta])*
                $ident($val),
            )*
            Unknown {
                name: String,
                value: Value<MaybeKnownTag<Tags>>,
            },
        }

        impl AttributeValue {
            pub fn name(&self) -> &str {
                match self {
                    $(Self::$ident(..) => $name,)*
                    Self::Unknown{name, ..} => name
                }
            }
        }

        $(
            impl AttributeType for $val {
                const NAME: AttributeName = AttributeName::$ident;
            }

            impl From<$val> for AttributeValue {
                fn from(value: $val) -> Self {
                    Self::$ident(value)
                }
            }

            impl TryFrom<AttributeValue> for $val {
                type Error = AttributeError;
                fn try_from(value: AttributeValue) -> std::result::Result<Self, Self::Error> {
                    let AttributeValue::$ident(v) = value else {
                        return Err(AttributeError);
                    };
                    Ok(v)
                }
            }

            impl TryAsRef<$val> for AttributeValue {
                fn try_as_ref(&self) -> Option<&$val> {
                    let AttributeValue::$ident(v) = self else {
                        return None;
                    };
                    Some(v)
                }
            }

            impl TryAsMut<$val> for AttributeValue {
                fn try_as_mut(&mut self) -> Option<&mut $val> {
                    let AttributeValue::$ident(v) = self else {
                        return None;
                    };
                    Some(v)
                }
            }
        )*

        impl Encodable for AttributeValue {
            fn encode(&self, encoder: &mut impl Encoder) -> ttlv::Result<()> {
                match self {
                    $(
                        Self::$ident(value) => encoder.tag_encode(Tags::AttributeValue, value),
                    )*
                    Self::Unknown { value, .. } => encoder.tag_encode(Tags::AttributeValue, value),
                }
            }
        }

        impl Decodable for Attribute {
            fn decode(decoder: &mut impl Decoder) -> ttlv::Result<Self> {
                decoder.read_struct(Tags::Attribute, |decoder| {
                    let name: String = decoder.tag_decode(Tags::AttributeName)?;
                    let index = decoder.tag_decode(Tags::AttributeIndex)?;
                    let value = match &name[..] {
                        $(
                            $name => AttributeValue::$ident(decoder.tag_decode(Tags::AttributeValue)?),
                        )*
                        _ => AttributeValue::Unknown {
                            name: name.clone(),
                            value: decoder.tag_decode(Tags::AttributeValue)?,
                        },
                    };
                    Ok(Self { name, index, value })
                })
            }
        }
    };
}

//TODO: Implement partial attribute structs to be used in locate requests
impl_attributes!(
    UniqueIdentifier(UniqueIdentifier) => "Unique Identifier",
    Name(Name) => "Name",
    ObjectType(ObjectType) => "Object Type",
    CryptographicAlgorithm(CryptographicAlgorithm) => "Cryptographic Algorithm",
    CryptographicLength(CryptographicLength) => "Cryptographic Length",
    CryptographicParameters(CryptographicParameters) => "Cryptographic Parameters",
    CryptographicDomainParameters(CryptographicDomainParameters) => "Cryptographic Domain Parameters",
    CertificateType(CertificateType) => "Certificate Type",
    #[deprecated = "deprecated as of kmip 1.1"] CertificateIdentifier(CertificateIdentifier) => "Certificate Identifier",
    #[deprecated = "deprecated as of kmip 1.1"] CertificateSubject(CertificateSubject) => "Certificate Subject",
    #[deprecated = "deprecated as of kmip 1.1"] CertificateIssuer(CertificateIssuer) => "Certificate Issuer",
    Digest(Digest) => "Digest",
    #[deprecated = "deprecated as of kmip 1.3"] OperationPolicyName(OperationPolicyName) => "Operation Policy Name",
    CryptographicUsageMask(CryptographicUsageMask) => "Cryptographic Usage Mask",
    LeaseTime(LeaseTime) => "Lease Time",
    UsageLimits(UsageLimits) => "Usage Limits",
    State(State) => "State",
    InitialDate(InitialDate) => "Initial Date",
    ActivationDate(ActivationDate) => "Activation Date",
    ProcessStartDate(ProcessStartDate) => "Process Start Date",
    ProtectStopDate(ProtectStopDate) => "Protect Stop Date",
    DeactivationDate(DeactivationDate) => "Deactivation Date",
    DestroyDate(DestroyDate) => "Destroy Date",
    CompromiseOccurrenceDate(CompromiseOccurrenceDate) => "Compromise Occurrence Date",
    CompromiseDate(CompromiseDate) => "Compromise Date",
    RevocationReason(RevocationReason) => "Revocation Reason",
    ArchiveDate(ArchiveDate) => "Archive Date",
    ObjectGroup(ObjectGroup) => "Object Group",
    Link(Link) => "Link",
    ApplicationSpecificInformation(ApplicationSpecificInformation) => "Application Specific Information",
    ContactInformation(ContactInformation) => "Contact Information",
    LastChangeDate(LastChangeDate) => "Last Change Date",

    // KMIP 1.1
    CertificateLength(CertificateLength) => "Certificate Length",
    Fresh(Fresh) => "Fresh",
    X509CertificateIdentifier(X509CertificateIdentifier) => "X.509 Certificate Identifier",
    X509CertificateSubject(X509CertificateSubject) => "X.509 Certificate Subject",
    X509CertificateIssuer(X509CertificateIssuer) => "X.509 Certificate Issuer",
    DigitalSignatureAlgorithm(DigitalSignatureAlgorithm) => "Digital Signature Algorithm",

    // KMIP 1.2
    AlternativeName(AlternativeName) => "Alternative Name",
    KeyValuePresent(KeyValuePresent) => "Key Value Present",
    KeyValueLocation(KeyValueLocation) => "Key Value Location",
    OriginalCreationDate(OriginalCreationDate) => "Original Creation Date",

    // KMIP 1.3
    RandomNumberGenerator(RNGParameters) => "Random Number Generator",

    // KMIP 1.4
    PKCS12FriendlyName(PKCS12FriendlyName) => "PKCS#12 Friendly Name",
    Description(Description) => "Description",
    Comment(Comment) => "Comment",
    Sensitive(Sensitive) => "Sensitive",
    AlwaysSensitive(AlwaysSensitive) => "Always Sensitive",
    Extractable(Extractable) => "Extractable",
    NeverExtractable(NeverExtractable) => "Never Extractable",
);

pub trait AttributesExt {
    fn iter_by_name(&self, name: AttributeName) -> impl Iterator<Item = &Attribute>;

    fn iter_typed<T: AttributeType>(&self) -> impl Iterator<Item = (Option<i32>, &T)>
    where
        AttributeValue: TryAsRef<T>,
    {
        self.iter_by_name(T::NAME)
            .flat_map(|a| a.value.try_as_ref().map(|v| (a.index, v)))
    }

    fn find_by_name(&self, name: AttributeName, index: i32) -> Option<&AttributeValue> {
        self.iter_by_name(name)
            .find(|a| a.index.unwrap_or_default() == index)
            .map(|a| &a.value)
    }

    fn find<T: AttributeType>(&self, index: i32) -> Option<&T>
    where
        AttributeValue: TryAsRef<T>,
    {
        self.find_by_name(T::NAME, index)?.try_as_ref()
    }
}

impl<T> AttributesExt for T
where
    for<'a> &'a T: IntoIterator<Item = &'a Attribute>,
{
    fn iter_by_name(&self, name: AttributeName) -> impl Iterator<Item = &Attribute> {
        self.into_iter().filter(move |a| a.name == name.as_str())
    }
}

macro_rules! wrap_specific {
    ($ident:ident(DateTime<Local>) ) => {
        impl $ident {
            pub fn now() -> Self {
                Self(Local::now())
            }
        }
    };
    ($ident:ident($($ty:tt)*)) => {};
}

macro_rules! wrap_attr_type {
    ($($(#[$meta:meta])* $ident:ident($($ty:tt)*)), *) => {
        $(
            #[repr(transparent)]
            #[cfg_attr(feature = "arbitrary", derive(::arbitrary::Arbitrary))]
            #[cfg_attr(feature="serde", derive(::serde::Serialize), serde(transparent))]
            #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, ttlv::Encodable, ttlv::Decodable)]
            #[ttlv(flatten)]
            $(#[$meta])*
            pub struct $ident(#[ttlv(tag = Tags::$ident)] pub $($ty)*);

            wrap_specific!($ident($($ty)*));

            impl std::ops::Deref for $ident {
                type Target = $($ty)*;

                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }

            impl std::ops::DerefMut for $ident {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut self.0
                }
            }

            impl From<$($ty)*> for $ident {
                fn from(value: $($ty)*) -> Self {
                    Self(value)
                }
            }

            impl From<$ident> for $($ty)* {
                fn from(value: $ident) -> Self {
                    value.0
                }
            }

            impl AsRef<$($ty)*> for $ident {
                fn as_ref(&self) -> &$($ty)* {
                    &self.0
                }
            }

            impl AsMut<$($ty)*> for $ident {
                fn as_mut(&mut self) -> &mut $($ty)* {
                    &mut self.0
                }
            }

            impl ttlv::TagEncodable for $ident {
                fn encode<E: Encoder>(&self, tag: impl ttlv::Tag, encoder: &mut E) -> ttlv::Result<()> {
                    encoder.tag_encode(tag, &self.0)
                }
            }

            impl ttlv::TagDecodable for $ident {
                fn decode<D: Decoder>(tag: impl ttlv::Tag, decoder: &mut D) -> ttlv::Result<Self> {
                   Ok(Self(decoder.tag_decode(tag)?))
                }
            }

            impl std::fmt::Display for $ident {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    self.0.fmt(f)
                }
            }

            impl std::fmt::Debug for $ident {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    self.0.fmt(f)
                }
            }
        )*
    };
}

wrap_attr_type! {
    UniqueIdentifier(String),
    CryptographicLength(i32),
    #[deprecated = "deprecated as of kmip 1.3"]
    OperationPolicyName(String),
    LeaseTime(Duration),
    InitialDate(DateTime<Local>),
    ActivationDate(DateTime<Local>),
    ProcessStartDate(DateTime<Local>),
    ProtectStopDate(DateTime<Local>),
    DeactivationDate(DateTime<Local>),
    DestroyDate(DateTime<Local>),
    CompromiseOccurrenceDate(DateTime<Local>),
    CompromiseDate(DateTime<Local>),
    ArchiveDate(DateTime<Local>),
    ObjectGroup(String),
    ContactInformation(String),
    LastChangeDate(DateTime<Local>),
    CertificateLength(i32),
    Fresh(bool),
    KeyValuePresent(bool),
    OriginalCreationDate(DateTime<Local>),
    PKCS12FriendlyName(String),
    Description(String),
    Comment(String),
    Sensitive(bool),
    AlwaysSensitive(bool),
    Extractable(bool),
    NeverExtractable(bool)
}
