#![allow(deprecated)]
use strum_macros::{EnumIs, EnumTryAs};
use ttlv::{
    BigInteger, Decodable, Decoder, Encodable, Error, Expected, MaybeKnownTag, Tag, Type, Value,
};

use crate::{
    Attribute, CertificateType, CryptographicAlgorithm, CryptographicParameters, EncodingOption,
    KeyCompressionType, KeyFormatType, ObjectType, OpaqueDataType, ProtocolVersion,
    RecommendedCurve, SecretDataType, SplitKeyMethod, Tags, TryAsMut, TryAsRef, WrappingMethod,
};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(untagged))]
#[derive(Debug, Clone, PartialEq, Encodable, EnumIs, EnumTryAs)]
#[ttlv(flatten)]
pub enum KeyMaterial {
    Bytes(#[ttlv(tag = Tags::KeyMaterial)] Vec<u8>),
    TransparentSymmetricKey(TransparentSymmetricKey),
    TransparentRSAPrivateKey(TransparentRSAPrivateKey),
    TransparentRSAPublicKey(TransparentRSAPublicKey),
    #[deprecated = "deprecated as of kmip 1.3"]
    TransparentECDSAPrivateKey(TransparentECDSAPrivateKey),
    #[deprecated = "deprecated as of kmip 1.3"]
    TransparentECDSAPublicKey(TransparentECDSAPublicKey),
    TransparentECPrivateKey(TransparentECPrivateKey),
    TransparentECPublicKey(TransparentECPublicKey),
    Other(#[ttlv(tag = Tags::KeyMaterial)] Vec<Value<MaybeKnownTag<Tags>>>),
}

impl KeyMaterial {
    pub fn decode(format: KeyFormatType, decoder: &mut impl ttlv::Decoder) -> ttlv::Result<Self> {
        Ok(match format {
            KeyFormatType::Raw
            | KeyFormatType::Opaque
            | KeyFormatType::PKCS1
            | KeyFormatType::PKCS8
            | KeyFormatType::X509
            | KeyFormatType::ECPrivateKey => Self::Bytes(decoder.tag_decode(Tags::KeyMaterial)?),

            KeyFormatType::TransparentSymmetricKey => {
                Self::TransparentSymmetricKey(decoder.decode()?)
            }
            // KeyFormatType::TransparentDSAPrivateKey => todo!(),
            // KeyFormatType::TransparentDSAPublicKey => todo!(),
            KeyFormatType::TransparentRSAPrivateKey => {
                Self::TransparentRSAPrivateKey(decoder.decode()?)
            }
            KeyFormatType::TransparentRSAPublicKey => {
                Self::TransparentRSAPublicKey(decoder.decode()?)
            }
            // KeyFormatType::TransparentDHPrivateKey => todo!(),
            // KeyFormatType::TransparentDHPublicKey => todo!(),
            KeyFormatType::TransparentECDSAPrivateKey => {
                Self::TransparentECDSAPrivateKey(decoder.decode()?)
            }
            KeyFormatType::TransparentECDSAPublicKey => {
                Self::TransparentECDSAPublicKey(decoder.decode()?)
            }
            // KeyFormatType::TransparentECDHPrivateKey => todo!(),
            // KeyFormatType::TransparentECDHPublicKey => todo!(),
            // KeyFormatType::TransparentECMQVPrivateKey => todo!(),
            // KeyFormatType::TransparentECMQVPublicKey => todo!(),
            _ => Self::Other(decoder.tag_decode(Tags::KeyMaterial)?),
        })
    }
}

impl From<TransparentRSAPublicKey> for KeyMaterial {
    fn from(value: TransparentRSAPublicKey) -> Self {
        Self::TransparentRSAPublicKey(value)
    }
}

impl From<TransparentRSAPrivateKey> for KeyMaterial {
    fn from(value: TransparentRSAPrivateKey) -> Self {
        Self::TransparentRSAPrivateKey(value)
    }
}

impl From<TransparentECPublicKey> for KeyMaterial {
    fn from(value: TransparentECPublicKey) -> Self {
        Self::TransparentECPublicKey(value)
    }
}

impl From<TransparentECPrivateKey> for KeyMaterial {
    fn from(value: TransparentECPrivateKey) -> Self {
        Self::TransparentECPrivateKey(value)
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable)]
pub struct PlainKeyValue {
    pub key_material: KeyMaterial,
    pub attributes: Vec<Attribute>,
}

impl PlainKeyValue {
    pub fn decode(format: KeyFormatType, decoder: &mut impl ttlv::Decoder) -> ttlv::Result<Self> {
        decoder.read_struct(Tags::KeyValue, |decoder| {
            Ok(Self {
                key_material: KeyMaterial::decode(format, decoder)?,
                attributes: decoder.decode()?,
            })
        })
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize),
    serde(untagged)
)]
#[derive(Debug, Clone, PartialEq, Encodable, EnumIs, EnumTryAs)]
#[ttlv(flatten)]
pub enum KeyValue {
    Wrapped(
        #[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))]
        #[ttlv(tag = Tags::KeyValue)]
        Vec<u8>,
    ),
    Plain(#[ttlv(tag = Tags::KeyValue)] PlainKeyValue),
}

impl KeyValue {
    fn decode(format: KeyFormatType, decoder: &mut impl ttlv::Decoder) -> ttlv::Result<Self> {
        match decoder.get_type()? {
            Type::ByteString => Ok(Self::Wrapped(decoder.tag_decode(Tags::KeyValue)?)),
            Type::Structure => Ok(Self::Plain(PlainKeyValue::decode(format, decoder)?)),
            other => Err(Error::UnexpectedType {
                got: other,
                expected: Expected::OneOf(vec![Type::Structure, Type::ByteString]),
                tag: Tags::KeyValue.raw().to_owned(),
            }),
        }
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::KeyWrappingData)]
pub struct KeyWrappingData {
    pub wrapping_method: WrappingMethod,
    pub encryption_key_info: Option<EncryptionKeyInformation>,
    pub mac_signature_key_information: Option<MacSignatureKeyInformation>,
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::MACSignature)]
    pub mac_signature: Option<Vec<u8>>,
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::IVCounterNonce)]
    pub iv_counter_nonce: Option<Vec<u8>>,
    #[ttlv(tag = Tags::EncodingOption, if(_ext.is_in(ProtocolVersion::V1_1..)))]
    pub encoding_option: Option<EncodingOption>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::KeyWrappingSpecification)]
pub struct KeyWrappingSpecification {
    pub wrapping_method: WrappingMethod,
    pub encryption_key_info: Option<EncryptionKeyInformation>,
    pub mac_signature_key_information: Option<MacSignatureKeyInformation>,
    #[ttlv(tag = Tags::AttributeName)]
    pub attribute_name: Vec<String>,
    #[ttlv(tag = Tags::EncodingOption, if(_ext.is_in(ProtocolVersion::V1_1..)))]
    pub encoding_option: Option<EncodingOption>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::EncryptionKeyInformation)]
pub struct EncryptionKeyInformation {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    pub cryptographic_parameters: Option<CryptographicParameters>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::MACSignatureKeyInformation)]
pub struct MacSignatureKeyInformation {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    pub cryptographic_parameters: Option<CryptographicParameters>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable)]
#[ttlv(tag = Tags::KeyBlock)]
pub struct KeyBlock {
    pub key_format_type: KeyFormatType,
    pub key_compression_type: Option<KeyCompressionType>,
    pub key_value: Option<KeyValue>,
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    #[ttlv(tag = Tags::CryptographicLength)]
    pub cryptographic_length: Option<i32>,
    pub key_wrapping_data: Option<KeyWrappingData>,
}

impl KeyBlock {
    pub fn into_plain_material(self) -> Option<KeyMaterial> {
        Some(self.key_value?.try_as_plain()?.key_material)
    }

    pub fn as_plain_material(&self) -> Option<&KeyMaterial> {
        Some(&self.key_value.as_ref()?.try_as_plain_ref()?.key_material)
    }

    pub fn try_as_bytes(&self) -> Option<&[u8]> {
        Some(self.as_plain_material()?.try_as_bytes_ref()?)
    }
}

impl Decodable for KeyBlock {
    fn decode(decoder: &mut impl Decoder) -> ttlv::Result<Self> {
        decoder.read_struct(Tags::KeyBlock, |d| {
            let key_format_type = d.decode()?;
            Ok(Self {
                key_format_type,
                key_compression_type: d.decode()?,
                key_value: if d.tag()?.matches(&Tags::KeyValue) {
                    Some(KeyValue::decode(key_format_type, d)?)
                } else {
                    None
                },
                cryptographic_algorithm: d.decode()?,
                cryptographic_length: d.tag_decode(Tags::CryptographicLength)?,
                key_wrapping_data: d.decode()?,
            })
        })
    }
}

macro_rules! impl_object {
    ($($(#[$meta:meta])* $ident:ident,)*) => {
        #[cfg_attr(feature = "arbitrary", derive(::arbitrary::Arbitrary))]
        #[cfg_attr(feature = "serde", derive(::serde::Serialize), serde(untagged))]
        #[derive(Debug, Clone, PartialEq, Encodable, ::strum_macros::EnumIs, ::strum_macros::EnumTryAs)]
        #[ttlv(flatten)]
        pub enum Object {
            $(
                $(#[$meta])*
                $ident($ident),
            )*
        }

        impl Object {
            pub fn object_type(&self) -> ObjectType {
                match self {
                    $(Self::$ident(_) => ObjectType::$ident,)*
                }
            }
        }

        impl Decodable for Object {
            fn decode(decoder: &mut impl ttlv::Decoder) -> ttlv::Result<Self> {
                match decoder.tag()?.raw().try_into()? {
                    $(Tags::$ident => Ok(Self::$ident(decoder.decode()?)),)*
                    other => Err(Error::UnexpectedTag {
                        got: other.raw().to_owned(),
                        expected: Expected::OneOf(vec![
                            $(Tags::$ident.raw().to_owned(),)*
                        ]),
                    }),
                }
            }
        }

        $(
            impl From<$ident> for Object {
                fn from(o: $ident) -> Self {
                    Self::$ident(o)
                }
            }

            impl TryFrom<Object> for $ident {
                type Error = $crate::UnexpectedObject;
                fn try_from(value: Object) -> Result<Self, Self::Error> {
                    let Object::$ident(obj) = value else {
                        return Err($crate::UnexpectedObject {
                            got: value.object_type(),
                            want: ObjectType::$ident,
                        });
                    };
                    Ok(obj)
                }
            }

            impl <'a> TryFrom<&'a Object> for &'a $ident {
                type Error = $crate::UnexpectedObject;
                fn try_from(value: &'a Object) -> Result<Self, Self::Error> {
                    let Object::$ident(obj) = value else {
                        return Err($crate::UnexpectedObject {
                            got: value.object_type(),
                            want: ObjectType::$ident,
                        });
                    };
                    Ok(obj)
                }
            }

            impl TryAsRef<$ident> for Object {
                fn try_as_ref(&self) -> Option<&$ident> {
                    let Object::$ident(obj) = self else {
                        return None;
                    };
                    Some(obj)
                }
            }

            impl TryAsMut<$ident> for Object {
                fn try_as_mut(&mut self) -> Option<&mut $ident> {
                    let Object::$ident(obj) = self else {
                        return None;
                    };
                    Some(obj)
                }
            }
        )*
    };
}

impl_object! {
    Certificate,
    SymmetricKey,
    PublicKey,
    PrivateKey,
    SecretData,
    SplitKey,
    OpaqueObject,
    #[deprecated = "Templates have been deprecated in KMIP v1.3"]
    Template,
    PGPKey,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::Certificate)]
pub struct Certificate {
    pub certificate_type: CertificateType,
    #[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))]
    #[ttlv(tag = Tags::CertificateValue)]
    pub certificate_value: Vec<u8>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::SecretData)]
pub struct SecretData {
    pub secret_data_type: SecretDataType,
    pub key_block: KeyBlock,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::SymmetricKey)]
pub struct SymmetricKey {
    pub key_block: KeyBlock,
}

impl SymmetricKey {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        let kmat = self.key_block.as_plain_material()?;
        match kmat {
            KeyMaterial::Bytes(bytes) => Some(bytes),
            KeyMaterial::TransparentSymmetricKey(tk) => Some(&tk.key),
            _ => None,
        }
    }

    pub fn into_bytes(self) -> Option<Vec<u8>> {
        let kmat = self.key_block.into_plain_material()?;
        match kmat {
            KeyMaterial::Bytes(bytes) => Some(bytes),
            KeyMaterial::TransparentSymmetricKey(tk) => Some(tk.key),
            _ => None,
        }
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::PublicKey)]
pub struct PublicKey {
    pub key_block: KeyBlock,
}

impl From<KeyBlock> for PublicKey {
    fn from(value: KeyBlock) -> Self {
        Self { key_block: value }
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::PrivateKey)]
pub struct PrivateKey {
    pub key_block: KeyBlock,
}

impl From<KeyBlock> for PrivateKey {
    fn from(value: KeyBlock) -> Self {
        Self { key_block: value }
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::KeyMaterial)]
pub struct TransparentSymmetricKey {
    #[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))]
    #[ttlv(tag = Tags::Key)]
    pub key: Vec<u8>,
}

// pub struct TransparentDSAPublicKey {}

// pub struct TransparentDSAPrivateKey {}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::KeyMaterial)]
pub struct TransparentRSAPublicKey {
    #[ttlv(tag = Tags::Modulus)]
    pub modulus: BigInteger,
    #[ttlv(tag = Tags::PublicExponent)]
    pub public_exponent: BigInteger,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::KeyMaterial)]
pub struct TransparentRSAPrivateKey {
    #[ttlv(tag = Tags::Modulus)]
    pub modulus: BigInteger,
    #[ttlv(tag = Tags::PrivateExponent)]
    pub private_exponent: Option<BigInteger>,
    #[ttlv(tag = Tags::PublicExponent)]
    pub public_exponent: Option<BigInteger>,
    #[ttlv(tag = Tags::P)]
    pub p: Option<BigInteger>,
    #[ttlv(tag = Tags::Q)]
    pub q: Option<BigInteger>,
    #[ttlv(tag = Tags::PrimeExponentP)]
    pub prime_exponent_p: Option<BigInteger>,
    #[ttlv(tag = Tags::PrimeExponentQ)]
    pub prime_exponent_q: Option<BigInteger>,
    #[ttlv(tag = Tags::CRTCoefficient)]
    pub crt_coefficient: Option<BigInteger>,
}

#[deprecated = "deprecated as of kmip 1.3"]
pub type TransparentECDSAPrivateKey = TransparentECPrivateKey;

#[deprecated = "deprecated as of kmip 1.3"]
pub type TransparentECDSAPublicKey = TransparentECPublicKey;

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::KeyMaterial)]
pub struct TransparentECPublicKey {
    pub recommended_curve: RecommendedCurve,
    #[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))]
    #[ttlv(tag = Tags::QString)]
    pub q_string: Vec<u8>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::KeyMaterial)]
pub struct TransparentECPrivateKey {
    pub recommended_curve: RecommendedCurve,
    #[ttlv(tag = Tags::D)]
    pub d: BigInteger,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::SplitKey)]
pub struct SplitKey {
    #[ttlv(tag = Tags::SplitKeyParts)]
    pub split_key_parts: i32,
    #[ttlv(tag = Tags::KeyPartIdentifier)]
    pub key_part_identifier: i32,
    #[ttlv(tag = Tags::SplitKeyThreshold)]
    pub split_key_threshold: i32,
    pub split_key_method: SplitKeyMethod,
    #[ttlv(tag = Tags::PrimeFieldSize)]
    pub prime_field_size: Option<BigInteger>,
    pub key_block: KeyBlock,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::OpaqueObject)]
pub struct OpaqueObject {
    pub opaque_data_type: OpaqueDataType,
    #[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))]
    #[ttlv(tag = Tags::OpaqueDataValue)]
    pub opaque_data_value: Vec<u8>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::Template)]
#[deprecated = "deprecated as of KMIP 1.3"]
pub struct Template {
    pub attribute: Vec<Attribute>,
}

// KMIP 1.2

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::PGPKey)]
pub struct PGPKey {
    #[ttlv(tag = Tags::PGPKeyVersion)]
    pub pgp_key_version: i32,
    pub key_block: KeyBlock,
}
