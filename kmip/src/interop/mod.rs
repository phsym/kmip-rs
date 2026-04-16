use crate::{
    CryptographicAlgorithm, KeyBlock, KeyCompressionType, KeyFormatType, KeyMaterial, KeyValue,
    Object, PlainKeyValue, ProtocolVersion,
};

#[cfg(feature = "interop-openssl")]
mod openssl;

#[cfg(feature = "interop-boring")]
mod boring;

mod crypto;

pub type KeyError = Box<dyn std::error::Error>;

pub trait ToObject<O: Into<Object>> {
    type Format;

    fn to_kmip_object(&self, format: Self::Format, vers: ProtocolVersion) -> Result<O, KeyError>;
}

pub trait FromObject<O: TryFrom<Object>>: Sized {
    fn from_kmip_object(object: Object) -> Result<Self, KeyError>;
}

pub trait ToKeyMaterial<O> {
    const ALGORITHM: CryptographicAlgorithm;
    const KEY_COMPRESSION: Option<KeyCompressionType> = None;
    type Format;

    fn to_material(&self, format: Self::Format) -> Result<KeyMaterial, KeyError>;
    fn cryptographic_length(&self) -> i32;
}

impl<O, T> ToObject<O> for T
where
    O: Into<Object> + From<KeyBlock>,
    T: ToKeyMaterial<O>,
    T::Format: Into<KeyFormatType> + Copy,
{
    type Format = T::Format;
    fn to_kmip_object(&self, format: Self::Format, vers: ProtocolVersion) -> Result<O, KeyError> {
        let mut alg = Self::ALGORITHM;
        let mut material = self.to_material(format)?;
        let mut format = format.into();
        if vers < ProtocolVersion::V1_3 {
            if alg == CryptographicAlgorithm::ECDSA {
                alg = CryptographicAlgorithm::EC;
            }
            #[allow(deprecated, reason = "legacy support")]
            match material {
                KeyMaterial::TransparentECPrivateKey(eckey) => {
                    material = KeyMaterial::TransparentECDSAPrivateKey(eckey);
                    format = KeyFormatType::TransparentECDSAPrivateKey;
                }
                KeyMaterial::TransparentECPublicKey(eckey) => {
                    material = KeyMaterial::TransparentECDSAPublicKey(eckey);
                    format = KeyFormatType::TransparentECDSAPublicKey;
                }
                _ => {}
            }
        }
        Ok(KeyBlock {
            key_format_type: format,
            key_compression_type: Self::KEY_COMPRESSION,
            cryptographic_algorithm: Some(alg),
            cryptographic_length: Some(self.cryptographic_length()),
            key_wrapping_data: None,
            key_value: Some(KeyValue::Plain(PlainKeyValue {
                attributes: vec![],
                key_material: material,
            })),
        }
        .into())
    }
}

impl<O: Into<Object>, K: ToKeyMaterial<O>> ToKeyMaterial<O> for &K {
    const ALGORITHM: CryptographicAlgorithm = K::ALGORITHM;
    const KEY_COMPRESSION: Option<KeyCompressionType> = K::KEY_COMPRESSION;
    type Format = K::Format;

    fn to_material(&self, format: Self::Format) -> Result<KeyMaterial, KeyError> {
        (*self).to_material(format)
    }

    fn cryptographic_length(&self) -> i32 {
        (*self).cryptographic_length()
    }
}

#[derive(Clone, Copy)]
pub enum FormatSymmetric {
    Raw,
    Transparent,
}

impl From<FormatSymmetric> for KeyFormatType {
    fn from(value: FormatSymmetric) -> Self {
        match value {
            FormatSymmetric::Raw => Self::Raw,
            FormatSymmetric::Transparent => Self::TransparentSymmetricKey,
        }
    }
}

#[derive(Clone, Copy)]
pub enum FormatRsaPrivate {
    PKCS1,
    PKCS8,
    Transparent,
}

impl From<FormatRsaPrivate> for KeyFormatType {
    fn from(value: FormatRsaPrivate) -> Self {
        match value {
            FormatRsaPrivate::PKCS1 => Self::PKCS1,
            FormatRsaPrivate::PKCS8 => Self::PKCS8,
            FormatRsaPrivate::Transparent => Self::TransparentRSAPrivateKey,
        }
    }
}

#[derive(Clone, Copy)]
pub enum FormatRsaPublic {
    PKCS1,
    X509,
    Transparent,
}

impl From<FormatRsaPublic> for KeyFormatType {
    fn from(value: FormatRsaPublic) -> Self {
        match value {
            FormatRsaPublic::PKCS1 => Self::PKCS1,
            FormatRsaPublic::X509 => Self::X509,
            FormatRsaPublic::Transparent => Self::TransparentRSAPublicKey,
        }
    }
}

#[derive(Clone, Copy)]
pub enum FormatEcPrivate {
    SEC1,
    PKCS8,
    Transparent,
}

impl From<FormatEcPrivate> for KeyFormatType {
    fn from(value: FormatEcPrivate) -> Self {
        match value {
            FormatEcPrivate::SEC1 => Self::ECPrivateKey,
            FormatEcPrivate::PKCS8 => Self::PKCS8,
            FormatEcPrivate::Transparent => Self::TransparentECPrivateKey,
        }
    }
}

#[derive(Clone, Copy)]
pub enum FormatEcPublic {
    X509,
    Transparent,
}

impl From<FormatEcPublic> for KeyFormatType {
    fn from(value: FormatEcPublic) -> Self {
        match value {
            FormatEcPublic::X509 => Self::X509,
            FormatEcPublic::Transparent => Self::TransparentECPublicKey,
        }
    }
}

pub enum FormatPrivate {
    /// SEC1 for EC keys, or PKCS1 for RSA keys
    DER,
    PKCS8,
    Transparent,
}

pub enum FormatPublic {
    /// PKCS1 for RSA keys, fallbacks to X509 for EC keys
    DER,
    /// SPKI format
    X509,
    Transparent,
}

impl From<FormatPrivate> for FormatEcPrivate {
    fn from(value: FormatPrivate) -> Self {
        match value {
            FormatPrivate::DER => Self::SEC1,
            FormatPrivate::PKCS8 => Self::PKCS8,
            FormatPrivate::Transparent => Self::Transparent,
        }
    }
}

impl From<FormatPrivate> for FormatRsaPrivate {
    fn from(value: FormatPrivate) -> Self {
        match value {
            FormatPrivate::DER => Self::PKCS1,
            FormatPrivate::PKCS8 => Self::PKCS8,
            FormatPrivate::Transparent => Self::Transparent,
        }
    }
}

impl From<FormatPublic> for FormatEcPublic {
    fn from(value: FormatPublic) -> Self {
        match value {
            FormatPublic::DER | FormatPublic::X509 => Self::X509,
            FormatPublic::Transparent => Self::Transparent,
        }
    }
}

impl From<FormatPublic> for FormatRsaPublic {
    fn from(value: FormatPublic) -> Self {
        match value {
            FormatPublic::DER => Self::PKCS1,
            FormatPublic::X509 => Self::X509,
            FormatPublic::Transparent => Self::Transparent,
        }
    }
}
