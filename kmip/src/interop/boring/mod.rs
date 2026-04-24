use boring::{
    ec::EcKey,
    pkey::{Id, PKey, Private, Public},
    rsa::Rsa,
};

use crate::{CryptographicAlgorithm, KeyFormatType, PrivateKey, PublicKey};

use super::{FormatPrivate, FormatPublic, FromObject, KeyError, ToObject};

mod ec;
mod rsa;

impl ToObject<PrivateKey> for PKey<Private> {
    type Format = FormatPrivate;

    fn to_kmip_object(
        &self,
        format: Self::Format,
        vers: crate::ProtocolVersion,
    ) -> Result<PrivateKey, KeyError> {
        match self.id() {
            Id::RSA => self.rsa()?.to_kmip_object(format.into(), vers),
            Id::EC => self.ec_key()?.to_kmip_object(format.into(), vers),
            _ => Err(KeyError::UnsupportedKeyType),
        }
    }
}

impl ToObject<PublicKey> for PKey<Public> {
    type Format = FormatPublic;

    fn to_kmip_object(
        &self,
        format: Self::Format,
        vers: crate::ProtocolVersion,
    ) -> Result<PublicKey, KeyError> {
        match self.id() {
            Id::RSA => self.rsa()?.to_kmip_object(format.into(), vers),
            Id::EC => self.ec_key()?.to_kmip_object(format.into(), vers),
            _ => Err(KeyError::UnsupportedKeyType),
        }
    }
}

impl FromObject<PublicKey> for PKey<Public> {
    fn from_kmip_object(object: crate::Object) -> Result<Self, KeyError> {
        let pubkey = <&PublicKey>::try_from(&object)?;
        match pubkey.key_block.cryptographic_algorithm {
            Some(CryptographicAlgorithm::RSA) => {
                Ok(PKey::from_rsa(Rsa::<Public>::from_kmip_object(object)?)?)
            }
            Some(CryptographicAlgorithm::EC | CryptographicAlgorithm::ECDSA) => Ok(
                PKey::from_ec_key(EcKey::<Public>::from_kmip_object(object)?)?,
            ),

            // If the algorithm is not set, try to guess based on the key material
            None => match pubkey.key_block.key_format_type {
                KeyFormatType::X509 => Ok(PKey::public_key_from_der(
                    pubkey
                        .key_block
                        .try_as_bytes()
                        .ok_or(KeyError::InvalidKeyMaterial)?,
                )?),
                KeyFormatType::PKCS1 | KeyFormatType::TransparentRSAPublicKey => {
                    Ok(PKey::from_rsa(Rsa::<Public>::from_kmip_object(object)?)?)
                }
                #[allow(deprecated, reason = "legacy support")]
                KeyFormatType::TransparentECPublicKey
                | KeyFormatType::TransparentECDSAPublicKey => Ok(PKey::from_ec_key(
                    EcKey::<Public>::from_kmip_object(object)?,
                )?),
                other => Err(KeyError::UnsupportedKeyFormat(other)),
            },
            _ => Err(KeyError::UnsupportedCryptographicAlgorithm),
        }
    }
}

impl FromObject<PrivateKey> for PKey<Private> {
    fn from_kmip_object(object: crate::Object) -> Result<Self, KeyError> {
        let privkey = <&PrivateKey>::try_from(&object)?;

        match privkey.key_block.cryptographic_algorithm {
            Some(CryptographicAlgorithm::RSA) => {
                Ok(PKey::from_rsa(Rsa::<Private>::from_kmip_object(object)?)?)
            }
            Some(CryptographicAlgorithm::EC | CryptographicAlgorithm::ECDSA) => Ok(
                PKey::from_ec_key(EcKey::<Private>::from_kmip_object(object)?)?,
            ),

            // If the algorithm is not set, try to guess based on the key material
            None => match privkey.key_block.key_format_type {
                KeyFormatType::PKCS8 => Ok(PKey::private_key_from_pkcs8(
                    privkey
                        .key_block
                        .try_as_bytes()
                        .ok_or(KeyError::InvalidKeyMaterial)?,
                )?),
                #[allow(deprecated, reason = "legacy support")]
                KeyFormatType::ECPrivateKey
                | KeyFormatType::TransparentECPrivateKey
                | KeyFormatType::TransparentECDSAPrivateKey => Ok(PKey::from_ec_key(
                    EcKey::<Private>::from_kmip_object(object)?,
                )?),
                KeyFormatType::PKCS1 | KeyFormatType::TransparentRSAPrivateKey => {
                    Ok(PKey::from_rsa(Rsa::<Private>::from_kmip_object(object)?)?)
                }
                other => Err(KeyError::UnsupportedKeyFormat(other)),
            },
            _ => Err(KeyError::UnsupportedCryptographicAlgorithm),
        }
    }
}
