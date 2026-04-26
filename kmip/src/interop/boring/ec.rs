use std::borrow::BorrowMut;

use boring::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
    pkey::{PKey, Private, Public},
};
use ttlv::BigInteger;

use crate::{
    CryptographicAlgorithm, KeyCompressionType, KeyFormatType, KeyMaterial, Object, PrivateKey,
    PublicKey, RecommendedCurve, TransparentECPrivateKey, TransparentECPublicKey,
};

use super::super::{
    FormatEcPrivate, FormatEcPublic, FromObject, KeyError, ToKeyMaterial, bits_to_i32,
};

impl TryFrom<RecommendedCurve> for Nid {
    type Error = KeyError;
    fn try_from(value: RecommendedCurve) -> Result<Self, Self::Error> {
        Ok(match value {
            //TODO: Support other curves
            RecommendedCurve::P256 => Nid::X9_62_PRIME256V1,
            RecommendedCurve::P384 => Nid::SECP384R1,
            RecommendedCurve::P521 => Nid::SECP521R1,
            _ => return Err(KeyError::UnsupportedCurve(value)),
        })
    }
}

impl TryFrom<Nid> for RecommendedCurve {
    type Error = KeyError;
    fn try_from(value: Nid) -> Result<Self, Self::Error> {
        Ok(match value {
            //TODO: Support other curves
            Nid::X9_62_PRIME256V1 => RecommendedCurve::P256,
            Nid::SECP384R1 => RecommendedCurve::P384,
            Nid::SECP521R1 => RecommendedCurve::P521,
            _ => return Err(KeyError::UnsupportedCurveNid),
        })
    }
}

impl TryFrom<Option<Nid>> for RecommendedCurve {
    type Error = KeyError;
    fn try_from(value: Option<Nid>) -> Result<Self, Self::Error> {
        value.ok_or(KeyError::MissingCurve)?.try_into()
    }
}

impl ToKeyMaterial<PublicKey> for EcKey<Public> {
    const ALGORITHM: CryptographicAlgorithm = CryptographicAlgorithm::EC;
    const KEY_COMPRESSION: Option<crate::KeyCompressionType> =
        Some(KeyCompressionType::ECPublicKeyTypeUncompressed);
    type Format = FormatEcPublic;

    fn to_material(&self, format: Self::Format) -> Result<KeyMaterial, KeyError> {
        Ok(match format {
            FormatEcPublic::X509 => KeyMaterial::Bytes(self.public_key_to_der()?),
            FormatEcPublic::Transparent => TransparentECPublicKey {
                recommended_curve: self.group().curve_name().try_into()?,
                q_string: self.public_key().to_bytes(
                    self.group(),
                    PointConversionForm::UNCOMPRESSED,
                    BigNumContext::new()?.borrow_mut(),
                )?,
            }
            .into(),
        })
    }

    fn cryptographic_length(&self) -> Result<i32, KeyError> {
        bits_to_i32(self.group().order_bits())
    }
}

impl ToKeyMaterial<PrivateKey> for EcKey<Private> {
    const ALGORITHM: CryptographicAlgorithm = CryptographicAlgorithm::EC;
    type Format = FormatEcPrivate;

    fn to_material(&self, format: Self::Format) -> Result<KeyMaterial, KeyError> {
        Ok(match format {
            FormatEcPrivate::SEC1 => KeyMaterial::Bytes(self.private_key_to_der()?),
            FormatEcPrivate::PKCS8 => {
                KeyMaterial::Bytes(PKey::from_ec_key(self.clone())?.private_key_to_der_pkcs8()?)
            }
            FormatEcPrivate::Transparent => TransparentECPrivateKey {
                recommended_curve: self.group().curve_name().try_into()?,
                d: BigInteger::unsigned(self.private_key().to_vec()),
            }
            .into(),
        })
    }

    fn cryptographic_length(&self) -> Result<i32, KeyError> {
        bits_to_i32(self.group().order_bits())
    }
}

impl FromObject<PublicKey> for EcKey<Public> {
    fn from_kmip_object(object: Object) -> Result<Self, KeyError> {
        let pkey = PublicKey::try_from(object)?;
        let kb = pkey.key_block;

        match kb.cryptographic_algorithm {
            None | Some(CryptographicAlgorithm::EC | CryptographicAlgorithm::ECDSA) => {}
            got => {
                return Err(KeyError::InvalidAlgorithm {
                    expected: "EC or ECDSA",
                    got,
                });
            }
        }

        let mat = kb.as_plain_material().ok_or(KeyError::InvalidKeyMaterial)?;
        match mat {
            #[allow(deprecated, reason = "For backward compatibility")]
            KeyMaterial::TransparentECPublicKey(pkey)
            | KeyMaterial::TransparentECDSAPublicKey(pkey) => {
                let group = EcGroup::from_curve_name(pkey.recommended_curve.try_into()?)?;
                let point = EcPoint::from_bytes(
                    &group,
                    &pkey.q_string,
                    BigNumContext::new()?.borrow_mut(),
                )?;
                Ok(EcKey::from_public_key(&group, &point)?)
            }
            KeyMaterial::Bytes(bytes) => match kb.key_format_type {
                KeyFormatType::X509 => Ok(EcKey::public_key_from_der(bytes)?),
                other => Err(KeyError::UnsupportedKeyFormat(other)),
            },
            _ => Err(KeyError::InvalidKeyValue),
        }
    }
}

impl FromObject<PrivateKey> for EcKey<Private> {
    fn from_kmip_object(object: Object) -> Result<Self, KeyError> {
        let pkey = PrivateKey::try_from(object)?;
        let kb = pkey.key_block;

        match kb.cryptographic_algorithm {
            None | Some(CryptographicAlgorithm::EC | CryptographicAlgorithm::ECDSA) => {}
            got => {
                return Err(KeyError::InvalidAlgorithm {
                    expected: "EC or ECDSA",
                    got,
                });
            }
        }

        let mat = kb.as_plain_material().ok_or(KeyError::InvalidKeyMaterial)?;
        match mat {
            #[allow(deprecated, reason = "For backward compatibility")]
            KeyMaterial::TransparentECPrivateKey(pkey)
            | KeyMaterial::TransparentECDSAPrivateKey(pkey) => {
                let group = EcGroup::from_curve_name(pkey.recommended_curve.try_into()?)?;
                let d = BigNum::from_slice(&pkey.d)?;
                let mut pubkey = EcPoint::new(&group)?;
                pubkey.mul_generator(&group, &d, BigNumContext::new()?.borrow_mut())?;
                Ok(EcKey::from_private_components(&group, &d, &pubkey)?)
            }
            KeyMaterial::Bytes(bytes) => match kb.key_format_type {
                KeyFormatType::PKCS8 => Ok(PKey::private_key_from_pkcs8(bytes)?.ec_key()?),
                KeyFormatType::ECPrivateKey => Ok(EcKey::private_key_from_der(bytes)?),
                other => Err(KeyError::UnsupportedKeyFormat(other)),
            },
            _ => Err(KeyError::InvalidKeyValue),
        }
    }
}
