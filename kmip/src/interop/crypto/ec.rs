use elliptic_curve::{
    AffinePoint, Curve, CurveArithmetic, FieldBytesSize,
    generic_array::GenericArray,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
};
use pkcs8::AssociatedOid;

use crate::{
    CryptographicAlgorithm, KeyCompressionType, KeyError, KeyFormatType, KeyMaterial, Object,
    PrivateKey, PublicKey, RecommendedCurve, ToKeyMaterial, TransparentECPrivateKey,
    TransparentECPublicKey,
};
use ttlv::BigInteger;

use super::super::{FormatEcPrivate, FormatEcPublic, FromObject};

trait CurveExt {
    const RECOMMENDED_CURVE: RecommendedCurve;
    const CRYPTOGRAPHIC_LENGTH: i32;
}

#[cfg(feature = "interop-p256")]
impl CurveExt for p256::NistP256 {
    const RECOMMENDED_CURVE: RecommendedCurve = RecommendedCurve::P256;
    const CRYPTOGRAPHIC_LENGTH: i32 = 256;
}

#[cfg(feature = "interop-p384")]
impl CurveExt for p384::NistP384 {
    const RECOMMENDED_CURVE: RecommendedCurve = RecommendedCurve::P384;
    const CRYPTOGRAPHIC_LENGTH: i32 = 384;
}

#[cfg(feature = "interop-p521")]
impl CurveExt for p521::NistP521 {
    const RECOMMENDED_CURVE: RecommendedCurve = RecommendedCurve::P521;
    const CRYPTOGRAPHIC_LENGTH: i32 = 521;
}

impl<C> ToKeyMaterial<PublicKey> for elliptic_curve::PublicKey<C>
where
    C: CurveArithmetic + CurveExt + AssociatedOid,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    const ALGORITHM: CryptographicAlgorithm = CryptographicAlgorithm::EC;
    const KEY_COMPRESSION: Option<crate::KeyCompressionType> =
        Some(KeyCompressionType::ECPublicKeyTypeUncompressed);
    type Format = FormatEcPublic;

    fn to_material(&self, format: Self::Format) -> Result<KeyMaterial, KeyError> {
        Ok(match format {
            FormatEcPublic::X509 => KeyMaterial::Bytes(self.to_public_key_der()?.into_vec()),
            FormatEcPublic::Transparent => TransparentECPublicKey {
                recommended_curve: C::RECOMMENDED_CURVE,
                q_string: self.as_affine().to_encoded_point(false).as_bytes().to_vec(),
            }
            .into(),
        })
    }

    fn cryptographic_length(&self) -> i32 {
        C::CRYPTOGRAPHIC_LENGTH
    }
}

impl<C> ToKeyMaterial<PrivateKey> for elliptic_curve::SecretKey<C>
where
    C: Curve + CurveExt + CurveArithmetic + AssociatedOid,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    const ALGORITHM: CryptographicAlgorithm = CryptographicAlgorithm::EC;
    type Format = FormatEcPrivate;

    fn to_material(&self, format: Self::Format) -> Result<KeyMaterial, KeyError> {
        Ok(match format {
            //TODO: Accept Zeroizing
            // FormatEcPrivate::SEC1 => KeyMaterial::Bytes(self.to_sec1_der()?.to_vec()),
            FormatEcPrivate::SEC1 => KeyMaterial::Bytes({
                use sec1::der::Encode;
                let private_key_bytes = self.to_bytes();
                let public_key_bytes = self.public_key().to_encoded_point(false);
                // XXX: Need to do the serializing ourselves, because the one from the lib does not include the parameters
                sec1::EcPrivateKey {
                    private_key: &private_key_bytes,
                    parameters: Some(sec1::EcParameters::NamedCurve(C::OID)),
                    public_key: Some(public_key_bytes.as_bytes()),
                }
                .to_der()?
            }),
            FormatEcPrivate::PKCS8 => KeyMaterial::Bytes(self.to_pkcs8_der()?.as_bytes().to_vec()),
            FormatEcPrivate::Transparent => TransparentECPrivateKey {
                recommended_curve: C::RECOMMENDED_CURVE,
                d: BigInteger::unsigned(self.to_bytes().to_vec()),
            }
            .into(),
        })
    }

    fn cryptographic_length(&self) -> i32 {
        C::CRYPTOGRAPHIC_LENGTH
    }
}

impl<C> FromObject<PublicKey> for elliptic_curve::PublicKey<C>
where
    C: CurveArithmetic + CurveExt + AssociatedOid,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn from_kmip_object(object: Object) -> Result<Self, KeyError> {
        let pkey = PublicKey::try_from(object)?;
        let kb = pkey.key_block;
        match kb.cryptographic_algorithm {
            None | Some(CryptographicAlgorithm::EC | CryptographicAlgorithm::ECDSA) => {}
            _ => return Err("Invalid algorithm".into()),
        }

        let mat = kb.as_plain_material().ok_or("Invalid key material")?;
        match mat {
            #[allow(deprecated, reason = "For backward compatibility")]
            KeyMaterial::TransparentECPublicKey(pkey)
            | KeyMaterial::TransparentECDSAPublicKey(pkey) => {
                if pkey.recommended_curve != C::RECOMMENDED_CURVE {
                    return Err("Recommended curve mismatch".into());
                }
                Ok(Self::from_sec1_bytes(&pkey.q_string)?)
            }
            KeyMaterial::Bytes(bytes) => match kb.key_format_type {
                KeyFormatType::X509 => Ok(Self::from_public_key_der(bytes)?),
                _ => Err("Invalid key format".into()),
            },
            _ => Err("Invalid key value".into()),
        }
    }
}

impl<C> FromObject<PrivateKey> for elliptic_curve::SecretKey<C>
where
    C: Curve + CurveExt + CurveArithmetic + AssociatedOid,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn from_kmip_object(object: Object) -> Result<Self, KeyError> {
        let pkey = PrivateKey::try_from(object)?;
        let kb = pkey.key_block;
        match kb.cryptographic_algorithm {
            None | Some(CryptographicAlgorithm::EC | CryptographicAlgorithm::ECDSA) => {}
            _ => return Err("Invalid algorithm".into()),
        }

        let mat = kb.as_plain_material().ok_or("Invalid key material")?;
        match mat {
            #[allow(deprecated, reason = "For backward compatibility")]
            KeyMaterial::TransparentECPrivateKey(pkey)
            | KeyMaterial::TransparentECDSAPrivateKey(pkey) => {
                if pkey.recommended_curve != C::RECOMMENDED_CURVE {
                    return Err("Recommended curve mismatch".into());
                };
                Ok(Self::from_bytes(GenericArray::from_slice(&pkey.d))?)
            }
            KeyMaterial::Bytes(bytes) => match kb.key_format_type {
                KeyFormatType::PKCS8 => Ok(Self::from_pkcs8_der(bytes)?),
                KeyFormatType::ECPrivateKey => Ok(Self::from_sec1_der(bytes)?),
                _ => Err("Invalid key format".into()),
            },
            _ => Err("Invalid key value".into()),
        }
    }
}
