use boring::{
    bn::BigNum,
    pkey::{PKey, Private, Public},
    rsa::{Rsa, RsaPrivateKeyBuilder},
};
use ttlv::BigInteger;

use crate::{
    CryptographicAlgorithm, KeyFormatType, KeyMaterial, Object, PrivateKey, PublicKey,
    TransparentRSAPrivateKey, TransparentRSAPublicKey,
};

use super::super::{
    FormatRsaPrivate, FormatRsaPublic, FromObject, KeyError, ToKeyMaterial, bytes_to_bit_length,
};

impl From<&Rsa<Private>> for TransparentRSAPrivateKey {
    fn from(value: &Rsa<Private>) -> Self {
        Self {
            modulus: BigInteger::unsigned(value.n().to_vec()),
            private_exponent: Some(BigInteger::unsigned(value.d().to_vec())),
            public_exponent: Some(BigInteger::unsigned(value.e().to_vec())),
            p: value.p().map(|v| BigInteger::unsigned(v.to_vec())),
            q: value.q().map(|v| BigInteger::unsigned(v.to_vec())),
            prime_exponent_p: value.dmp1().map(|v| BigInteger::unsigned(v.to_vec())),
            prime_exponent_q: value.dmq1().map(|v| BigInteger::unsigned(v.to_vec())),
            crt_coefficient: value.iqmp().map(|v| BigInteger::unsigned(v.to_vec())),
        }
    }
}

impl TryFrom<&TransparentRSAPrivateKey> for Rsa<Private> {
    type Error = KeyError;

    fn try_from(value: &TransparentRSAPrivateKey) -> Result<Self, Self::Error> {
        let mut bld = RsaPrivateKeyBuilder::new(
            BigNum::from_slice(&value.modulus)?,
            BigNum::from_slice(value.public_exponent.as_ref().ok_or(
                KeyError::InvalidRsaParameter {
                    parameter: "public_exponent",
                },
            )?)?,
            BigNum::from_slice(value.private_exponent.as_ref().ok_or(
                KeyError::InvalidRsaParameter {
                    parameter: "private_exponent",
                },
            )?)?,
        )?;
        if value.p.is_some() || value.q.is_some() {
            bld = bld.set_factors(
                BigNum::from_slice(
                    value
                        .p
                        .as_ref()
                        .ok_or(KeyError::InvalidRsaParameter { parameter: "p" })?,
                )?,
                BigNum::from_slice(
                    value
                        .q
                        .as_ref()
                        .ok_or(KeyError::InvalidRsaParameter { parameter: "q" })?,
                )?,
            )?;
        }
        if value.prime_exponent_p.is_some()
            || value.prime_exponent_q.is_some()
            || value.crt_coefficient.is_some()
        {
            bld = bld.set_crt_params(
                BigNum::from_slice(value.prime_exponent_p.as_ref().ok_or(
                    KeyError::InvalidRsaParameter {
                        parameter: "prime_exponent_p",
                    },
                )?)?,
                BigNum::from_slice(value.prime_exponent_q.as_ref().ok_or(
                    KeyError::InvalidRsaParameter {
                        parameter: "prime_exponent_q",
                    },
                )?)?,
                BigNum::from_slice(value.crt_coefficient.as_ref().ok_or(
                    KeyError::InvalidRsaParameter {
                        parameter: "crt_coefficient",
                    },
                )?)?,
            )?
        }
        Ok(bld.build())
    }
}

impl From<&Rsa<Public>> for TransparentRSAPublicKey {
    fn from(value: &Rsa<Public>) -> Self {
        Self {
            modulus: BigInteger::unsigned(value.n().to_vec()),
            public_exponent: BigInteger::unsigned(value.e().to_vec()),
        }
    }
}

impl TryFrom<&TransparentRSAPublicKey> for Rsa<Public> {
    type Error = KeyError;

    fn try_from(value: &TransparentRSAPublicKey) -> Result<Self, Self::Error> {
        Ok(Self::from_public_components(
            BigNum::from_slice(&value.modulus)?,
            BigNum::from_slice(&value.public_exponent)?,
        )?)
    }
}

impl ToKeyMaterial<PublicKey> for Rsa<Public> {
    const ALGORITHM: CryptographicAlgorithm = CryptographicAlgorithm::RSA;

    type Format = FormatRsaPublic;

    fn to_material(&self, format: Self::Format) -> Result<KeyMaterial, KeyError> {
        Ok(match format {
            FormatRsaPublic::Transparent => KeyMaterial::TransparentRSAPublicKey(self.into()),
            FormatRsaPublic::PKCS1 => KeyMaterial::Bytes(self.public_key_to_der_pkcs1()?),
            FormatRsaPublic::X509 => KeyMaterial::Bytes(self.public_key_to_der()?),
        })
    }

    fn cryptographic_length(&self) -> Result<i32, KeyError> {
        bytes_to_bit_length(self.size())
    }
}

impl ToKeyMaterial<PrivateKey> for Rsa<Private> {
    const ALGORITHM: CryptographicAlgorithm = CryptographicAlgorithm::RSA;

    type Format = FormatRsaPrivate;

    fn to_material(&self, format: Self::Format) -> Result<KeyMaterial, KeyError> {
        Ok(match format {
            FormatRsaPrivate::Transparent => KeyMaterial::TransparentRSAPrivateKey(self.into()),
            FormatRsaPrivate::PKCS1 => KeyMaterial::Bytes(self.private_key_to_der()?),
            FormatRsaPrivate::PKCS8 => {
                KeyMaterial::Bytes(PKey::from_rsa(self.clone())?.private_key_to_der_pkcs8()?)
            }
        })
    }

    fn cryptographic_length(&self) -> Result<i32, KeyError> {
        bytes_to_bit_length(self.size())
    }
}

impl FromObject<PrivateKey> for Rsa<Private> {
    fn from_kmip_object(object: Object) -> Result<Self, KeyError> {
        let pkey = PrivateKey::try_from(object)?;
        let kb = pkey.key_block;

        match kb.cryptographic_algorithm {
            None | Some(CryptographicAlgorithm::RSA) => {}
            got => {
                return Err(KeyError::InvalidAlgorithm {
                    expected: "RSA",
                    got,
                });
            }
        }

        let mat = kb.as_plain_material().ok_or(KeyError::InvalidKeyMaterial)?;
        match mat {
            KeyMaterial::TransparentRSAPrivateKey(pkey) => Ok(pkey.try_into()?),
            KeyMaterial::Bytes(bytes) => match kb.key_format_type {
                KeyFormatType::PKCS1 => Ok(Rsa::private_key_from_der(bytes)?),
                KeyFormatType::PKCS8 => Ok(PKey::private_key_from_pkcs8(bytes)?.rsa()?),
                other => Err(KeyError::UnsupportedKeyFormat(other)),
            },
            _ => Err(KeyError::InvalidKeyValue),
        }
    }
}

impl FromObject<PublicKey> for Rsa<Public> {
    fn from_kmip_object(object: Object) -> Result<Self, KeyError> {
        let pkey = PublicKey::try_from(object)?;
        let kb = pkey.key_block;
        match kb.cryptographic_algorithm {
            None | Some(CryptographicAlgorithm::RSA) => {}
            got => {
                return Err(KeyError::InvalidAlgorithm {
                    expected: "RSA",
                    got,
                });
            }
        }

        let mat = kb.as_plain_material().ok_or(KeyError::InvalidKeyMaterial)?;
        match mat {
            KeyMaterial::TransparentRSAPublicKey(pkey) => Ok(pkey.try_into()?),
            KeyMaterial::Bytes(bytes) => match kb.key_format_type {
                KeyFormatType::PKCS1 => Ok(Rsa::public_key_from_der_pkcs1(bytes)?),
                KeyFormatType::X509 => Ok(Rsa::public_key_from_der(bytes)?),
                other => Err(KeyError::UnsupportedKeyFormat(other)),
            },
            _ => Err(KeyError::InvalidKeyValue),
        }
    }
}
