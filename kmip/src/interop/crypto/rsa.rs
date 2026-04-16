use pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{
    BigUint, RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    traits::{PrivateKeyParts, PublicKeyParts},
};
use ttlv::BigInteger;

use crate::{
    CryptographicAlgorithm, KeyError, KeyFormatType, KeyMaterial, Object, PrivateKey, PublicKey,
    ToKeyMaterial, TransparentRSAPrivateKey, TransparentRSAPublicKey,
};

use super::super::{FormatRsaPrivate, FormatRsaPublic, FromObject};

impl From<&RsaPrivateKey> for TransparentRSAPrivateKey {
    fn from(value: &RsaPrivateKey) -> Self {
        Self {
            modulus: BigInteger::unsigned(value.n().to_bytes_be()),
            private_exponent: Some(BigInteger::unsigned(value.d().to_bytes_be())),
            public_exponent: Some(BigInteger::unsigned(value.e().to_bytes_be())),
            p: value
                .primes()
                .first()
                .map(|v| BigInteger::unsigned(v.to_bytes_be())),
            q: value
                .primes()
                .get(1)
                .map(|v| BigInteger::unsigned(v.to_bytes_be())),
            prime_exponent_p: value.dp().map(|v| BigInteger::unsigned(v.to_bytes_be())),
            prime_exponent_q: value.dq().map(|v| BigInteger::unsigned(v.to_bytes_be())),
            crt_coefficient: value
                .crt_coefficient()
                .map(|v| BigInteger::unsigned(v.to_bytes_be())),
        }
    }
}

impl TryFrom<&TransparentRSAPrivateKey> for RsaPrivateKey {
    type Error = KeyError;
    fn try_from(value: &TransparentRSAPrivateKey) -> Result<Self, Self::Error> {
        match value {
            TransparentRSAPrivateKey {
                modulus,
                private_exponent: Some(d),
                public_exponent: Some(e),
                p,
                q,
                ..
            } => {
                let primes = if let (Some(p), Some(q)) = (p, q) {
                    vec![BigUint::from_bytes_be(p), BigUint::from_bytes_be(q)]
                } else {
                    vec![]
                };
                Ok(rsa::RsaPrivateKey::from_components(
                    BigUint::from_bytes_be(modulus),
                    BigUint::from_bytes_be(e),
                    BigUint::from_bytes_be(d),
                    primes,
                )?)
            }
            TransparentRSAPrivateKey {
                modulus: _,
                private_exponent: _,
                public_exponent: Some(e),
                p: Some(p),
                q: Some(q),
                ..
            } => Ok(rsa::RsaPrivateKey::from_p_q(
                BigUint::from_bytes_be(p),
                BigUint::from_bytes_be(q),
                BigUint::from_bytes_be(e),
            )?),
            _ => Err("Invalid RSA parameter".into()),
        }
    }
}

impl From<&RsaPublicKey> for TransparentRSAPublicKey {
    fn from(value: &RsaPublicKey) -> Self {
        Self {
            modulus: BigInteger::unsigned(value.n().to_bytes_be()),
            public_exponent: BigInteger::unsigned(value.e().to_bytes_be()),
        }
    }
}

impl TryFrom<&TransparentRSAPublicKey> for RsaPublicKey {
    type Error = KeyError;
    fn try_from(value: &TransparentRSAPublicKey) -> Result<Self, Self::Error> {
        Ok(Self::new(
            BigUint::from_bytes_be(&value.modulus),
            BigUint::from_bytes_be(&value.public_exponent),
        )?)
    }
}

impl ToKeyMaterial<PublicKey> for RsaPublicKey {
    const ALGORITHM: CryptographicAlgorithm = CryptographicAlgorithm::RSA;
    type Format = FormatRsaPublic;

    fn to_material(&self, format: Self::Format) -> Result<KeyMaterial, KeyError> {
        Ok(match format {
            FormatRsaPublic::Transparent => KeyMaterial::TransparentRSAPublicKey(self.into()),
            FormatRsaPublic::PKCS1 => KeyMaterial::Bytes(self.to_pkcs1_der()?.into_vec()),
            FormatRsaPublic::X509 => KeyMaterial::Bytes(self.to_public_key_der()?.into_vec()),
        })
    }

    fn cryptographic_length(&self) -> i32 {
        self.size() as i32 * 8
    }
}

impl TryFrom<PublicKey> for RsaPublicKey {
    type Error = KeyError;
    fn try_from(pkey: PublicKey) -> Result<Self, Self::Error> {
        let kb = pkey.key_block;
        match kb.cryptographic_algorithm {
            None | Some(CryptographicAlgorithm::RSA) => {}
            _ => return Err("Invalid algorithm".into()),
        }

        let mat = kb.as_plain_material().ok_or("Invalid key material")?;
        match mat {
            KeyMaterial::TransparentRSAPublicKey(pkey) => Ok(pkey.try_into()?),
            KeyMaterial::Bytes(bytes) => match kb.key_format_type {
                KeyFormatType::PKCS1 => Ok(RsaPublicKey::from_pkcs1_der(bytes)?),
                KeyFormatType::X509 => Ok(RsaPublicKey::from_public_key_der(bytes)?),
                _ => Err("Invalid key format".into()),
            },
            _ => Err("Invalid key value".into()),
        }
    }
}

impl TryFrom<PrivateKey> for RsaPrivateKey {
    type Error = KeyError;
    fn try_from(pkey: PrivateKey) -> Result<Self, Self::Error> {
        let kb = pkey.key_block;

        match kb.cryptographic_algorithm {
            None | Some(CryptographicAlgorithm::RSA) => {}
            _ => return Err("Invalid algorithm".into()),
        }

        let mat = kb.as_plain_material().ok_or("Invalid key material")?;
        match mat {
            KeyMaterial::TransparentRSAPrivateKey(pkey) => Ok(pkey.try_into()?),
            KeyMaterial::Bytes(bytes) => match kb.key_format_type {
                KeyFormatType::PKCS1 => Ok(RsaPrivateKey::from_pkcs1_der(bytes)?),
                KeyFormatType::PKCS8 => Ok(RsaPrivateKey::from_pkcs8_der(bytes)?),
                _ => Err("Invalid key format".into()),
            },
            _ => Err("Invalid key value".into()),
        }
    }
}

impl ToKeyMaterial<PrivateKey> for RsaPrivateKey {
    const ALGORITHM: CryptographicAlgorithm = CryptographicAlgorithm::RSA;
    type Format = FormatRsaPrivate;

    fn to_material(&self, format: Self::Format) -> Result<KeyMaterial, KeyError> {
        Ok(match format {
            FormatRsaPrivate::Transparent => KeyMaterial::TransparentRSAPrivateKey(self.into()),
            FormatRsaPrivate::PKCS1 => {
                KeyMaterial::Bytes(self.to_pkcs1_der()?.as_bytes().to_vec())
                //TODO: Accept Zeroizing
            }
            FormatRsaPrivate::PKCS8 => {
                KeyMaterial::Bytes(self.to_pkcs8_der()?.as_bytes().to_vec())
                //TODO: Accept Zeroizing
            }
        })
    }

    fn cryptographic_length(&self) -> i32 {
        self.size() as i32 * 8
    }
}

impl FromObject<PrivateKey> for RsaPrivateKey {
    fn from_kmip_object(object: Object) -> Result<Self, KeyError> {
        let pkey = PrivateKey::try_from(object)?;
        pkey.try_into()
    }
}

impl FromObject<PublicKey> for RsaPublicKey {
    fn from_kmip_object(object: Object) -> Result<Self, KeyError> {
        let pkey = PublicKey::try_from(object)?;
        pkey.try_into()
    }
}
