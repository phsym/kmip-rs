use const_oid::db::rfc5912;
use cryptoki_sys::*;
use der::Decode;
use kmip::{
    enums::{HashingAlgorithm, MaskGenerator},
    types::CryptographicParameters,
};

use crate::core::asn1::DigestInfoRef;

#[derive(Debug, Clone)]
pub enum SignVerifyMode {
    HashAndSign(CryptographicParameters),
    Sign(CryptographicParameters),
    RsaPkcsDigestInfo,
    EcdsaRawDigest,
}

impl SignVerifyMode {
    pub fn to_crypto_params(
        &self,
        data: &mut &[u8],
    ) -> crate::errors::Result<(CryptographicParameters, bool)> {
        let (alg, is_digest) = match self {
            SignVerifyMode::HashAndSign(params) => (params.clone(), false),
            SignVerifyMode::Sign(params) => (params.clone(), true),
            SignVerifyMode::RsaPkcsDigestInfo => {
                let info = DigestInfoRef::from_der(data).unwrap();
                tracing::trace!("digest info: {info:#?}");
                let alg = match info.algorithm.oid {
                    rfc5912::ID_SHA_256 => CryptographicParameters::rsa_pkcs_sha256(),
                    rfc5912::ID_SHA_384 => CryptographicParameters::rsa_pkcs_sha384(),
                    rfc5912::ID_SHA_512 => CryptographicParameters::rsa_pkcs_sha512(),
                    other => {
                        tracing::error!("Unsupported algorithm OID {other}");
                        return Err(CKR_MECHANISM_INVALID);
                    }
                };
                *data = info.digest.as_bytes();
                (alg, true)
            }
            SignVerifyMode::EcdsaRawDigest => {
                let alg = match data.len() {
                    32 => CryptographicParameters::ecdsa_sha256(),
                    48 => CryptographicParameters::ecdsa_sha384(),
                    64 => CryptographicParameters::ecdsa_sha512(),
                    other => {
                        tracing::error!("Unsupported digest length {other}");
                        return Err(CKR_MECHANISM_INVALID);
                    }
                };
                (alg, true)
            }
        };
        Ok((alg, is_digest))
    }
}

impl TryFrom<&CK_MECHANISM> for SignVerifyMode {
    type Error = CK_RV;

    fn try_from(mech: &CK_MECHANISM) -> Result<Self, Self::Error> {
        let mode = match mech.mechanism {
            CKM_SHA256_RSA_PKCS => Self::HashAndSign(CryptographicParameters::rsa_pkcs_sha256()),
            CKM_SHA384_RSA_PKCS => Self::HashAndSign(CryptographicParameters::rsa_pkcs_sha384()),
            CKM_SHA512_RSA_PKCS => Self::HashAndSign(CryptographicParameters::rsa_pkcs_sha512()),
            CKM_RSA_PKCS => Self::RsaPkcsDigestInfo,

            CKM_SHA256_RSA_PKCS_PSS => Self::HashAndSign(CryptographicParameters::rsa_pss_sha256()),
            CKM_SHA384_RSA_PKCS_PSS => Self::HashAndSign(CryptographicParameters::rsa_pss_sha384()),
            CKM_SHA512_RSA_PKCS_PSS => Self::HashAndSign(CryptographicParameters::rsa_pss_sha512()),
            CKM_RSA_PKCS_PSS => {
                if mech.pParameter.is_null() {
                    tracing::error!("CKM_RSA_PKCS_PSS mechanism requires parameters");
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                if mech.ulParameterLen != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() as u64 {
                    tracing::error!(
                        "CKM_RSA_PKCS_PSS mechanism parameter length is invalid. Expected {} but got {}",
                        std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>(),
                        mech.ulParameterLen
                    );
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                let params = unsafe { &*(mech.pParameter as CK_RSA_PKCS_PSS_PARAMS_PTR) };
                let hash = match params.hashAlg {
                    CKM_SHA_1 => HashingAlgorithm::SHA1,
                    CKM_SHA224 => HashingAlgorithm::SHA224,
                    CKM_SHA256 => HashingAlgorithm::SHA256,
                    CKM_SHA384 => HashingAlgorithm::SHA384,
                    CKM_SHA512 => HashingAlgorithm::SHA512,
                    other => {
                        tracing::error!(
                            "Unsupported hash algorithm {other} in CKM_RSA_PKCS_PSS parameters"
                        );
                        return Err(CKR_MECHANISM_PARAM_INVALID);
                    }
                };
                let (mgf, mgf_hash) = match params.mgf {
                    CKG_MGF1_SHA1 => (MaskGenerator::MGF1, HashingAlgorithm::SHA1),
                    CKG_MGF1_SHA224 => (MaskGenerator::MGF1, HashingAlgorithm::SHA224),
                    CKG_MGF1_SHA256 => (MaskGenerator::MGF1, HashingAlgorithm::SHA256),
                    CKG_MGF1_SHA384 => (MaskGenerator::MGF1, HashingAlgorithm::SHA384),
                    CKG_MGF1_SHA512 => (MaskGenerator::MGF1, HashingAlgorithm::SHA512),
                    other => {
                        tracing::error!(
                            "Unsupported MGF type {other} in CKM_RSA_PKCS_PSS parameters"
                        );
                        return Err(CKR_MECHANISM_PARAM_INVALID);
                    }
                };
                //TODO: handle salt length params.sLen
                Self::Sign(CryptographicParameters::rsa_pss(hash, mgf, mgf_hash))
            }

            CKM_ECDSA_SHA256 => Self::HashAndSign(CryptographicParameters::ecdsa_sha256()),
            CKM_ECDSA_SHA384 => Self::HashAndSign(CryptographicParameters::ecdsa_sha384()),
            CKM_ECDSA_SHA512 => Self::HashAndSign(CryptographicParameters::ecdsa_sha512()),
            CKM_ECDSA => Self::EcdsaRawDigest,
            _ => return Err(CKR_MECHANISM_INVALID),
        };
        Ok(mode)
    }
}
