use cryptoki_sys::*;
use kmip::{enums::PaddingMethod, types::CryptographicParameters};

#[derive(Debug, Clone)]
pub struct EncryptMode {
    pub params: CryptographicParameters,
    pub align: Option<usize>,
    pub iv: Option<Vec<u8>>,
    pub aad: Option<Vec<u8>>,
}

impl TryFrom<&CK_MECHANISM> for EncryptMode {
    type Error = CK_RV;

    fn try_from(mechanism: &CK_MECHANISM) -> Result<Self, Self::Error> {
        let (params, align, iv, aad) = match (*mechanism).mechanism {
            CKM_AES_GCM => {
                if (*mechanism).pParameter.is_null() {
                    tracing::error!("Parameters must be provided for AES GCM mode");
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                if (*mechanism).ulParameterLen != std::mem::size_of::<CK_GCM_PARAMS>() as u64 {
                    tracing::error!(
                        "Invalid parameter length for AES GCM mode: {}",
                        (*mechanism).ulParameterLen
                    );
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                let param = unsafe { &*((*mechanism).pParameter as CK_GCM_PARAMS_PTR) };
                if param.ulIvLen == 0 || param.ulIvLen > 256 {
                    tracing::error!("Invalid IV length: {}", param.ulIvLen);
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                if param.ulIvLen > 0 && param.pIv.is_null() {
                    tracing::error!("IV length is non-zero but IV pointer is null");
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                if param.ulTagBits == 0 || param.ulTagBits > 128 {
                    tracing::error!("Invalid tag length: {}", param.ulTagBits);
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                if param.ulAADLen > 0 && param.pAAD.is_null() {
                    tracing::error!("AAD length is non-zero but AAD pointer is null");
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                let iv = unsafe {
                    std::slice::from_raw_parts(param.pIv as *const u8, param.ulIvLen as usize)
                };

                let aad = if param.ulAADLen > 0 && !param.pAAD.is_null() {
                    unsafe {
                        Some(
                            std::slice::from_raw_parts(
                                param.pAAD as *const u8,
                                param.ulAADLen as usize,
                            )
                            .to_vec(),
                        )
                    }
                } else {
                    None
                };

                let params = CryptographicParameters::aes_gcm(
                    Some(iv.len() as i32),
                    Some((param.ulTagBits / 8) as i32),
                );
                (params, None, Some(iv.to_vec()), aad)
            }
            CKM_AES_ECB => {
                // Input must be a mutliple of 16 bytes
                (
                    CryptographicParameters::aes_ecb(Some(PaddingMethod::None)),
                    Some(16),
                    None,
                    None,
                )
            }
            CKM_AES_CBC | CKM_AES_CBC_PAD => {
                if (*mechanism).pParameter.is_null() {
                    tracing::error!("IV must be provided for AES CBC mode");
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                if (*mechanism).ulParameterLen != 16 {
                    tracing::error!(
                        "Invalid IV length for AES CBC mode: {}",
                        (*mechanism).ulParameterLen
                    );
                    return Err(CKR_MECHANISM_PARAM_INVALID);
                }
                let iv = unsafe {
                    std::slice::from_raw_parts(
                        (*mechanism).pParameter as *mut u8,
                        (*mechanism).ulParameterLen as usize,
                    )
                };
                match (*mechanism).mechanism {
                    CKM_AES_CBC => {
                        // Input must be a mutliple of 16 bytes
                        (
                            CryptographicParameters::aes_cbc(Some(PaddingMethod::None)),
                            Some(16),
                            Some(iv.to_vec()),
                            None,
                        )
                    }
                    CKM_AES_CBC_PAD => (
                        CryptographicParameters::aes_cbc_pkcs5(),
                        None,
                        Some(iv.to_vec()),
                        None,
                    ),
                    _ => unreachable!(),
                }
            }
            _ => {
                tracing::error!("Unsupported mechanism: {}", (*mechanism).mechanism);
                return Err(CKR_MECHANISM_INVALID);
            }
        };
        Ok(Self {
            params,
            align,
            iv,
            aad,
        })
    }
}
