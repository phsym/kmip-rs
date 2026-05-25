use std::slice;

use const_oid::db::rfc5912;
use cryptoki::object::{Attribute, KeyType, ObjectClass};
use cryptoki_sys::*;
use der::Decode;
use kmip::{
    CryptographicUsageMask,
    attributes::{CryptographicLength, Extractable, Sensitive},
    client::BatchResultExt,
    enums::{CryptographicAlgorithm, ObjectType, RecommendedCurve},
    payloads::{ActivateRequestPayload, CreateKeyPairRequestPayload, CreateRequestPayload},
    types::{CryptographicDomainParameters, Name, TemplateAttribute},
};
use macro_rules_attribute::apply;
use sec1::EcParameters;

use crate::core::{Handle, State};

#[macro_use]
mod macros;
mod core;
mod encrypt;
mod errors;
mod init;
mod legacy;
mod mapping;
mod objects;
mod random;
mod session;
mod sign;
mod slot;

const VERSION_MAJOR: &str = env!("CARGO_PKG_VERSION_MAJOR");
const VERSION_MINOR: &str = env!("CARGO_PKG_VERSION_MINOR");

static FUNCLIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 4 },
    C_Initialize: Some(init::C_Initialize),
    C_Finalize: Some(init::C_Finalize),
    C_GetInfo: Some(init::C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(slot::C_GetSlotList),
    C_GetSlotInfo: Some(slot::C_GetSlotInfo),
    C_GetTokenInfo: Some(slot::C_GetTokenInfo),
    C_GetMechanismList: Some(slot::C_GetMechanismList),
    C_GetMechanismInfo: Some(slot::C_GetMechanismInfo),
    C_InitToken: not_supported!(C_InitToken),
    C_InitPIN: not_supported!(C_InitPIN),
    C_SetPIN: not_supported!(C_SetPIN),
    C_OpenSession: Some(session::C_OpenSession),
    C_CloseSession: Some(session::C_CloseSession),
    C_CloseAllSessions: Some(session::C_CloseAllSessions),
    C_GetSessionInfo: Some(session::C_GetSessionInfo),
    C_GetOperationState: not_supported!(C_GetOperationState),
    C_SetOperationState: not_supported!(C_SetOperationState),
    C_Login: Some(session::C_Login),
    C_Logout: Some(session::C_Logout),
    C_CreateObject: not_supported!(C_CreateObject),
    C_CopyObject: not_supported!(C_CopyObject),
    C_DestroyObject: Some(objects::C_DestroyObject),
    C_GetObjectSize: Some(objects::C_GetObjectSize),
    C_GetAttributeValue: Some(objects::C_GetAttributeValue),
    C_SetAttributeValue: not_supported!(C_SetAttributeValue),
    C_FindObjectsInit: Some(objects::C_FindObjectsInit),
    C_FindObjects: Some(objects::C_FindObjects),
    C_FindObjectsFinal: Some(objects::C_FindObjectsFinal),
    C_EncryptInit: Some(encrypt::C_EncryptInit),
    C_Encrypt: Some(encrypt::C_Encrypt),
    C_EncryptUpdate: not_supported!(C_EncryptUpdate),
    C_EncryptFinal: not_supported!(C_EncryptFinal),
    C_DecryptInit: Some(encrypt::C_DecryptInit),
    C_Decrypt: Some(encrypt::C_Decrypt),
    C_DecryptUpdate: not_supported!(C_DecryptUpdate),
    C_DecryptFinal: not_supported!(C_DecryptFinal),
    C_DigestInit: not_supported!(C_DigestInit),
    C_Digest: not_supported!(C_Digest),
    C_DigestUpdate: not_supported!(C_DigestUpdate),
    C_DigestKey: not_supported!(C_DigestKey),
    C_DigestFinal: not_supported!(C_DigestFinal),
    C_SignInit: Some(sign::C_SignInit),
    C_Sign: Some(sign::C_Sign),
    C_SignUpdate: not_supported!(C_SignUpdate),
    C_SignFinal: not_supported!(C_SignFinal),
    C_SignRecoverInit: not_supported!(C_SignRecoverInit),
    C_SignRecover: not_supported!(C_SignRecover),
    C_VerifyInit: Some(sign::C_VerifyInit),
    C_Verify: Some(sign::C_Verify),
    C_VerifyUpdate: not_supported!(C_VerifyUpdate),
    C_VerifyFinal: not_supported!(C_VerifyFinal),
    C_VerifyRecoverInit: not_supported!(C_VerifyRecoverInit),
    C_VerifyRecover: not_supported!(C_VerifyRecover),
    C_DigestEncryptUpdate: not_supported!(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: not_supported!(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: not_supported!(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: not_supported!(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: not_supported!(C_WrapKey),
    C_UnwrapKey: not_supported!(C_UnwrapKey),
    C_DeriveKey: not_supported!(C_DeriveKey),
    C_SeedRandom: Some(random::C_SeedRandom),
    C_GenerateRandom: Some(random::C_GenerateRandom),
    C_GetFunctionStatus: Some(legacy::C_GetFunctionStatus),
    C_CancelFunction: Some(legacy::C_CancelFunction),
    C_WaitForSlotEvent: not_supported!(C_WaitForSlotEvent),
};

/// C_GetFunctionList obtains a pointer to the Cryptoki library’s list of function pointers.
/// ppFunctionList points to a value which will receive a pointer to the library’s CK_FUNCTION_LIST structure,
/// which in turn contains function pointers for all the Cryptoki API routines in the library.  
/// The pointer thus obtained may point into memory which is owned by the Cryptoki library, and which may or may not be writable.  
/// Whether or not this is the case, no attempt should be made to write to this memory.
///
/// C_GetFunctionList is the only Cryptoki function which an application may call before calling C_Initialize.  
/// It is provided to make it easier and faster for applications to use shared Cryptoki libraries and to use more than one
/// Cryptoki library simultaneously.
///
/// # Returns
/// CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK.
#[apply(pkcs11_export)]
unsafe fn C_GetFunctionList(function_list: *mut *mut CK_FUNCTION_LIST) -> errors::Result<()> {
    if function_list.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    unsafe { *function_list = &FUNCLIST as *const _ as *mut _ };
    Ok(())
}

#[apply(pkcs11_export)]
pub unsafe fn C_GenerateKey(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    templ: *mut CK_ATTRIBUTE,
    ul_count: ::std::os::raw::c_ulong,
    key: *mut CK_OBJECT_HANDLE,
) -> errors::Result<()> {
    ensure_not_null!(mechanism, key, templ);
    let gstate = State::get()?;
    gstate.enter_session(session, |mut session| unsafe {
        tracing::debug!("mechanism: {:?}", *mechanism);
        if (*mechanism).mechanism != CKM_AES_KEY_GEN {
            return Err(CKR_MECHANISM_INVALID);
        }

        let attributes = std::slice::from_raw_parts_mut(templ, ul_count as usize);
        tracing::debug!("Key template: {attributes:?}");

        let mut req = CreateRequestPayload {
            object_type: ObjectType::SymmetricKey,
            attributes: TemplateAttribute::new(vec![CryptographicAlgorithm::AES.into()]),
        };
        let mut key_ops = CryptographicUsageMask::empty();

        for attr in attributes {
            match Attribute::try_from(*attr).unwrap() {
                Attribute::Label(lbl) => req
                    .attributes
                    .attribute
                    .push(Name::new_string(String::from_utf8(lbl).unwrap()).into()),
                Attribute::Class(ObjectClass::SECRET_KEY) => {}
                Attribute::Encrypt(true) => key_ops |= CryptographicUsageMask::Encrypt,
                Attribute::Decrypt(true) => key_ops |= CryptographicUsageMask::Decrypt,
                Attribute::Sign(true) => key_ops |= CryptographicUsageMask::Sign,
                Attribute::Verify(true) => key_ops |= CryptographicUsageMask::Verify,
                Attribute::ValueLen(len) => req
                    .attributes
                    .attribute
                    .push(CryptographicLength((*len * 8).try_into().unwrap()).into()),
                Attribute::KeyType(KeyType::AES) => {}
                Attribute::Token(_b) => {
                    // req.attributes.attribute.push(kmip::attributes::AttributeValue::Unknown { name: "x-ephemeral".into(), value: kmip:: })
                }
                Attribute::Sensitive(s) => req
                    .attributes
                    .attribute
                    .push(kmip::attributes::Sensitive(s).into()),
                Attribute::Extractable(e) => req
                    .attributes
                    .attribute
                    .push(kmip::attributes::Extractable(e).into()),
                Attribute::Private(_) => {}
                Attribute::Wrap(_) => {}
                Attribute::Unwrap(_) => {}
                _ => {
                    tracing::error!(
                        "Invalid attribute: {:?}",
                        Attribute::try_from(*attr).unwrap()
                    );
                    return Err(CKR_ATTRIBUTE_TYPE_INVALID);
                }
            }
        }
        if !key_ops.is_empty() {
            req.attributes.attribute.push(key_ops.into());
        }

        let resp = session
            .client()
            .batch((req, ActivateRequestPayload::default()))
            .unwrap()
            .flatten()
            .unwrap();

        *key = session.new_handle(Handle::SecretKey(resp.0.unique_identifier));
        Ok(())
    })
}

#[apply(pkcs11_export)]
pub unsafe fn C_GenerateKeyPair(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    public_key_template: *mut CK_ATTRIBUTE,
    public_key_attribute_count: ::std::os::raw::c_ulong,
    private_key_template: *mut CK_ATTRIBUTE,
    private_key_attribute_count: ::std::os::raw::c_ulong,
    public_key: *mut CK_OBJECT_HANDLE,
    private_key: *mut CK_OBJECT_HANDLE,
) -> errors::Result<()> {
    ensure_not_null!(
        mechanism,
        public_key_template,
        private_key_template,
        public_key,
        private_key,
    );

    let kty = unsafe {
        match (*mechanism).mechanism {
            CKM_RSA_PKCS_KEY_PAIR_GEN => CryptographicAlgorithm::RSA,
            CKM_EC_KEY_PAIR_GEN => CryptographicAlgorithm::EC,
            other => {
                tracing::error!("Unssuported mechanism {other}");
                return Err(CKR_MECHANISM_INVALID);
            }
        }
    };

    let pub_attrs =
        unsafe { slice::from_raw_parts(public_key_template, public_key_attribute_count as usize) };
    let priv_attrs = unsafe {
        slice::from_raw_parts(private_key_template, private_key_attribute_count as usize)
    };
    tracing::debug!("Public key template: {pub_attrs:?}");
    tracing::debug!("Private key template: {priv_attrs:?}");

    State::get()?.enter_session(session, |mut session| unsafe {
        let mut common_attributes = Vec::from([kty.into()]);
        let mut pub_attributes = Vec::with_capacity(pub_attrs.len());
        let mut priv_attributes = Vec::with_capacity(priv_attrs.len());

        for (attr, attributes) in [
            (pub_attrs, &mut pub_attributes),
            (priv_attrs, &mut priv_attributes),
        ] {
            let mut key_ops = CryptographicUsageMask::empty();
            for attr in attr.iter() {
                match Attribute::try_from(*attr).unwrap() {
                    Attribute::Label(lbl) => {
                        attributes.push(Name::new_string(String::from_utf8(lbl).unwrap()).into())
                    }
                    Attribute::Sign(true) => key_ops |= CryptographicUsageMask::Sign,
                    Attribute::Verify(true) => key_ops |= CryptographicUsageMask::Verify,
                    Attribute::Encrypt(true) => key_ops |= CryptographicUsageMask::Encrypt,
                    Attribute::Decrypt(true) => key_ops |= CryptographicUsageMask::Decrypt,
                    Attribute::ModulusBits(len) => common_attributes
                        .push(CryptographicLength((*len).try_into().unwrap()).into()),
                    Attribute::ValueLen(l) => common_attributes
                        .push(CryptographicLength((*l * 8).try_into().unwrap()).into()),
                    Attribute::Private(_) => {}
                    Attribute::Class(ObjectClass::PRIVATE_KEY | ObjectClass::PUBLIC_KEY) => {}
                    Attribute::KeyType(KeyType::EC)
                        if (*mechanism).mechanism == CKM_EC_KEY_PAIR_GEN => {}
                    Attribute::KeyType(KeyType::RSA)
                        if (*mechanism).mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN => {}
                    Attribute::Token(_) => {}
                    Attribute::Sensitive(s) => attributes.push(Sensitive(s).into()),
                    Attribute::Extractable(e) => attributes.push(Extractable(e).into()),
                    Attribute::PublicExponent(_) => {
                        tracing::warn!("Ignoring public exponent attribute")
                    }
                    Attribute::EcParams(params) => {
                        let params = EcParameters::from_der(&params).unwrap();
                        let oid = match params {
                            EcParameters::NamedCurve(oid) => oid,
                        };
                        let crv = match oid {
                            rfc5912::SECP_256_R_1 => RecommendedCurve::P256,
                            rfc5912::SECP_384_R_1 => RecommendedCurve::P384,
                            rfc5912::SECP_521_R_1 => RecommendedCurve::P521,
                            other => {
                                tracing::error!("Unsupported curve name {other}");
                                return Err(CKR_MECHANISM_INVALID);
                            }
                        };
                        common_attributes.push(
                            CryptographicDomainParameters {
                                recommended_curve: Some(crv),
                                qlength: None,
                            }
                            .into(),
                        )
                    }
                    _ => {
                        tracing::error!(
                            "Invalid attribute: {:?}",
                            Attribute::try_from(*attr).unwrap()
                        );
                        return Err(CKR_ATTRIBUTE_TYPE_INVALID);
                    }
                }
                if !key_ops.is_empty() {
                    attributes.push(key_ops.into());
                }
            }
        }

        let req = CreateKeyPairRequestPayload {
            common_template_attribute: Some(TemplateAttribute::new(common_attributes)),
            private_key_template_attribute: Some(TemplateAttribute::new(priv_attributes)),
            public_key_template_attribute: Some(TemplateAttribute::new(pub_attributes)),
        };

        let resp = session.client().request(req).or(Err(CKR_FUNCTION_FAILED))?;
        session
            .client()
            .activate(&resp.public_key_unique_identifier)
            .and_then(|c| c.activate(Some(resp.private_key_unique_identifier.clone())))
            .exec()
            .to_crv::<CKR_FUNCTION_FAILED>()?
            .flatten()
            .to_crv::<CKR_FUNCTION_FAILED>()?;

        *public_key = session.new_handle(Handle::PublicKey(resp.public_key_unique_identifier));
        *private_key = session.new_handle(Handle::PrivateKey(resp.private_key_unique_identifier));
        Ok(())
    })
}

#[track_caller]
fn map_err<const RV: CK_RV, E: std::fmt::Display>(error: E) -> CK_RV {
    tracing::error!("Error: {error}");
    RV
}

trait ResultExt<T> {
    fn to_crv<const RV: CK_RV>(self) -> Result<T, CK_RV>;
}

impl<T, E: std::fmt::Display> ResultExt<T> for Result<T, E> {
    #[track_caller]
    fn to_crv<const RV: CK_RV>(self) -> Result<T, CK_RV> {
        self.map_err(map_err::<RV, _>)
    }
}
