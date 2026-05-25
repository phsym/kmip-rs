use std::io::Write;

use cryptoki_sys::*;
use macro_rules_attribute::apply;

use crate::{core::State, errors};

decl_mechanisms!(
// The AES key generation mechanism, denoted CKM_AES_KEY_GEN, is a key generation mechanism for NIST’s Advanced Encryption Standard.
//
// It does not have a parameter.
// The mechanism generates AES keys with a particular length in bytes, as specified in the CKA_VALUE_LEN attribute of the template for the key.
// The mechanism contributes the CKA_CLASS, CKA_KEY_TYPE, and CKA_VALUE attributes to the new key. Other attributes supported by
// the AES key type (specifically, the flags indicating which functions the key supports) may be specified in the template for the key,
// or else are assigned default initial values.
// For this mechanism, the ulMinKeySize and ulMaxKeySize fields of the CK_MECHANISM_INFO structure specify the supported
// range of AES key sizes, in bytes.
    CKM_AES_KEY_GEN: {
        flags: CKF_GENERATE,
        ulMinKeySize: 16,
        ulMaxKeySize: 32,
    },

    CKM_RSA_PKCS_KEY_PAIR_GEN: {
        flags: CKF_GENERATE_KEY_PAIR,
        ulMinKeySize: 1024,
        ulMaxKeySize: 4096,
    },
    CKM_AES_ECB: {
        flags: CKF_ENCRYPT | CKF_DECRYPT,
        ulMinKeySize: 16,
        ulMaxKeySize: 32,
    },
    CKM_AES_CBC: {
        flags: CKF_ENCRYPT | CKF_DECRYPT,
        ulMinKeySize: 16,
        ulMaxKeySize: 32,
    },
    CKM_AES_CBC_PAD: {
        flags: CKF_ENCRYPT | CKF_DECRYPT,
        ulMinKeySize: 16,
        ulMaxKeySize: 32,
    },
    CKM_AES_GCM: {
        flags: CKF_ENCRYPT | CKF_DECRYPT,
        ulMinKeySize: 16,
        ulMaxKeySize: 32,
    },
    CKM_RSA_PKCS: {
        flags: CKF_SIGN | CKF_VERIFY,
        ulMinKeySize: 1024,
        ulMaxKeySize: 4096,
    },
    CKM_SHA256_RSA_PKCS: {
        flags: CKF_SIGN | CKF_VERIFY,
        ulMinKeySize: 1024,
        ulMaxKeySize: 4096,
    },
    CKM_SHA384_RSA_PKCS:{
        flags: CKF_SIGN | CKF_VERIFY,
        ulMinKeySize: 1024,
        ulMaxKeySize: 4096,
    },
    CKM_SHA512_RSA_PKCS:{
        flags: CKF_SIGN | CKF_VERIFY,
        ulMinKeySize: 1024,
        ulMaxKeySize: 4096,
    },

    CKM_RSA_PKCS_PSS: {
        flags: CKF_SIGN | CKF_VERIFY,
        ulMinKeySize: 1024,
        ulMaxKeySize: 4096,
    },
    CKM_SHA256_RSA_PKCS_PSS: {
        flags: CKF_SIGN | CKF_VERIFY,
        ulMinKeySize: 1024,
        ulMaxKeySize: 4096,
    },
    CKM_SHA384_RSA_PKCS_PSS: {
        flags: CKF_SIGN | CKF_VERIFY,
        ulMinKeySize: 1024,
        ulMaxKeySize: 4096,
    },
    CKM_SHA512_RSA_PKCS_PSS: {
        flags: CKF_SIGN | CKF_VERIFY,
        ulMinKeySize: 1024,
        ulMaxKeySize: 4096,
    },

    CKM_EC_KEY_PAIR_GEN: {
        flags: CKF_GENERATE_KEY_PAIR,
        ulMinKeySize: 256,
        ulMaxKeySize: 521,
    },
    CKM_ECDSA_SHA256: {
        flags: CKF_SIGN | CKF_VERIFY,
        ulMinKeySize: 256,
        ulMaxKeySize: 521,
    },
    CKM_ECDSA_SHA384: {
        flags: CKF_SIGN | CKF_VERIFY,
        ulMinKeySize: 256,
        ulMaxKeySize: 521,
    },
    CKM_ECDSA_SHA512: {
        flags: CKF_SIGN | CKF_VERIFY,
        ulMinKeySize: 256,
        ulMaxKeySize: 521,
    },
    CKM_ECDSA: {
        flags: CKF_SIGN | CKF_VERIFY,
        ulMinKeySize: 256,
        ulMaxKeySize: 521,
    },
);

/// C_GetSlotList is used to obtain a list of slots in the system. tokenPresent indicates whether the list obtained includes
/// only those slots with a token present (CK_TRUE), or all slots (CK_FALSE); pulCount points to the location that receives the number of slots.
///
/// There are two ways for an application to call C_GetSlotList:
/// 1. If pSlotList is NULL_PTR, then all that C_GetSlotList does is return (in *pulCount) the number of slots,
///    without actually returning a list of slots.  The contents of the buffer pointed to by pulCount on entry to C_GetSlotList
///    has no meaning in this case, and the call returns the value CKR_OK.
/// 2. If pSlotList is not NULL_PTR, then *pulCount MUST contain the size (in terms of CK_SLOT_ID elements) of the buffer pointed
///    to by pSlotList.  If that buffer is large enough to hold the list of slots, then the list is returned in it, and CKR_OK is returned.  
///    If not, then the call to C_GetSlotList returns the value CKR_BUFFER_TOO_SMALL.  In either case, the value *pulCount is set to hold the
///    number of slots.
///
/// Because C_GetSlotList does not allocate any space of its own, an application will often call C_GetSlotList twice
/// (or sometimes even more times—if an application is trying to get a list of all slots with a token present,
/// then the number of such slots can (unfortunately) change between when the application asks for how many such slots there are and
/// when the application asks for the slots themselves).  However, multiple calls to C_GetSlotList are by no means required.
///
/// All slots which C_GetSlotList reports MUST be able to be queried as valid slots by C_GetSlotInfo.  Furthermore, the set of slots
/// accessible through a Cryptoki library is checked at the time that C_GetSlotList, for list length prediction (NULL pSlotList argument) is called.
/// If an application calls C_GetSlotList with a non-NULL pSlotList, and then the user adds or removes a hardware device,
/// the changed slot list will only be visible and effective if C_GetSlotList is called again with NULL. Even if C_ GetSlotList is
/// successfully called this way, it may or may not be the case that the changed slot list will be successfully recognized depending
/// on the library implementation.  On some platforms, or earlier PKCS11 compliant libraries, it may be necessary to successfully call
/// C_Initialize or to restart the entire system.
///
/// # Returns
/// CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK.
#[apply(pkcs11_export)]
pub unsafe fn C_GetSlotList(
    _token_present: ::std::os::raw::c_uchar,
    slot_list: *mut CK_SLOT_ID,
    ul_count: *mut ::std::os::raw::c_ulong,
) -> errors::Result<()> {
    ensure_not_null!(ul_count);

    State::get()?;
    unsafe {
        if !slot_list.is_null() {
            if *ul_count < 1 {
                *ul_count = 1;
                return Err(CKR_BUFFER_TOO_SMALL);
            }
            *slot_list = 0;
        }
        *ul_count = 1;
    }
    Ok(())
}

/// C_GetSlotInfo obtains information about a particular slot in the system. slotID is the ID of the slot;
/// pInfo points to the location that receives the slot information.
///
/// # Returns
/// CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR,
/// CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID.
#[apply(pkcs11_export)]
pub unsafe fn C_GetSlotInfo(slot_id: CK_SLOT_ID, info: *mut CK_SLOT_INFO) -> errors::Result<()> {
    if slot_id != 0 {
        return Err(CKR_SLOT_ID_INVALID);
    }
    ensure_not_null!(info);

    State::get()?;
    unsafe {
        (*info).flags = CKF_TOKEN_PRESENT;
        (*info).manufacturerID.fill(b' ');
        (*info).slotDescription.fill(b' ');
        (&mut (&mut *info).manufacturerID[..])
            .write_all(b"kmip-rs")
            .unwrap();
        (&mut (&mut *info).slotDescription[..])
            .write_all(b"kmip-rs")
            .unwrap();
        //TODO: Update versions maybe ?
        (*info).firmwareVersion = CK_VERSION { major: 0, minor: 0 };
        (*info).hardwareVersion = CK_VERSION { major: 0, minor: 0 };
    }
    Ok(())
}

/// C_GetTokenInfo obtains information about a particular token in the system.  slotID is the ID of the token’s slot;
/// pInfo points to the location that receives the token information.
///
/// # Returns
/// CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR,
/// CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD.
#[apply(pkcs11_export)]
pub unsafe fn C_GetTokenInfo(slot_id: CK_SLOT_ID, info: *mut CK_TOKEN_INFO) -> errors::Result<()> {
    if slot_id != 0 {
        return Err(CKR_SLOT_ID_INVALID);
    }
    ensure_not_null!(info);

    let gstate = State::get()?;
    unsafe {
        (*info).label.fill(b' ');
        (*info).manufacturerID.fill(b' ');
        (*info).model.fill(b' ');
        (*info).serialNumber.fill(b' ');

        (&mut (&mut *info).label[..]).write_all(b"kmip-rs").unwrap();

        (&mut (&mut *info).manufacturerID[..])
            .write_all(b"kmip-rs")
            .unwrap();

        (&mut (&mut *info).model[..]).write_all(b"kmip-rs").unwrap();

        (*info).flags = CKF_TOKEN_INITIALIZED
            | CKF_PROTECTED_AUTHENTICATION_PATH
            | CKF_LOGIN_REQUIRED
            | CKF_CLOCK_ON_TOKEN
            | CKF_RNG;

        (*info).firmwareVersion = CK_VERSION { major: 0, minor: 0 };
        (*info).hardwareVersion = CK_VERSION { major: 0, minor: 0 };
        (*info).ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
        (*info).ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
        (*info).ulMaxPinLen = CK_UNAVAILABLE_INFORMATION;
        (*info).ulMinPinLen = CK_UNAVAILABLE_INFORMATION;
        (*info).ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
        (*info).ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
        (*info).ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
        (*info).ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
        (*info).ulRwSessionCount = gstate.rw_session_count() as u64;
        (*info).ulSessionCount = gstate.active_session_count() as u64;

        // Current time as a character-string of length 16, represented in the format YYYYMMDDhhmmssxx (4 characters for the year;
        // 2 characters each for the month, the day, the hour, the minute, and the second; and 2 additional reserved ‘0’ characters).
        // The value of this field only makes sense for tokens equipped with a clock, as indicated in the token information flags (see below)
        let dt = chrono::Utc::now().format("%Y%m%d%H%M%S00");
        (&mut (&mut *info).utcTime[..])
            .write_fmt(format_args!("{dt}"))
            .unwrap();
    }

    Ok(())
}

/// C_GetMechanismList is used to obtain a list of mechanism types supported by a token.  SlotID is the ID of the token’s slot;
/// pulCount points to the location that receives the number of mechanisms.
///
/// There are two ways for an application to call C_GetMechanismList:
/// 1. If pMechanismList is NULL_PTR, then all that C_GetMechanismList does is return (in *pulCount) the number of mechanisms,
///    without actually returning a list of mechanisms.  The contents of *pulCount on entry to C_GetMechanismList has no meaning in this case, and the call returns the value CKR_OK.
/// 2. If pMechanismList is not NULL_PTR, then *pulCount MUST contain the size (in terms of CK_MECHANISM_TYPE elements) of the buffer
///    pointed to by pMechanismList.  If that buffer is large enough to hold the list of mechanisms, then the list is returned in it, and CKR_OK is returned.  If not, then the call to C_GetMechanismList returns the value CKR_BUFFER_TOO_SMALL.  In either case, the value *pulCount is set to hold the number of mechanisms.
///
/// Because C_GetMechanismList does not allocate any space of its own, an application will often call C_GetMechanismList twice.  
/// However, this behavior is by no means required.
///
/// # Returns
/// CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
/// CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD.
#[apply(pkcs11_export)]
pub unsafe fn C_GetMechanismList(
    slot_id: CK_SLOT_ID,
    mechanism_list: *mut CK_MECHANISM_TYPE,
    ul_count: *mut CK_ULONG,
) -> errors::Result<()> {
    if slot_id != 0 {
        return Err(CKR_SLOT_ID_INVALID);
    }
    ensure_not_null!(ul_count);

    State::get()?;
    unsafe {
        if !mechanism_list.is_null() {
            if *ul_count < MECHANISMS_TYPES.len() as CK_ULONG {
                *ul_count = MECHANISMS_TYPES.len() as CK_ULONG;
                return Err(CKR_BUFFER_TOO_SMALL);
            }
            mechanism_list
                .copy_from_nonoverlapping(MECHANISMS_TYPES.as_ptr(), MECHANISMS_TYPES.len())
        }
        *ul_count = MECHANISMS_TYPES.len() as CK_ULONG;
    }
    Ok(())
}

/// C_GetMechanismInfo obtains information about a particular mechanism possibly supported by a token.
/// slotID is the ID of the token’s slot; type is the type of mechanism; pInfo points to the location that receives the mechanism information.
///
/// # Returns
/// CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
/// CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_MECHANISM_INVALID, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT,
/// CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD.
#[apply(pkcs11_export)]
pub unsafe fn C_GetMechanismInfo(
    slot_id: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    info: *mut CK_MECHANISM_INFO,
) -> errors::Result<()> {
    if slot_id != 0 {
        return Err(CKR_SLOT_ID_INVALID);
    }
    ensure_not_null!(info);

    State::get()?;
    unsafe {
        *info = *MECHANISMS.get(&type_).ok_or_else(|| {
            tracing::error!("ERROR: invalid mechanism type {}", type_.to_string());
            CKR_MECHANISM_INVALID
        })?;
    }
    Ok(())
}
