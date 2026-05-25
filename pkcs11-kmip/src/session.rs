use cryptoki_sys::*;
use macro_rules_attribute::apply;

use crate::{core::State, errors};

/// C_OpenSession opens a session between an application and a token in a particular slot.  slotID is the slot’s ID;
/// flags indicates the type of session; pApplication is an application-defined pointer to be passed to the notification callback;
/// Notify is the address of the notification callback function (see Section 5.16);
/// phSession points to the location that receives the handle for the new session.
///
/// When opening a session with C_OpenSession, the flags parameter consists of the logical OR of zero or more bit flags
/// defined in the CK_SESSION_INFO data type.  For legacy reasons, the CKF_SERIAL_SESSION bit MUST always be set;
/// if a call to C_OpenSession does not have this bit set, the call should return unsuccessfully with the error
/// code CKR_SESSION_PARALLEL_NOT_SUPPORTED.
///
/// There may be a limit on the number of concurrent sessions an application may have with the token,
/// which may depend on whether the session is “read-only” or “read/write”.  An attempt to open a session which does not
/// succeed because there are too many existing sessions of some type should return CKR_SESSION_COUNT.
///
/// If the token is write-protected (as indicated in the CK_TOKEN_INFO structure), then only read-only sessions may be opened with it.
///
/// If the application calling C_OpenSession already has a R/W SO session open with the token, then any attempt to open a R/O session
///  with the token fails with error code CKR_SESSION_READ_WRITE_SO_EXISTS (see [PKCS11-UG] for further details).
///
/// The Notify callback function is used by Cryptoki to notify the application of certain events.  
/// If the application does not wish to support callbacks, it should pass a value of NULL_PTR as the Notify parameter.  
/// See Section 5.16 for more information about application callbacks.
///
/// # Returns
/// CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
/// CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_COUNT, CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SESSION_READ_WRITE_SO_EXISTS,
/// CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_TOKEN_WRITE_PROTECTED, CKR_ARGUMENTS_BAD.
#[apply(pkcs11_export)]
pub unsafe fn C_OpenSession(
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
    _application: *mut ::std::os::raw::c_void,
    _notify: CK_NOTIFY,
    session: *mut CK_SESSION_HANDLE,
) -> errors::Result<()> {
    if slot_id != 0 {
        return Err(CKR_SLOT_ID_INVALID);
    }
    ensure_not_null!(session);

    if flags & CKF_SERIAL_SESSION == 0 {
        return Err(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
    }

    let rw = flags & CKF_RW_SESSION > 0;
    unsafe { *session = State::get()?.create_session(rw)? };
    Ok(())
}

/// C_CloseSession closes a session between an application and a token.  hSession is the session’s handle.
///
/// When a session is closed, all session objects created by the session are destroyed automatically,
/// even if the application has other sessions “using” the objects (see [PKCS11-UG] for further details).
///
/// If this function is successful and it closes the last session between the application and the token,
/// the login state of the token for the application returns to public sessions. Any new sessions to the token opened
/// by the application will be either R/O Public or R/W Public sessions.
///
/// Depending on the token, when the last open session any application has with the token is closed,
/// the token may be “ejected” from its reader (if this capability exists).
///
/// Despite the fact this C_CloseSession is supposed to close a session, the return value CKR_SESSION_CLOSED is an error return.  
/// It actually indicates the (probably somewhat unlikely) event that while this function call was executing,
/// another call was made to C_CloseSession to close this particular session, and that call finished executing first.
/// Such uses of sessions are a bad idea, and Cryptoki makes little promise of what will occur in general if an application
/// indulges in this sort of behavior.
///
/// # Return
/// CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
/// CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID.
#[apply(pkcs11_export)]
pub unsafe fn C_CloseSession(session: CK_SESSION_HANDLE) -> errors::Result<()> {
    State::get()?.close_session(session)?;
    Ok(())
}

/// C_CloseAllSessions closes all sessions an application has with a token. slotID specifies the token’s slot.
///
/// When a session is closed, all session objects created by the session are destroyed automatically.
///
/// After successful execution of this function, the login state of the token for the application returns to public sessions.
/// Any new sessions to the token opened by the application will be either R/O Public or R/W Public sessions.
///
/// Depending on the token, when the last open session any application has with the token is closed, the token may be “ejected”
/// from its reader (if this capability exists).
///
/// # Returns
/// CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
/// CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT.
#[apply(pkcs11_export)]
pub unsafe fn C_CloseAllSessions(slot_id: CK_SLOT_ID) -> errors::Result<()> {
    if slot_id != 0 {
        return Err(CKR_SLOT_ID_INVALID);
    }
    State::get()?.close_all_sessions();
    Ok(())
}

/// C_GetSessionInfo obtains information about a session.  hSession is the session’s handle;
/// pInfo points to the location that receives the session information.
///
/// # Returns
/// CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED,
/// CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_ARGUMENTS_BAD.
#[apply(pkcs11_export)]
pub unsafe fn C_GetSessionInfo(
    session: CK_SESSION_HANDLE,
    info: *mut CK_SESSION_INFO,
) -> errors::Result<()> {
    ensure_not_null!(info);

    let gstate = State::get()?;
    let session = gstate.get_session(session)?;
    let session = session.lock();
    unsafe {
        (*info).slotID = 0;
        (*info).state = 0;
        (*info).ulDeviceError = 0;
        (*info).flags = CKF_SERIAL_SESSION;
        if session.is_rw() {
            (*info).flags |= CKF_RW_SESSION;
            (*info).state |= if gstate.is_logged_in() {
                CKS_RW_USER_FUNCTIONS
            } else {
                CKS_RW_PUBLIC_SESSION
            };
        } else {
            (*info).state |= if gstate.is_logged_in() {
                CKS_RO_USER_FUNCTIONS
            } else {
                CKS_RO_PUBLIC_SESSION
            };
        }
    }
    Ok(())
}

/// C_Login logs a user into a token.  hSession is a session handle; userType is the user type; pPin points to the user’s PIN;
/// ulPinLen is the length of the PIN. This standard allows PIN values to contain any valid UTF8 character, but the token may
/// impose subset restrictions.
///
/// When the user type is either CKU_SO or CKU_USER, if the call succeeds, each of the application's sessions will
///  enter either the "R/W SO Functions" state, the "R/W User Functions" state, or the "R/O User Functions" state.
/// If the user type is CKU_CONTEXT_SPECIFIC , the behavior of C_Login depends on the context in which it is called.
/// Improper use of this user type will result in a return value  CKR_OPERATION_NOT_INITIALIZED..
///
/// If the token has a “protected authentication path”, as indicated by the CKF_PROTECTED_AUTHENTICATION_PATH flag in
/// its CK_TOKEN_INFO being set, then that means that there is some way for a user to be authenticated to the token without having
/// to send a PIN through the Cryptoki library.  One such possibility is that the user enters a PIN on a PIN pad on the token itself,
/// or on the slot device.  Or the user might not even use a PIN—authentication could be achieved by some fingerprint-reading device,
/// for example.  To log into a token with a protected authentication path, the pPin parameter to C_Login should be NULL_PTR.  
/// When C_Login returns, whatever authentication method supported by the token will have been performed; a return value of CKR_OK means
/// that the user was successfully authenticated, and a return value of CKR_PIN_INCORRECT means that the user was denied access.
///
/// If there are any active cryptographic or object finding operations in an application’s session, and then C_Login is successfully
/// executed by that application, it may or may not be the case that those operations are still active.  
/// Therefore, before logging in, any active operations should be finished.
///
/// If the application calling C_Login has a R/O session open with the token, then it will be unable to log the SO into a
/// session (see [PKCS11-UG] for further details).  An attempt to do this will result in the error code CKR_SESSION_READ_ONLY_EXISTS.
///
/// C_Login may be called repeatedly, without intervening C_Logout calls, if (and only if) a key with the CKA_ALWAYS_AUTHENTICATE
/// attribute set to CK_TRUE exists, and the user needs to do cryptographic operation on this key. See further Section 4.9.
///
/// # Returns
/// CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED,
/// CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_PIN_INCORRECT, CKR_PIN_LOCKED,
/// CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY_EXISTS, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
/// CKR_USER_PIN_NOT_INITIALIZED, CKR_USER_TOO_MANY_TYPES, CKR_USER_TYPE_INVALID.
#[apply(pkcs11_export)]
pub unsafe fn C_Login(
    session: CK_SESSION_HANDLE,
    user_type: CK_USER_TYPE,
    _pin: *mut CK_UTF8CHAR,
    _pin_len: CK_ULONG,
) -> errors::Result<()> {
    let gstate = State::get()?;
    gstate.get_session(session)?;
    if user_type != CKU_USER {
        return Err(CKR_USER_TYPE_INVALID);
    }
    gstate.login();
    Ok(())
}

/// C_Logout logs a user out from a token.  hSession is the session’s handle.
///
/// Depending on the current user type, if the call succeeds, each of the application’s sessions will enter either
/// the “R/W Public Session” state or the “R/O Public Session” state.
///
/// When C_Logout successfully executes, any of the application’s handles to private objects become invalid
/// (even if a user is later logged back into the token, those handles remain invalid).  
/// In addition, all private session objects from sessions belonging to the application are destroyed.
///
/// If there are any active cryptographic or object-finding operations in an application’s session, and then C_Logout
/// is successfully executed by that application, it may or may not be the case that those operations are still active.
/// Therefore, before logging out, any active operations should be finished.
///
/// # Returns
/// CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR,
/// CKR_HOST_MEMORY, CKR_OK, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN.
#[apply(pkcs11_export)]
pub unsafe fn C_Logout(session: CK_SESSION_HANDLE) -> errors::Result<()> {
    let gstate = State::get()?;
    gstate.get_session(session)?;
    gstate.logout();
    Ok(())
}
