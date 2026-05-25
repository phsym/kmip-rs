use cryptoki_sys::*;
use macro_rules_attribute::apply;

use crate::errors;

/// In previous versions of Cryptoki, C_GetFunctionStatus obtained the status of a function running in parallel with an application.
/// Now, however, C_GetFunctionStatus is a legacy function which should simply return the value CKR_FUNCTION_NOT_PARALLEL.
/// # Returns
/// CKR_FUNCTION_NOT_PARALLEL
#[apply(pkcs11_export)]
pub unsafe fn C_GetFunctionStatus(_session: CK_SESSION_HANDLE) -> errors::Result<()> {
    Err(CKR_FUNCTION_NOT_PARALLEL)
}

/// In previous versions of Cryptoki, C_CancelFunction cancelled a function running in parallel with an application.
/// Now, however, C_CancelFunction is a legacy function which should simply return the value CKR_FUNCTION_NOT_PARALLEL.
/// # Returns
/// CKR_FUNCTION_NOT_PARALLEL
#[apply(pkcs11_export)]
pub unsafe fn C_CancelFunction(_session: CK_SESSION_HANDLE) -> errors::Result<()> {
    Err(CKR_FUNCTION_NOT_PARALLEL)
}
