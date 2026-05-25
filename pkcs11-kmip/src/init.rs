use ::std::os::raw::c_void;
use cryptoki_sys::*;
use macro_rules_attribute::apply;
use std::io::Write;

use crate::{
    core::{Config, State},
    errors,
};

/// C_Initialize initializes the Cryptoki library.  pInitArgs either has the value NULL_PTR or points to a CK_C_INITIALIZE_ARGS
/// structure containing information on how the library should deal with multi-threaded access.
/// If an application will not be accessing Cryptoki through multiple threads simultaneously, it can generally supply the
/// value NULL_PTR to C_Initialize (the consequences of supplying this value will be explained below).
///
/// If pInitArgs is non-NULL_PTR, C_Initialize should cast it to a CK_C_INITIALIZE_ARGS_PTR and then dereference the
/// resulting pointer to obtain the CK_C_INITIALIZE_ARGS fields CreateMutex, DestroyMutex, LockMutex, UnlockMutex, flags, and pReserved.
/// For this version of Cryptoki, the value of pReserved thereby obtained MUST be NULL_PTR; if it’s not,
/// then C_Initialize should return with the value CKR_ARGUMENTS_BAD.
///
/// If the CKF_LIBRARY_CANT_CREATE_OS_THREADS flag in the flags field is set, that indicates that application threads which are
/// executing calls to the Cryptoki library are not permitted to use the native operation system calls to spawn off new threads.
/// In other words, the library’s code may not create its own threads.  If the library is unable to function properly under this restriction,
/// C_Initialize should return with the value CKR_NEED_TO_CREATE_THREADS.
///
/// A call to C_Initialize specifies one of four different ways to support multi-threaded access via the value of the CKF_OS_LOCKING_OK
/// flag in the flags field and the values of the CreateMutex, DestroyMutex, LockMutex, and UnlockMutex function pointer fields:
/// 1. If the flag isn’t set, and the function pointer fields aren’t supplied (i.e., they all have the value NULL_PTR),
///    that means that the application won’t be accessing the Cryptoki library from multiple threads simultaneously.
/// 2. If the flag is set, and the function pointer fields aren’t supplied (i.e., they all have the value NULL_PTR),
///    that means that the application will be performing multi-threaded Cryptoki access, and the library needs to use the native operating system primitives to ensure safe multi-threaded access.  If the library is unable to do this, C_Initialize should return with the value CKR_CANT_LOCK.
/// 3. If the flag isn’t set, and the function pointer fields are supplied (i.e., they all have non-NULL_PTR values),
///    that means that the application will be performing multi-threaded Cryptoki access, and the library needs to use the supplied function pointers for mutex-handling to ensure safe multi-threaded access.  If the library is unable to do this, C_Initialize should return with the value CKR_CANT_LOCK.
/// 4. If the flag is set, and the function pointer fields are supplied (i.e., they all have non-NULL_PTR values),
///    that means that the application will be performing multi-threaded Cryptoki access, and the library needs to use either the native operating system primitives or the supplied function pointers for mutex-handling to ensure safe multi-threaded access.  If the library is unable to do this, C_Initialize should return with the value CKR_CANT_LOCK.
///
/// If some, but not all, of the supplied function pointers to C_Initialize are non-NULL_PTR, then C_Initialize should return
/// with the value CKR_ARGUMENTS_BAD.
///
/// A call to C_Initialize with pInitArgs set to NULL_PTR is treated like a call to C_Initialize with pInitArgs pointing
/// to a CK_C_INITIALIZE_ARGS which has the CreateMutex, DestroyMutex, LockMutex, UnlockMutex, and pReserved fields set to NULL_PTR,
/// and has the flags field set to 0.
///
/// C_Initialize should be the first Cryptoki call made by an application, except for calls to C_GetFunctionList.
/// What this function actually does is implementation-dependent; typically, it might cause Cryptoki to initialize its
/// internal memory buffers, or any other resources it requires.
///
/// If several applications are using Cryptoki, each one should call C_Initialize.  Every call to C_Initialize should (eventually)
/// be succeeded by a single call to C_Finalize.  See [PKCS11-UG] for further details.
///
/// # Returns
/// CKR_ARGUMENTS_BAD, CKR_CANT_LOCK, CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR,
/// CKR_HOST_MEMORY, CKR_NEED_TO_CREATE_THREADS, CKR_OK.
#[apply(pkcs11_export)]
pub unsafe fn C_Initialize(init_args: *mut c_void) -> errors::Result<()> {
    let cfg = Config::from_env().map_err(|e| {
        eprintln!("Error loading config: {:?}", e);
        CKR_ARGUMENTS_BAD
    })?;
    super::core::setup_logging(&cfg);
    tracing::debug!("Initializing PKCS#11 library with config: {:?}", cfg);

    let init_args = init_args as CK_C_INITIALIZE_ARGS_PTR;
    unsafe {
        if !init_args.is_null() && !(*init_args).pReserved.is_null() {
            return Err(CKR_ARGUMENTS_BAD);
        }
        if !init_args.is_null() && (*init_args).flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS != 0 {
            return Err(CKR_NEED_TO_CREATE_THREADS);
        }
        if !init_args.is_null()
            && (*init_args).flags & CKF_OS_LOCKING_OK == 0
            && let CK_C_INITIALIZE_ARGS {
                CreateMutex: Some(_),
                DestroyMutex: Some(_),
                LockMutex: Some(_),
                UnlockMutex: Some(_),
                ..
            } = *init_args
        {
            return Err(CKR_CANT_LOCK);
        }
    }

    State::initialize(cfg)
}

/// C_Finalize is called to indicate that an application is finished with the Cryptoki library.
/// It should be the last Cryptoki call made by an application.  The pReserved parameter is reserved for future versions;
/// for this version, it should be set to NULL_PTR (if C_Finalize is called with a non-NULL_PTR value for pReserved,
/// it should return the value CKR_ARGUMENTS_BAD.
///
/// If several applications are using Cryptoki, each one should call C_Finalize.  Each application’s call to C_Finalize
/// should be preceded by a single call to C_Initialize; in between the two calls, an application can make calls to other
/// Cryptoki functions.  See [PKCS11-UG] for further details.
///
/// Despite the fact that the parameters supplied to C_Initialize can in general allow for safe multi-threaded access to a C
/// ryptoki library, the behavior of C_Finalize is nevertheless undefined if it is called by an application while other threads
/// of the application are making Cryptoki calls.  The exception to this exceptional behavior of C_Finalize occurs when a
/// thread calls C_Finalize while another of the application’s threads is blocking on Cryptoki’s C_WaitForSlotEvent function.
/// When this happens, the blocked thread becomes unblocked and returns the value CKR_CRYPTOKI_NOT_INITIALIZED.
/// See C_WaitForSlotEvent for more information.
///
/// # Returns
/// CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK.
#[apply(pkcs11_export)]
pub unsafe fn C_Finalize(p_reserved: *mut c_void) -> errors::Result<()> {
    if !p_reserved.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    State::finalize()
}

/// C_GetInfo returns general information about Cryptoki.  pInfo points to the location that receives the information.
///
/// # Returns
/// CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK.
#[apply(pkcs11_export)]
pub unsafe fn C_GetInfo(info: *mut CK_INFO) -> errors::Result<()> {
    ensure_not_null!(info);
    State::get()?;
    unsafe {
        (*info).cryptokiVersion = super::FUNCLIST.version;
        (*info).manufacturerID.fill(b' ');
        (*info).libraryDescription.fill(b' ');
        (&mut (&mut *info).manufacturerID[..])
            .write_all(b"kmip-rs")
            .unwrap();
        (&mut (&mut *info).libraryDescription[..])
            .write_all(b"kmip-rs")
            .unwrap();
        (*info).libraryVersion = CK_VERSION {
            major: super::VERSION_MAJOR.parse().unwrap_or_default(),
            minor: super::VERSION_MINOR.parse().unwrap_or_default(),
        };
        (*info).flags = 0;
    }
    Ok(())
}
