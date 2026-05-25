use cryptoki_sys::*;
use macro_rules_attribute::apply;

use crate::{core::State, errors};

/// C_SeedRandom mixes additional seed material into the token’s random number generator.
/// hSession is the session’s handle; pSeed points to the seed material; and ulSeedLen is the length in bytes of the seed material.
///
/// # Returns
/// CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED,
/// CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_ACTIVE, CKR_RANDOM_SEED_NOT_SUPPORTED,
/// CKR_RANDOM_NO_RNG, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN.
#[apply(pkcs11_export)]
pub unsafe fn C_SeedRandom(
    session: CK_SESSION_HANDLE,
    seed: *mut CK_BYTE,
    _seed_len: CK_ULONG,
) -> errors::Result<()> {
    ensure_not_null!(seed);
    State::get()?.get_session(session)?;
    tracing::warn!("C_SeedRandom is not supported");
    Err(CKR_RANDOM_SEED_NOT_SUPPORTED)
}

/// C_GenerateRandom generates random or pseudo-random data. hSession is the session’s handle;
/// pRandomData points to the location that receives the random data;
/// and ulRandomLen is the length in bytes of the randomor pseudo-random data to be generated.
///
/// # Returns
/// CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED,
/// CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_ACTIVE, CKR_RANDOM_NO_RNG, CKR_SESSION_CLOSED,
/// CKR_SESSION_HANDLE_INVALID, CKR_USER_NOT_LOGGED_IN.
#[apply(pkcs11_export)]
pub unsafe fn C_GenerateRandom(
    _session: CK_SESSION_HANDLE,
    random_data: *mut CK_BYTE,
    random_len: CK_ULONG,
) -> errors::Result<()> {
    ensure_not_null!(random_data);
    if random_len == 0 {
        return Ok(());
    }

    // let gstate = State::get()?;
    // let session = gstate.get_session(session)?;
    // let client = session.lock().client();
    // let rlen = random_len.try_into().or(Err(CKR_ARGUMENTS_BAD))?;
    // let resp = client.generate_random_bytes(rlen)
    //     .or(Err(CKR_FUNCTION_FAILED))?;
    // let random_data = unsafe {
    //     std::slice::from_raw_parts_mut(
    //         random_data,
    //         random_len.try_into().or(Err(CKR_ARGUMENTS_BAD))?,
    //     )
    // };
    // random_data.copy_from_slice(&resp.bytes);
    // Ok(())
    Err(CKR_FUNCTION_NOT_SUPPORTED)
}
