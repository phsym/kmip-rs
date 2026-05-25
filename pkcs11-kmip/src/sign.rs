use std::slice;

use cryptoki_sys::*;
use kmip::enums::ValidityIndicator;
use macro_rules_attribute::apply;

use crate::{
    core::{Handle, SessionState, State},
    errors,
    mapping::SignVerifyMode,
};

#[apply(pkcs11_export)]
pub unsafe fn C_SignInit(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> errors::Result<()> {
    ensure_not_null!(mechanism);
    State::get()?.enter_session(session, |mut session| unsafe {
        tracing::debug!("mechanism: {:?}", *mechanism);

        let sign_mode = SignVerifyMode::try_from(&*mechanism)?;

        let key = session.get_handle(key)?;
        let key_id = match key {
            Handle::PrivateKey(id) => id.clone(),
            _ => return Err(CKR_KEY_HANDLE_INVALID),
        };
        session.set_state(SessionState::Sign(key_id, sign_mode));
        Ok(())
    })
}

#[apply(pkcs11_export)]
pub unsafe fn C_Sign(
    session: CK_SESSION_HANDLE,
    data: *mut CK_BYTE,
    data_len: CK_ULONG,
    signature: *mut CK_BYTE,
    signature_len: *mut CK_ULONG,
) -> errors::Result<()> {
    ensure_not_null!(data, signature_len);
    let state = State::get()?;
    state.enter_session(session, |mut session| unsafe {
        let mut data = slice::from_raw_parts(data, data_len as usize);

        if let SessionState::Signed(cached_data, sign) = session.get_state() {
            if cached_data != data {
                tracing::error!("Data does not match the previously signed data");
                return Err(CKR_DATA_INVALID);
            }
            if signature.is_null() {
                *signature_len = sign.len() as CK_ULONG;
                return Ok(()); // stay in Signed
            }
            if *signature_len < sign.len() as CK_ULONG {
                tracing::error!(
                    "too small. Expected {} but got {}",
                    sign.len(),
                    *signature_len,
                );
                *signature_len = sign.len() as CK_ULONG;
                return Err(CKR_BUFFER_TOO_SMALL);
            }
            signature.copy_from_nonoverlapping(sign.as_ptr(), sign.len());
            *signature_len = sign.len() as CK_ULONG;
            session.set_state(SessionState::Idle);
            return Ok(());
        }
        let SessionState::Sign(key, mode) = session.get_state() else {
            return Err(CKR_OPERATION_NOT_INITIALIZED);
        };
        let key = key.clone();

        tracing::trace!("Data Length = {data_len}");
        tracing::trace!("Data = {data:?}");

        let (alg, is_digest) = mode.to_crypto_params(&mut data)?;

        let req = session
            .client()
            .sign(key)
            .with_cryptographic_parameters(alg);
        let req = if is_digest {
            req.digested_data(data)
        } else {
            req.data(data)
        };

        let resp = req.exec().map_err(|_| CKR_FUNCTION_FAILED)?;

        let signature_data = resp.signature_data.unwrap();
        tracing::trace!("Signature Length = {}", signature_data.len());
        tracing::trace!("Signature = {signature_data:?}");

        if signature.is_null() {
            *signature_len = signature_data.len() as CK_ULONG;
            session.set_state(SessionState::Signed(data.to_vec(), signature_data));
            return Ok(());
        }

        if *signature_len < signature_data.len() as CK_ULONG {
            tracing::error!(
                "too small. Expected {} but got {}",
                signature_data.len(),
                *signature_len,
            );
            *signature_len = signature_data.len() as CK_ULONG;
            session.set_state(SessionState::Signed(data.to_vec(), signature_data));
            return Err(CKR_BUFFER_TOO_SMALL);
        }

        signature.copy_from_nonoverlapping(signature_data.as_ptr(), signature_data.len());
        *signature_len = signature_data.len() as CK_ULONG;

        session.set_state(SessionState::Idle);
        Ok(())
    })
}

#[apply(pkcs11_export)]
pub unsafe fn C_VerifyInit(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> errors::Result<()> {
    ensure_not_null!(mechanism);
    State::get()?.enter_session(session, |mut session| unsafe {
        tracing::trace!("mechanism: {:?}", *mechanism);

        let sign_mode = SignVerifyMode::try_from(&*mechanism)?;

        let key = session.get_handle(key)?;
        let key_id = match key {
            Handle::PublicKey(id) => id.clone(),
            _ => return Err(CKR_KEY_HANDLE_INVALID),
        };
        session.set_state(SessionState::Verify(key_id, sign_mode));
        Ok(())
    })
}

#[apply(pkcs11_export)]
pub unsafe fn C_Verify(
    session: CK_SESSION_HANDLE,
    data: *mut CK_BYTE,
    data_len: CK_ULONG,
    signature: *mut CK_BYTE,
    signature_len: CK_ULONG,
) -> errors::Result<()> {
    ensure_not_null!(data, signature);
    let state = State::get()?;
    state.enter_session(session, |mut session| unsafe {
        let SessionState::Verify(key, mode) = session.get_state() else {
            return Err(CKR_OPERATION_NOT_INITIALIZED);
        };
        let key = key.clone();
        let mut data = slice::from_raw_parts(data, data_len as usize);
        let sig = slice::from_raw_parts(signature, signature_len as usize);

        tracing::trace!("Data Length = {data_len}");
        tracing::trace!("Data = {data:?}");
        tracing::trace!("Signature Length = {signature_len}");
        tracing::trace!("Signature = {sig:?}");

        let (alg, is_digest) = mode.to_crypto_params(&mut data)?;

        let req = session
            .client()
            .signature_verify(key)
            .with_cryptographic_parameters(alg)
            .signature(sig);
        let req = if is_digest {
            req.digested_data(data)
        } else {
            req.data(data)
        };
        let resp = req.exec().map_err(|_| CKR_FUNCTION_FAILED)?;
        session.set_state(SessionState::Idle);

        if resp.validity_indicator != ValidityIndicator::Valid {
            return Err(CKR_SIGNATURE_INVALID);
        }
        Ok(())
    })
}
