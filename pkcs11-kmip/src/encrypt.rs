use cryptoki_sys::{
    CK_BYTE, CK_MECHANISM, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_ULONG, CKR_ARGUMENTS_BAD,
    CKR_BUFFER_TOO_SMALL, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_FUNCTION_FAILED,
    CKR_KEY_HANDLE_INVALID, CKR_OPERATION_NOT_INITIALIZED,
};
use macro_rules_attribute::apply;

use crate::{
    core::{Handle, SessionState, State},
    errors,
    mapping::EncryptMode,
};

#[apply(pkcs11_export)]
pub unsafe fn C_EncryptInit(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> errors::Result<()> {
    ensure_not_null!(mechanism);

    State::get()?.enter_session(session, |mut session| unsafe {
        let mode = EncryptMode::try_from(&*mechanism)?;

        let key = session.get_handle(key)?;
        match key {
            Handle::SecretKey(key) => session.set_state(SessionState::Encrypt(key.clone(), mode)),
            _ => return Err(CKR_KEY_HANDLE_INVALID),
        }

        Ok(())
    })
}

#[apply(pkcs11_export)]
pub unsafe fn C_Encrypt(
    session: CK_SESSION_HANDLE,
    data: *mut ::std::os::raw::c_uchar,
    data_len: ::std::os::raw::c_ulong,
    encrypted_data: *mut ::std::os::raw::c_uchar,
    encrypted_data_len: *mut ::std::os::raw::c_ulong,
) -> errors::Result<()> {
    ensure_not_null!(data, encrypted_data_len);
    State::get()?.enter_session(session, |mut session| unsafe {
        let data = std::slice::from_raw_parts(data, data_len as usize);

        if let SessionState::Encrypted(cached_data, cipher) = session.get_state() {
            if cached_data.as_slice() != data {
                tracing::error!("Data does not match the previously encrypted data");
                return Err(CKR_DATA_INVALID);
            }
            if encrypted_data.is_null() {
                *encrypted_data_len = cipher.len() as u64;
                return Ok(()); // stay in Encrypted
            }
            if *encrypted_data_len < cipher.len() as u64 {
                tracing::error!(
                    "too small. Expected {} but got {}",
                    cipher.len(),
                    *encrypted_data_len,
                );
                *encrypted_data_len = cipher.len() as u64;
                return Err(CKR_BUFFER_TOO_SMALL);
            }
            encrypted_data.copy_from_nonoverlapping(cipher.as_ptr(), cipher.len());
            *encrypted_data_len = cipher.len() as u64;
            session.set_state(SessionState::Idle);
            return Ok(());
        }

        let (key_id, mode) = match session.get_state() {
            SessionState::Encrypt(key, mode) => (key.clone(), mode.clone()),
            _ => return Err(CKR_OPERATION_NOT_INITIALIZED),
        };

        if let Some(align) = mode.align
            && data_len % align as u64 != 0
        {
            tracing::error!("Data length must be a multiple of {align} bytes");
            return Err(CKR_DATA_LEN_RANGE);
        }

        let mut req = session
            .client()
            .encrypt(key_id)
            .with_cryptographic_parameters(mode.params)
            .data(data);
        if let Some(iv) = mode.iv {
            req = req.with_iv_counter_nonce(iv)
        }
        if let Some(aad) = mode.aad {
            req = req.with_aad(aad)
        }
        let resp = req.exec().or(Err(CKR_FUNCTION_FAILED))?;

        let mut ciphertext = resp.data.unwrap();
        if let Some(tag) = resp.authenticated_encryption_tag {
            ciphertext.extend_from_slice(&tag);
        }

        if encrypted_data.is_null() {
            *encrypted_data_len = ciphertext.len() as u64;
            session.set_state(SessionState::Encrypted(data.to_vec().into(), ciphertext));
            return Ok(());
        }
        if *encrypted_data_len < ciphertext.len() as u64 {
            tracing::debug!(
                "too small. Expected {} but got {}",
                ciphertext.len(),
                *encrypted_data_len,
            );
            *encrypted_data_len = ciphertext.len() as u64;
            session.set_state(SessionState::Encrypted(data.to_vec().into(), ciphertext));
            return Err(CKR_BUFFER_TOO_SMALL);
        }
        *encrypted_data_len = ciphertext.len() as u64;
        encrypted_data.copy_from_nonoverlapping(ciphertext.as_ptr(), ciphertext.len());

        session.set_state(SessionState::Idle);

        Ok(())
    })
}

#[apply(pkcs11_export)]
pub unsafe fn C_DecryptInit(
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> errors::Result<()> {
    ensure_not_null!(mechanism);

    State::get()?.enter_session(session, |mut session| unsafe {
        let mode = EncryptMode::try_from(&*mechanism)?;

        let key = session.get_handle(key)?;
        match key {
            Handle::SecretKey(key) => session.set_state(SessionState::Decrypt(key.clone(), mode)),
            _ => return Err(CKR_KEY_HANDLE_INVALID),
        }

        Ok(())
    })
}

#[apply(pkcs11_export)]
pub unsafe fn C_Decrypt(
    session: CK_SESSION_HANDLE,
    encrypted_data: *mut CK_BYTE,
    encrypted_data_len: CK_ULONG,
    data: *mut CK_BYTE,
    data_len: *mut CK_ULONG,
) -> errors::Result<()> {
    ensure_not_null!(encrypted_data, data_len);
    if encrypted_data_len == 0 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if data.is_null() {
        unsafe { *data_len = encrypted_data_len };
        return Ok(());
    }

    let encrypted_data =
        unsafe { std::slice::from_raw_parts(encrypted_data, encrypted_data_len as usize) };

    State::get()?.enter_session(session, |mut session| unsafe {
        let (key_id, mode) = match session.get_state() {
            SessionState::Decrypted(cached_data, plaintext) => {
                if cached_data.as_slice() != encrypted_data {
                    tracing::error!("Encrypted data does not match the previously encrypted data");
                    return Err(CKR_DATA_INVALID);
                }
                if data.is_null() {
                    *data_len = plaintext.len() as u64;
                    return Ok(()); // stay in Decrypted
                }
                if *data_len < plaintext.len() as u64 {
                    tracing::error!(
                        "too small. Expected {} but got {}",
                        plaintext.len(),
                        *data_len,
                    );
                    *data_len = plaintext.len() as u64;
                    return Err(CKR_BUFFER_TOO_SMALL);
                }
                data.copy_from_nonoverlapping(plaintext.as_ptr(), plaintext.len());
                *data_len = plaintext.len() as u64;
                session.set_state(SessionState::Idle);
                return Ok(());
            }
            SessionState::Decrypt(key, mode) => (key.clone(), mode.clone()),
            _ => return Err(CKR_OPERATION_NOT_INITIALIZED),
        };

        let tag_len = mode.params.tag_length.unwrap_or(0) as usize;
        if encrypted_data_len < tag_len as u64 {
            tracing::error!(
                "Encrypted data length must be at least as long as the tag length ({tag_len} bytes)"
            );
            return Err(CKR_DATA_LEN_RANGE);
        }
        let (encrypted_data, tag) = if tag_len > 0 {
            let (data, tag) = encrypted_data.split_at(encrypted_data.len() - tag_len);
            tracing::debug!("Data: {:02x?}", data);
            tracing::debug!("Tag: {:02x?}", tag);
            (data, Some(tag))
        } else {
            (encrypted_data, None)
        };

        let mut req = session
            .client()
            .decrypt(key_id)
            .with_cryptographic_parameters(mode.params)
            .data(encrypted_data);
        if let Some(iv) = mode.iv {
            req = req.with_iv_counter_nonce(iv)
        }
        if let Some(aad) = mode.aad {
            req = req.with_aad(aad)
        }
        if let Some(tag) = tag {
            req = req.with_tag(tag)
        }
        let resp = req.exec().or(Err(CKR_FUNCTION_FAILED))?;

        let plaintext = resp.data.ok_or(CKR_FUNCTION_FAILED)?;

        if data.is_null() {
            *data_len = plaintext.len() as u64;
            session.set_state(SessionState::Decrypted(
                encrypted_data.to_vec().into(),
                plaintext.into(),
            ));
            return Ok(());
        }

        if *data_len < plaintext.len() as u64 {
            *data_len = plaintext.len() as u64;
            session.set_state(SessionState::Decrypted(
                encrypted_data.to_vec().into(),
                plaintext.into(),
            ));
            return Err(CKR_BUFFER_TOO_SMALL);
        }

        *data_len = plaintext.len() as u64;
        data.copy_from_nonoverlapping(plaintext.as_ptr(), plaintext.len());
        session.set_state(SessionState::Idle);
        Ok(())
    })?;

    Ok(())
}
