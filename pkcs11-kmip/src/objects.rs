use cryptoki::object::Attribute;
use cryptoki_sys::*;
use kmip::{
    attributes::AttributesExt,
    client::BatchResultExt,
    enums::{BatchErrorContinuationOption, ObjectType},
    objects::Object,
    payloads::GetAttributesResponsePayload,
};
use macro_rules_attribute::apply;

use crate::{
    core::{Handle, ObjectHandle, SessionState, State},
    errors,
    mapping::Pkcs11AttributeExt,
};

#[apply(pkcs11_export)]
pub unsafe fn C_FindObjectsInit(
    session: CK_SESSION_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    ul_count: CK_ULONG,
) -> errors::Result<()> {
    let gstate = State::get()?;
    let session = gstate.get_session(session)?;

    let mut attributes = &mut [][..];
    if !templ.is_null() {
        attributes = unsafe { std::slice::from_raw_parts_mut(templ, ul_count as usize) };
    }
    tracing::debug!("Attributes to find: {:#?}", attributes);

    let mut session = session.lock();

    // **************************************************************************************
    // ⚠️⚠️⚠️ WARNING !!! This is shitty code that should probably never have been written.
    // Please consider erasing it and start from scratch in a different way, like:
    //  - passing search attributes to the server (edit: Done ✅)
    //  - Iterate lazily, with chunked pages
    //  - And many other things
    // Apologies, I suffer from a laziness peak right now ... 🙏
    // **************************************************************************************

    let mut keys = Vec::new();
    // push_handle when called will add the provided handle to the iterator if it matches the template.
    let mut push_handle = |(hdl, resp): (Handle, (GetAttributesResponsePayload, Object))| {
        if !gstate.is_logged_in() && hdl.is_private() {
            return;
        }
        if attributes
            .iter()
            .all(|a| hdl.match_attribute(*a) || resp.match_attribute(*a))
        {
            keys.push(hdl);
        }
    };

    // Convert the template attributes to kmip attributes for the filtering
    let mut attrs = Vec::with_capacity(attributes.len());
    for attr in attributes.iter() {
        if let Some(a) = Attribute::try_from(*attr)
            .or(Err(CKR_ATTRIBUTE_VALUE_INVALID))?
            .into_kmip()
        {
            attrs.push(a);
        }
    }

    let it = session
        .client()
        .locate()
        .with_attributes(attrs)
        .exec()
        .or(Err(CKR_FUNCTION_FAILED))?;

    for key_id in it.unique_identifier {
        let resp = session
            .client()
            .get_attributes(&key_id)
            .and_then(|c| c.get(None))
            .exec_opt(BatchErrorContinuationOption::Continue)
            .or(Err(CKR_FUNCTION_FAILED))?
            .flatten()
            .or(Err(CKR_FUNCTION_FAILED))?;

        let resp = (resp.0, resp.1.object);

        match resp.0.attribute.find::<ObjectType>(0) {
            Some(ObjectType::SymmetricKey) => {
                push_handle((Handle::SecretKey(key_id), resp));
            }
            Some(ObjectType::PublicKey) => {
                push_handle((Handle::PublicKey(key_id), resp));
            }
            Some(ObjectType::PrivateKey) => {
                push_handle((Handle::PrivateKey(key_id), resp));
            }
            _ => {}
        }
    }

    session.set_state(SessionState::FindServiceKey(Box::new(keys.into_iter())));
    Ok(())
}

#[apply(pkcs11_export)]
pub unsafe fn C_FindObjects(
    session: CK_SESSION_HANDLE,
    object: *mut CK_OBJECT_HANDLE,
    max_object_count: CK_ULONG,
    object_count: *mut CK_ULONG,
) -> errors::Result<()> {
    ensure_not_null!(object, object_count);

    let gstate = State::get()?;
    let session = gstate.get_session(session)?;

    let result = unsafe { std::slice::from_raw_parts_mut(object, max_object_count as usize) };

    tracing::debug!("Max object count : {max_object_count}");

    let mut session = session.lock();
    let SessionState::FindServiceKey(keys) = session.get_mut_state() else {
        return Err(CKR_OPERATION_NOT_INITIALIZED);
    };

    let mut handles = Vec::with_capacity(max_object_count as usize);
    for hdl in keys.take(max_object_count as usize) {
        // session.new_handle(hdl);
        handles.push(hdl);
    }

    let count = handles.len();
    for (x, hdl) in handles.into_iter().enumerate() {
        result[x] = session.new_handle(hdl);
    }
    unsafe { *object_count = count as CK_ULONG };

    Ok(())
}

#[apply(pkcs11_export)]
pub unsafe fn C_FindObjectsFinal(session: CK_SESSION_HANDLE) -> errors::Result<()> {
    let session = State::get()?.get_session(session)?;
    let mut session = session.lock();
    session.set_state(SessionState::Idle);
    Ok(())
}

#[apply(pkcs11_export)]
pub unsafe fn C_GetObjectSize(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    size: *mut CK_ULONG,
) -> errors::Result<()> {
    ensure_not_null!(size);
    State::get()?.enter_session(session, |session| {
        session.get_handle(object)?; // Trigger a specific error if the object does not exist
        unsafe { *size = CK_UNAVAILABLE_INFORMATION };
        Ok(())
    })
}

#[apply(pkcs11_export)]
pub unsafe fn C_GetAttributeValue(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    templ: *mut CK_ATTRIBUTE,
    ul_count: CK_ULONG,
) -> errors::Result<()> {
    ensure_not_null!(templ);

    let state = State::get()?;
    state.enter_session(session, |mut session| {
        let obj = session.get_handle(object)?.clone();

        let templ = unsafe { std::slice::from_raw_parts_mut(templ, ul_count as usize) };
        tracing::debug!("attributes to get: {templ:?}");

        // **************************************************************************************
        // ⚠️⚠️⚠️ WARNING !!! Once again, this is shitty code that should probably never have been written.
        // Please consider erasing it and start from scratch in a different way, like:
        //  - passing search attributes  to look for to the server
        //  - And many other things
        // Apologies, I suffer from a laziness peak right now ... 🙏
        // **************************************************************************************

        let mut cache = state.cache.lock();
        let key = cache.try_get_or_insert(obj.clone(), || {
            session
                .client()
                .get_attributes(obj.id())
                .and_then(|c| c.get(None))
                .exec_opt(BatchErrorContinuationOption::Continue)
                .or(Err(CKR_FUNCTION_FAILED))?
                .flatten()
                .map(|resp| (resp.0, resp.1.object))
                .or(Err(CKR_FUNCTION_FAILED))
        })?;

        let mut ret_val = Ok(());

        for attr in templ.iter_mut() {
            match obj
                .get_attribute(attr.type_)
                .or_else(|| key.get_attribute(attr.type_))
            {
                Some(a) => {
                    let a = CK_ATTRIBUTE::from(&a);
                    if !attr.pValue.is_null() {
                        // Handle short buffers
                        if attr.ulValueLen < a.ulValueLen {
                            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                            ret_val = Err(CKR_BUFFER_TOO_SMALL);
                            continue;
                        }
                        unsafe {
                            attr.pValue
                                .copy_from_nonoverlapping(a.pValue, a.ulValueLen as usize);
                        }
                    }
                    attr.ulValueLen = a.ulValueLen;
                }
                None => {
                    tracing::warn!("Unsupported attribute: {attr:?}");
                    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                    ret_val = Err(CKR_ATTRIBUTE_TYPE_INVALID);
                }
            }
        }
        ret_val
    })
}

#[apply(pkcs11_export)]
pub unsafe fn C_DestroyObject(
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> errors::Result<()> {
    State::get()?.enter_session(session, |mut session| {
        let hdl = session.remove_handle(object)?;
        let res = session
            .client()
            .revoke(hdl.id())
            .and_then(|c| c.destroy(Some(hdl.id().into())))
            .exec_opt(BatchErrorContinuationOption::Continue)
            .or(Err(CKR_FUNCTION_FAILED))?;
        if let Err(e) = res.0 {
            tracing::warn!("Failed to deactivate object with id {}: {:?}", hdl.id(), e);
        }
        res.1.or(Err(CKR_FUNCTION_FAILED))?;
        Ok(())
    })
}
