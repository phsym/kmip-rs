macro_rules! not_supported {
    ($($ident:ident)?) => {
        unsafe {
            unsafe extern "C" fn unimplemented() -> ::cryptoki_sys::CK_RV {
                $(::tracing::warn!("{} -> Unsupported function", ::std::stringify!($ident));)?
                match State::get() {
                    Ok(_) => ::cryptoki_sys::CKR_FUNCTION_NOT_SUPPORTED,
                    Err(e) => e,
                }
            }
            #[allow(clippy::missing_transmute_annotations)]
            Some(std::mem::transmute(
                unimplemented as unsafe extern "C" fn() -> _,
            ))
        }
    }
}

macro_rules! pkcs11_export {
    (
        $(#[$meta:meta])*
        $vis:vis unsafe fn $ident:ident($($argn:ident: $argt:ty), * $(,)?) -> $ret:ty {
            $($body:tt)*
        }
    ) => {
        $(#[$meta])*
        #[unsafe(no_mangle)]
        #[::tracing::instrument(skip_all)]
        #[allow(clippy::missing_safety_doc)]
        $vis unsafe extern "C" fn $ident($($argn: $argt), *) -> ::cryptoki_sys::CK_RV {
            ::tracing::debug!("{}", ::std::stringify!($ident));
            // Catch panics and make them errors
            match ::std::panic::catch_unwind(move || -> $ret { $($body)* }) {
                Err(e) => {
                    ::tracing::error!("PKCS11 panicked: {e:?}");
                    return ::cryptoki_sys::CKR_GENERAL_ERROR;
                }
                Ok(Err(e)) => {
                    let rv = e.into();
                    if let ::cryptoki::error::Rv::Error(e) = ::cryptoki::error::Rv::from(rv) {
                        ::tracing::error!("PKCS11 error: {e:?}");
                    }
                    rv
                },
                Ok(Ok(_)) => ::cryptoki_sys::CKR_OK,
            }
        }
    }
}

macro_rules! ensure_not_null {
    ($($expr:expr), * $(,)?) => {
        $(
            if $expr.is_null() {
                ::tracing::error!("Argument {} is null", ::std::stringify!($expr));
                return Err(CKR_ARGUMENTS_BAD);
            }
        )*
    };
}

macro_rules! decl_mechanisms {
    ($($key:ident $(: {$($field:ident : $value:expr,)*})?,)*) => {
        static MECHANISMS: ::std::sync::LazyLock<::std::collections::HashMap<::cryptoki_sys::CK_MECHANISM_TYPE, ::cryptoki_sys::CK_MECHANISM_INFO>> =
            ::std::sync::LazyLock::new(|| {
                let mut m = ::std::collections::HashMap::new();
                $(
                    m.insert(
                        $key,
                        #[allow(clippy::needless_update)]
                        ::cryptoki_sys::CK_MECHANISM_INFO {
                            $($($field: $value,)*)?
                            ..::std::default::Default::default()
                        },
                    );
                )*
                m
            });

        static MECHANISMS_TYPES: &[::cryptoki_sys::CK_MECHANISM_TYPE] = &[$($key,)*];
    }
}
