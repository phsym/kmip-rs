use crate::{
    CryptographicAlgorithm, KeyBlock, KeyCompressionType, KeyFormatType, KeyMaterial, KeyValue,
    Object, PlainKeyValue, ProtocolVersion, RecommendedCurve,
};

#[cfg(feature = "interop-openssl")]
mod openssl;

#[cfg(feature = "interop-boring")]
mod boring;

mod crypto;

/// Errors raised while converting between KMIP objects and native key types.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Invalid cryptographic algorithm: expected {expected}, got {got:?}")]
    InvalidAlgorithm {
        expected: &'static str,
        got: Option<CryptographicAlgorithm>,
    },
    #[error("Unsupported key type")]
    UnsupportedKeyType,
    #[error("Invalid or unsupported cryptographic algorithm")]
    UnsupportedCryptographicAlgorithm,
    #[error("Unsupported key format: {0:?}")]
    UnsupportedKeyFormat(KeyFormatType),
    #[error("Unsupported curve: {0:?}")]
    UnsupportedCurve(RecommendedCurve),
    /// An OpenSSL/BoringSSL NID did not map to a known KMIP recommended curve.
    #[error("Unsupported curve NID")]
    UnsupportedCurveNid,
    #[error("Missing curve")]
    MissingCurve,
    #[error("Recommended curve mismatch: expected {expected:?}, got {got:?}")]
    CurveMismatch {
        expected: RecommendedCurve,
        got: RecommendedCurve,
    },
    #[error("Invalid or missing RSA parameter: {parameter}")]
    InvalidRsaParameter { parameter: &'static str },
    #[error("Invalid key material")]
    InvalidKeyMaterial,
    /// The key material variant is well-formed but not accepted in this context
    /// (e.g. receiving a `TransparentDHPrivateKey` where only symmetric bytes are expected).
    #[error("Unsupported key material variant")]
    UnsupportedKeyMaterial,
    #[error("Invalid key value")]
    InvalidKeyValue,
    #[error("Invalid key block")]
    InvalidKeyBlock,
    #[error("Unsupported wrapped key block")]
    UnsupportedWrappedBlock,
    #[error(transparent)]
    Kmip(#[from] crate::errors::Error),
    #[error(transparent)]
    UnexpectedObject(#[from] crate::errors::UnexpectedObject),
    #[error("Invalid UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    #[error("Key conversion failed: {0}")]
    ConversionError(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

#[cfg(any(
    feature = "interop-openssl",
    feature = "interop-boring",
    feature = "interop-rsa",
    feature = "_interop-elliptic-curve"
))]
impl KeyError {
    /// Wrap an arbitrary error into a [`KeyError::ConversionError`].
    pub(crate) fn conversion<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::ConversionError(Box::new(err))
    }
}

#[cfg(feature = "interop-openssl")]
impl From<::openssl::error::ErrorStack> for KeyError {
    fn from(err: ::openssl::error::ErrorStack) -> Self {
        Self::conversion(err)
    }
}

#[cfg(feature = "interop-boring")]
impl From<::boring::error::ErrorStack> for KeyError {
    fn from(err: ::boring::error::ErrorStack) -> Self {
        Self::conversion(err)
    }
}

#[cfg(feature = "interop-rsa")]
impl From<::rsa::Error> for KeyError {
    fn from(err: ::rsa::Error) -> Self {
        Self::conversion(err)
    }
}

#[cfg(feature = "interop-rsa")]
impl From<::rsa::pkcs1::Error> for KeyError {
    fn from(err: ::rsa::pkcs1::Error) -> Self {
        Self::conversion(err)
    }
}

#[cfg(feature = "_interop-elliptic-curve")]
impl From<::elliptic_curve::Error> for KeyError {
    fn from(err: ::elliptic_curve::Error) -> Self {
        Self::conversion(err)
    }
}

#[cfg(feature = "_interop-elliptic-curve")]
impl From<::pkcs8::Error> for KeyError {
    fn from(err: ::pkcs8::Error) -> Self {
        Self::conversion(err)
    }
}

#[cfg(feature = "_interop-elliptic-curve")]
impl From<::pkcs8::spki::Error> for KeyError {
    fn from(err: ::pkcs8::spki::Error) -> Self {
        Self::conversion(err)
    }
}

#[cfg(feature = "_interop-elliptic-curve")]
impl From<::pkcs8::der::Error> for KeyError {
    fn from(err: ::pkcs8::der::Error) -> Self {
        Self::conversion(err)
    }
}

pub trait ToObject<O: Into<Object>> {
    type Format;

    fn to_kmip_object(&self, format: Self::Format, vers: ProtocolVersion) -> Result<O, KeyError>;
}

pub trait FromObject<O: TryFrom<Object>>: Sized {
    fn from_kmip_object(object: Object) -> Result<Self, KeyError>;
}

pub trait ToKeyMaterial<O> {
    const ALGORITHM: CryptographicAlgorithm;
    const KEY_COMPRESSION: Option<KeyCompressionType> = None;
    type Format;

    fn to_material(&self, format: Self::Format) -> Result<KeyMaterial, KeyError>;
    fn cryptographic_length(&self) -> i32;
}

impl<O, T> ToObject<O> for T
where
    O: Into<Object> + From<KeyBlock>,
    T: ToKeyMaterial<O>,
    T::Format: Into<KeyFormatType> + Copy,
{
    type Format = T::Format;
    fn to_kmip_object(&self, format: Self::Format, vers: ProtocolVersion) -> Result<O, KeyError> {
        let mut alg = Self::ALGORITHM;
        let mut material = self.to_material(format)?;
        let mut format = format.into();
        if vers < ProtocolVersion::V1_3 {
            if alg == CryptographicAlgorithm::ECDSA {
                alg = CryptographicAlgorithm::EC;
            }
            #[allow(deprecated, reason = "legacy support")]
            match material {
                KeyMaterial::TransparentECPrivateKey(eckey) => {
                    material = KeyMaterial::TransparentECDSAPrivateKey(eckey);
                    format = KeyFormatType::TransparentECDSAPrivateKey;
                }
                KeyMaterial::TransparentECPublicKey(eckey) => {
                    material = KeyMaterial::TransparentECDSAPublicKey(eckey);
                    format = KeyFormatType::TransparentECDSAPublicKey;
                }
                _ => {}
            }
        }
        Ok(KeyBlock {
            key_format_type: format,
            key_compression_type: Self::KEY_COMPRESSION,
            cryptographic_algorithm: Some(alg),
            cryptographic_length: Some(self.cryptographic_length()),
            key_wrapping_data: None,
            key_value: Some(KeyValue::Plain(PlainKeyValue {
                attributes: vec![],
                key_material: material,
            })),
        }
        .into())
    }
}

impl<O: Into<Object>, K: ToKeyMaterial<O>> ToKeyMaterial<O> for &K {
    const ALGORITHM: CryptographicAlgorithm = K::ALGORITHM;
    const KEY_COMPRESSION: Option<KeyCompressionType> = K::KEY_COMPRESSION;
    type Format = K::Format;

    fn to_material(&self, format: Self::Format) -> Result<KeyMaterial, KeyError> {
        (*self).to_material(format)
    }

    fn cryptographic_length(&self) -> i32 {
        (*self).cryptographic_length()
    }
}

#[derive(Clone, Copy)]
pub enum FormatSymmetric {
    Raw,
    Transparent,
}

impl From<FormatSymmetric> for KeyFormatType {
    fn from(value: FormatSymmetric) -> Self {
        match value {
            FormatSymmetric::Raw => Self::Raw,
            FormatSymmetric::Transparent => Self::TransparentSymmetricKey,
        }
    }
}

#[derive(Clone, Copy)]
pub enum FormatRsaPrivate {
    PKCS1,
    PKCS8,
    Transparent,
}

impl From<FormatRsaPrivate> for KeyFormatType {
    fn from(value: FormatRsaPrivate) -> Self {
        match value {
            FormatRsaPrivate::PKCS1 => Self::PKCS1,
            FormatRsaPrivate::PKCS8 => Self::PKCS8,
            FormatRsaPrivate::Transparent => Self::TransparentRSAPrivateKey,
        }
    }
}

#[derive(Clone, Copy)]
pub enum FormatRsaPublic {
    PKCS1,
    X509,
    Transparent,
}

impl From<FormatRsaPublic> for KeyFormatType {
    fn from(value: FormatRsaPublic) -> Self {
        match value {
            FormatRsaPublic::PKCS1 => Self::PKCS1,
            FormatRsaPublic::X509 => Self::X509,
            FormatRsaPublic::Transparent => Self::TransparentRSAPublicKey,
        }
    }
}

#[derive(Clone, Copy)]
pub enum FormatEcPrivate {
    SEC1,
    PKCS8,
    Transparent,
}

impl From<FormatEcPrivate> for KeyFormatType {
    fn from(value: FormatEcPrivate) -> Self {
        match value {
            FormatEcPrivate::SEC1 => Self::ECPrivateKey,
            FormatEcPrivate::PKCS8 => Self::PKCS8,
            FormatEcPrivate::Transparent => Self::TransparentECPrivateKey,
        }
    }
}

#[derive(Clone, Copy)]
pub enum FormatEcPublic {
    X509,
    Transparent,
}

impl From<FormatEcPublic> for KeyFormatType {
    fn from(value: FormatEcPublic) -> Self {
        match value {
            FormatEcPublic::X509 => Self::X509,
            FormatEcPublic::Transparent => Self::TransparentECPublicKey,
        }
    }
}

pub enum FormatPrivate {
    /// SEC1 for EC keys, or PKCS1 for RSA keys
    DER,
    PKCS8,
    Transparent,
}

pub enum FormatPublic {
    /// PKCS1 for RSA keys, fallbacks to X509 for EC keys
    DER,
    /// SPKI format
    X509,
    Transparent,
}

impl From<FormatPrivate> for FormatEcPrivate {
    fn from(value: FormatPrivate) -> Self {
        match value {
            FormatPrivate::DER => Self::SEC1,
            FormatPrivate::PKCS8 => Self::PKCS8,
            FormatPrivate::Transparent => Self::Transparent,
        }
    }
}

impl From<FormatPrivate> for FormatRsaPrivate {
    fn from(value: FormatPrivate) -> Self {
        match value {
            FormatPrivate::DER => Self::PKCS1,
            FormatPrivate::PKCS8 => Self::PKCS8,
            FormatPrivate::Transparent => Self::Transparent,
        }
    }
}

impl From<FormatPublic> for FormatEcPublic {
    fn from(value: FormatPublic) -> Self {
        match value {
            FormatPublic::DER | FormatPublic::X509 => Self::X509,
            FormatPublic::Transparent => Self::Transparent,
        }
    }
}

impl From<FormatPublic> for FormatRsaPublic {
    fn from(value: FormatPublic) -> Self {
        match value {
            FormatPublic::DER => Self::PKCS1,
            FormatPublic::X509 => Self::X509,
            FormatPublic::Transparent => Self::Transparent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "interop-rsa", feature = "interop-p256"))]
    fn make_key_block(
        format: KeyFormatType,
        alg: Option<CryptographicAlgorithm>,
        material: KeyMaterial,
    ) -> KeyBlock {
        KeyBlock {
            key_format_type: format,
            key_compression_type: None,
            cryptographic_algorithm: alg,
            cryptographic_length: None,
            key_wrapping_data: None,
            key_value: Some(KeyValue::Plain(PlainKeyValue {
                attributes: vec![],
                key_material: material,
            })),
        }
    }

    #[test]
    fn key_error_display_includes_context() {
        let err = KeyError::InvalidAlgorithm {
            expected: "RSA",
            got: Some(CryptographicAlgorithm::AES),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("RSA"),
            "message should mention expected: {msg}"
        );
        assert!(msg.contains("AES"), "message should mention got: {msg}");
    }

    #[test]
    fn key_error_variants_are_matchable() {
        // Simulate programmatic branching on typed variants — the point of #27.
        let err = KeyError::UnsupportedCurve(RecommendedCurve::B163);
        assert!(matches!(
            err,
            KeyError::UnsupportedCurve(RecommendedCurve::B163)
        ));

        let err = KeyError::UnsupportedKeyFormat(KeyFormatType::Opaque);
        assert!(matches!(
            err,
            KeyError::UnsupportedKeyFormat(KeyFormatType::Opaque)
        ));

        let err = KeyError::CurveMismatch {
            expected: RecommendedCurve::P256,
            got: RecommendedCurve::P384,
        };
        assert!(matches!(
            err,
            KeyError::CurveMismatch {
                expected: RecommendedCurve::P256,
                got: RecommendedCurve::P384,
            }
        ));

        let err = KeyError::InvalidRsaParameter {
            parameter: "private_exponent",
        };
        assert!(matches!(
            err,
            KeyError::InvalidRsaParameter {
                parameter: "private_exponent"
            }
        ));
    }

    #[test]
    fn key_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KeyError>();
    }

    #[test]
    fn kmip_error_converts_via_from() {
        // `Object::try_from` on the wrong variant returns `UnexpectedObject`; the
        // `?`-propagation must promote that into a `KeyError` without ad-hoc strings.
        use crate::{PrivateKey, PublicKey};
        let pk = PrivateKey::from(KeyBlock {
            key_format_type: KeyFormatType::Raw,
            key_compression_type: None,
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
            key_value: Some(KeyValue::Plain(PlainKeyValue {
                attributes: vec![],
                key_material: KeyMaterial::Bytes(vec![]),
            })),
        });
        let obj: Object = pk.into();
        let err: KeyError = <&PublicKey>::try_from(&obj).unwrap_err().into();
        assert!(
            matches!(err, KeyError::UnexpectedObject(_)),
            "expected UnexpectedObject, got: {err:?}"
        );
    }

    #[cfg(feature = "interop-rsa")]
    #[test]
    fn rsa_public_key_rejects_wrong_algorithm_with_typed_error() {
        use crate::PublicKey as PublicKeyObj;
        use ::rsa::RsaPublicKey;

        let obj: Object = PublicKeyObj::from(make_key_block(
            KeyFormatType::PKCS1,
            Some(CryptographicAlgorithm::AES),
            KeyMaterial::Bytes(vec![0u8; 4]),
        ))
        .into();

        let err = RsaPublicKey::from_kmip_object(obj).expect_err("should fail");
        assert!(
            matches!(
                err,
                KeyError::InvalidAlgorithm {
                    expected: "RSA",
                    got: Some(CryptographicAlgorithm::AES),
                }
            ),
            "expected InvalidAlgorithm variant, got: {err:?}"
        );
    }

    #[cfg(feature = "interop-rsa")]
    #[test]
    fn rsa_private_key_rejects_unsupported_format_with_typed_error() {
        use crate::PrivateKey as PrivateKeyObj;
        use ::rsa::RsaPrivateKey;

        let obj: Object = PrivateKeyObj::from(make_key_block(
            KeyFormatType::Raw,
            Some(CryptographicAlgorithm::RSA),
            KeyMaterial::Bytes(vec![0u8; 4]),
        ))
        .into();

        let err = RsaPrivateKey::from_kmip_object(obj).expect_err("should fail");
        assert!(
            matches!(err, KeyError::UnsupportedKeyFormat(KeyFormatType::Raw)),
            "expected UnsupportedKeyFormat(Raw), got: {err:?}"
        );
    }

    #[cfg(feature = "interop-rsa")]
    #[test]
    fn rsa_private_key_rejects_missing_private_exponent() {
        use crate::TransparentRSAPrivateKey;
        let transparent = TransparentRSAPrivateKey {
            modulus: ttlv::BigInteger::unsigned(vec![1]),
            private_exponent: None,
            public_exponent: Some(ttlv::BigInteger::unsigned(vec![1])),
            p: None,
            q: None,
            prime_exponent_p: None,
            prime_exponent_q: None,
            crt_coefficient: None,
        };
        let err = ::rsa::RsaPrivateKey::try_from(&transparent).expect_err("should fail");
        assert!(
            matches!(err, KeyError::InvalidRsaParameter { .. }),
            "expected InvalidRsaParameter, got: {err:?}"
        );
    }

    #[cfg(feature = "interop-openssl")]
    #[test]
    fn openssl_error_stack_wraps_to_conversion_error() {
        let underlying =
            ::openssl::rsa::Rsa::<::openssl::pkey::Public>::public_key_from_der(b"garbage")
                .expect_err("garbage DER must fail to parse");
        let err: KeyError = underlying.into();
        assert!(
            matches!(err, KeyError::ConversionError(_)),
            "expected ConversionError, got: {err:?}"
        );
    }

    #[cfg(feature = "interop-boring")]
    #[test]
    fn boring_error_stack_wraps_to_conversion_error() {
        let underlying =
            ::boring::rsa::Rsa::<::boring::pkey::Public>::public_key_from_der(b"garbage")
                .expect_err("garbage DER must fail to parse");
        let err: KeyError = underlying.into();
        assert!(
            matches!(err, KeyError::ConversionError(_)),
            "expected ConversionError, got: {err:?}"
        );
    }

    #[cfg(feature = "interop-rsa")]
    #[test]
    fn rsa_pkcs1_error_wraps_to_conversion_error() {
        use ::rsa::pkcs1::DecodeRsaPrivateKey;
        let underlying = ::rsa::RsaPrivateKey::from_pkcs1_der(b"garbage")
            .expect_err("garbage DER must fail to parse");
        let err: KeyError = underlying.into();
        assert!(
            matches!(err, KeyError::ConversionError(_)),
            "expected ConversionError, got: {err:?}"
        );
    }

    #[cfg(feature = "interop-p256")]
    #[test]
    fn elliptic_curve_error_wraps_to_conversion_error() {
        let underlying = ::p256::PublicKey::from_sec1_bytes(&[0u8; 5])
            .expect_err("invalid SEC1 bytes must fail");
        let err: KeyError = underlying.into();
        assert!(
            matches!(err, KeyError::ConversionError(_)),
            "expected ConversionError, got: {err:?}"
        );
    }

    #[cfg(feature = "interop-p256")]
    #[test]
    fn pkcs8_error_wraps_to_conversion_error() {
        use ::pkcs8::DecodePrivateKey;
        let underlying = ::p256::SecretKey::from_pkcs8_der(b"garbage")
            .expect_err("garbage DER must fail to parse");
        let err: KeyError = underlying.into();
        assert!(
            matches!(err, KeyError::ConversionError(_)),
            "expected ConversionError, got: {err:?}"
        );
    }

    #[cfg(feature = "interop-p256")]
    #[test]
    fn pkcs8_spki_error_wraps_to_conversion_error() {
        use ::pkcs8::DecodePublicKey;
        let underlying = ::p256::PublicKey::from_public_key_der(b"garbage")
            .expect_err("garbage DER must fail to parse");
        let err: KeyError = underlying.into();
        assert!(
            matches!(err, KeyError::ConversionError(_)),
            "expected ConversionError, got: {err:?}"
        );
    }

    #[cfg(feature = "_interop-elliptic-curve")]
    #[test]
    fn pkcs8_der_error_wraps_to_conversion_error() {
        use ::pkcs8::der::Decode;
        let underlying = ::pkcs8::der::asn1::OctetString::from_der(b"garbage")
            .expect_err("garbage DER must fail to parse");
        let err: KeyError = underlying.into();
        assert!(
            matches!(err, KeyError::ConversionError(_)),
            "expected ConversionError, got: {err:?}"
        );
    }

    #[cfg(feature = "interop-p256")]
    #[test]
    fn ec_public_key_rejects_curve_mismatch_with_typed_error() {
        use crate::{PublicKey as PublicKeyObj, TransparentECPublicKey};
        let obj: Object = PublicKeyObj::from(make_key_block(
            KeyFormatType::TransparentECPublicKey,
            Some(CryptographicAlgorithm::EC),
            KeyMaterial::TransparentECPublicKey(TransparentECPublicKey {
                recommended_curve: RecommendedCurve::P384,
                q_string: vec![0u8; 97],
            }),
        ))
        .into();

        let err = <::p256::PublicKey as FromObject<PublicKeyObj>>::from_kmip_object(obj)
            .expect_err("should fail");
        assert!(
            matches!(
                err,
                KeyError::CurveMismatch {
                    expected: RecommendedCurve::P256,
                    got: RecommendedCurve::P384,
                }
            ),
            "expected CurveMismatch, got: {err:?}"
        );
    }
}
