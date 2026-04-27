use crate::{
    CryptographicUsageMask,
    attributes::Attribute,
    client::{BatchClient, Client},
    enums::{CertificateType, CryptographicAlgorithm, KeyFormatType, SecretDataType},
    interop::{FormatSymmetric, KeyError, ToObject, bytes_to_bit_length},
    objects::{
        Certificate, KeyBlock, KeyMaterial, KeyValue, Object, PlainKeyValue, PrivateKey, PublicKey,
        SecretData, SymmetricKey, TransparentSymmetricKey,
    },
    payloads::RegisterRequestPayload,
};

use super::{Attributed, Exec};

pub type RegisterExec<'a> = Exec<'a, RegisterRequestPayload>;
pub struct RegisterExecWantType<'a>(&'a mut Client);

impl Client {
    pub fn register(&mut self) -> RegisterExecWantType<'_> {
        RegisterExecWantType(self)
    }
}

impl<'a> BatchClient<'a> {
    pub fn register(self) -> RegisterExecWantType<'a> {
        self.0.register()
    }
}

impl Attributed for RegisterExec<'_> {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute> {
        &mut self.req.template_attribute.attribute
    }
}

impl<'a> RegisterExecWantType<'a> {
    pub fn object(self, obj: impl Into<Object>) -> RegisterExec<'a> {
        RegisterExec::new(self.0, RegisterRequestPayload::new(obj))
    }

    pub fn secret(
        self,
        secret_type: SecretDataType,
        value: impl Into<Vec<u8>>,
    ) -> RegisterExec<'a> {
        self.object(SecretData {
            secret_data_type: secret_type,
            key_block: KeyBlock {
                key_format_type: KeyFormatType::Raw,
                key_value: Some(KeyValue::Plain(PlainKeyValue {
                    key_material: KeyMaterial::Bytes(value.into()),
                    attributes: Vec::new(),
                })),
                cryptographic_algorithm: None,
                cryptographic_length: None,
                key_compression_type: None,
                key_wrapping_data: None,
            },
        })
    }

    pub fn certificate(self, cert_type: CertificateType, value: Vec<u8>) -> RegisterExec<'a> {
        self.object(Certificate {
            certificate_type: cert_type,
            certificate_value: value,
        })
    }

    pub fn symmetric_key(
        self,
        value: impl Into<Vec<u8>>,
        alg: CryptographicAlgorithm,
        format: FormatSymmetric,
        usage: CryptographicUsageMask,
    ) -> Result<RegisterExec<'a>, KeyError> {
        let value = value.into();
        let cryptographic_length = bytes_to_bit_length(value.len())?;
        Ok(self
            .object(SymmetricKey {
                key_block: KeyBlock {
                    key_format_type: format.into(),
                    key_compression_type: None,
                    cryptographic_algorithm: Some(alg),
                    cryptographic_length: Some(cryptographic_length),
                    key_wrapping_data: None,
                    key_value: Some(KeyValue::Plain(PlainKeyValue {
                        attributes: vec![],
                        key_material: match format {
                            FormatSymmetric::Raw => KeyMaterial::Bytes(value),
                            FormatSymmetric::Transparent => {
                                KeyMaterial::TransparentSymmetricKey(TransparentSymmetricKey {
                                    key: value,
                                })
                            }
                        },
                    })),
                },
            })
            .with_attribute(usage))
    }

    pub fn public_key<K>(
        self,
        key: K,
        format: K::Format,
        usage: CryptographicUsageMask,
    ) -> Result<RegisterExec<'a>, KeyError>
    where
        K: ToObject<PublicKey>,
    {
        self.key(key, format, usage)
    }

    pub fn private_key<K>(
        self,
        key: K,
        format: K::Format,
        usage: CryptographicUsageMask,
    ) -> Result<RegisterExec<'a>, KeyError>
    where
        K: ToObject<PrivateKey>,
    {
        self.key(key, format, usage)
    }

    fn key<K: ToObject<impl Into<Object>>>(
        self,
        key: K,
        format: K::Format,
        usage: CryptographicUsageMask,
    ) -> Result<RegisterExec<'a>, KeyError> {
        let version = self.0.version()?;
        Ok(self
            .object(key.to_kmip_object(format, version)?)
            .with_attribute(usage))
    }
}
