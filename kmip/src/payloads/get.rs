use std::str;

use ttlv::{Decodable, Encodable};

use crate::{
    Certificate, FromObject, KeyCompressionType, KeyError, KeyFormatType, KeyMaterial, KeyWrapType,
    KeyWrappingSpecification, Object, ObjectType, PrivateKey, ProtocolVersion, PublicKey,
    SecretData, SymmetricKey, Tags,
};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Decodable, Encodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct GetRequestPayload {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: Option<String>,
    pub key_format_type: Option<KeyFormatType>,
    #[ttlv(tag = Tags::KeyWrapType, if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub key_wrap_type: Option<KeyWrapType>,
    pub key_compression_type: Option<KeyCompressionType>,
    pub key_wrapping_specification: Option<KeyWrappingSpecification>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Decodable, Encodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct GetResponsePayload {
    pub object_type: ObjectType,
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    pub object: Object,
}

impl GetResponsePayload {
    pub fn secret(&self) -> Result<&[u8], KeyError> {
        let secret: &SecretData = (&self.object).try_into()?;
        //TODO: Move this into the SecretData struct impl
        secret
            .key_block
            .try_as_bytes()
            .ok_or(KeyError::InvalidKeyBlock)
    }

    pub fn secret_str(&self) -> Result<&str, KeyError> {
        let raw = self.secret()?;
        let s = str::from_utf8(raw)?;
        Ok(s)
    }

    pub fn certificate_der(&self) -> crate::Result<&[u8]> {
        let cert: &Certificate = (&self.object).try_into()?;
        Ok(&cert.certificate_value)
    }

    pub fn certificate<T: From<Certificate>>(self) -> crate::Result<T> {
        let cert: Certificate = self.object.try_into()?;
        Ok(cert.into())
    }

    pub fn private_key<T: FromObject<PrivateKey>>(self) -> Result<T, KeyError> {
        T::from_kmip_object(self.object)
    }

    pub fn public_key<T: FromObject<PublicKey>>(self) -> Result<T, KeyError> {
        T::from_kmip_object(self.object)
    }

    pub fn symmetric_key(&self) -> Result<&[u8], KeyError> {
        let key: &SymmetricKey = (&self.object).try_into()?;
        let kmat = key
            .key_block
            .as_plain_material()
            .ok_or(KeyError::UnsupportedWrappedBlock)?;
        match kmat {
            KeyMaterial::Bytes(bytes) => Ok(bytes),
            KeyMaterial::TransparentSymmetricKey(tk) => Ok(&tk.key),
            _ => Err(KeyError::UnsupportedKeyMaterial),
        }
    }
}
