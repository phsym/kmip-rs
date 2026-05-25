use std::collections::HashMap;

use const_oid::db::rfc5912;
use cryptoki::{
    object::{Attribute, KeyType, ObjectClass},
    types::Ulong,
};
use cryptoki_sys::*;
use der::Encode;
use kmip::{
    CryptographicUsageMask,
    attributes::{AttributesExt, CryptographicLength},
    enums::{CryptographicAlgorithm, RecommendedCurve},
    objects::Object,
    payloads::GetAttributesResponsePayload,
    types::{CryptographicDomainParameters, Name},
};
use sec1::EcParameters;
use slab::Slab;

pub trait ObjectHandle {
    fn get_attribute(&self, attr: CK_ATTRIBUTE_TYPE) -> Option<Attribute>;

    fn match_attribute(&self, attr: CK_ATTRIBUTE) -> bool {
        let Some(a) = self.get_attribute(attr.type_) else {
            return false;
        };
        Attribute::try_from(attr).unwrap() == a
    }

    // fn match_all_attributes(&self, attrs: &[CK_ATTRIBUTE]) -> bool {
    //     attrs.iter().all(|a| self.match_attribute(*a))
    // }
}

impl ObjectHandle for GetAttributesResponsePayload {
    fn get_attribute(&self, attr: CK_ATTRIBUTE_TYPE) -> Option<Attribute> {
        match attr {
            CKA_ID => Some(Attribute::Id(self.unique_identifier.clone().into_bytes())),
            CKA_LABEL => Some(Attribute::Label(
                self.attribute
                    .find::<Name>(0)?
                    .name_value
                    .clone()
                    .into_bytes(),
            )),
            CKA_TOKEN => Some(Attribute::Token(true)),
            CKA_KEY_TYPE => Some(match self.attribute.find::<CryptographicAlgorithm>(0)? {
                CryptographicAlgorithm::AES => Attribute::KeyType(KeyType::AES),
                CryptographicAlgorithm::RSA => Attribute::KeyType(KeyType::RSA),
                CryptographicAlgorithm::EC | CryptographicAlgorithm::ECDSA => {
                    Attribute::KeyType(KeyType::EC)
                }
                _ => return None,
            }),
            CKA_SIGN => Some(Attribute::Sign(
                self.attribute
                    .find::<CryptographicUsageMask>(0)?
                    .contains(CryptographicUsageMask::Sign),
            )),
            CKA_VERIFY => Some(Attribute::Verify(
                self.attribute
                    .find::<CryptographicUsageMask>(0)?
                    .contains(CryptographicUsageMask::Verify),
            )),
            CKA_ENCRYPT => Some(Attribute::Encrypt(
                self.attribute
                    .find::<CryptographicUsageMask>(0)?
                    .contains(CryptographicUsageMask::Encrypt),
            )),
            CKA_DECRYPT => Some(Attribute::Decrypt(
                self.attribute
                    .find::<CryptographicUsageMask>(0)?
                    .contains(CryptographicUsageMask::Decrypt),
            )),
            CKA_DERIVE => Some(Attribute::Derive(
                self.attribute
                    .find::<CryptographicUsageMask>(0)?
                    .contains(CryptographicUsageMask::DeriveKey),
            )),
            CKA_WRAP => Some(Attribute::Wrap(
                self.attribute
                    .find::<CryptographicUsageMask>(0)?
                    .contains(CryptographicUsageMask::WrapKey),
            )),
            CKA_UNWRAP => Some(Attribute::Unwrap(
                self.attribute
                    .find::<CryptographicUsageMask>(0)?
                    .contains(CryptographicUsageMask::UnwrapKey),
            )),
            CKA_MODULUS_BITS => self
                .attribute
                .find::<CryptographicLength>(0)
                .map(|l| Attribute::ModulusBits(Ulong::new(l.0.try_into().unwrap()))),
            CKA_VALUE_LEN => self
                .attribute
                .find::<CryptographicLength>(0)
                .map(|l| Attribute::ValueLen(Ulong::new((l.0 / 8).try_into().unwrap()))),
            CKA_EC_PARAMS => {
                let oid = match self
                    .attribute
                    .find::<CryptographicDomainParameters>(0)?
                    .recommended_curve?
                {
                    RecommendedCurve::P256 => rfc5912::SECP_256_R_1,
                    RecommendedCurve::P384 => rfc5912::SECP_384_R_1,
                    RecommendedCurve::P521 => rfc5912::SECP_521_R_1,
                    _ => return None,
                };
                Some(Attribute::EcParams(
                    EcParameters::NamedCurve(oid).to_der().unwrap(),
                ))
            }
            _ => None,
        }
    }
}

impl ObjectHandle for Object {
    fn get_attribute(&self, attr: CK_ATTRIBUTE_TYPE) -> Option<Attribute> {
        match attr {
            CKA_TOKEN => Some(Attribute::Token(true)),
            CKA_MODULUS => match self {
                Object::PublicKey(kb) => Some(Attribute::Modulus(
                    kb.key_block
                        .as_plain_material()?
                        .try_as_transparent_rsa_public_key_ref()?
                        .modulus
                        .as_ref()
                        .to_vec(),
                )),
                _ => None,
            },
            CKA_PUBLIC_EXPONENT => match self {
                Object::PublicKey(kb) => Some(Attribute::Modulus(
                    kb.key_block
                        .as_plain_material()?
                        .try_as_transparent_rsa_public_key_ref()?
                        .public_exponent
                        .as_ref()
                        .to_vec(),
                )),
                _ => None,
            },
            CKA_EC_POINT => match self {
                Object::PublicKey(kb) => {
                    let mat = kb.key_block.as_plain_material()?;
                    mat.try_as_transparent_ec_public_key_ref()
                        .map(|k| k.q_string.clone())
                        .or_else(|| {
                            mat.try_as_transparent_ecdsa_public_key_ref()
                                .map(|k| k.q_string.clone())
                        })
                        .map(Attribute::EcPoint)
                }
                _ => None,
            },
            _ => None,
        }
    }
}

impl ObjectHandle for (GetAttributesResponsePayload, Object) {
    fn get_attribute(&self, attr: CK_ATTRIBUTE_TYPE) -> Option<Attribute> {
        self.0
            .get_attribute(attr)
            .or_else(|| self.1.get_attribute(attr))
    }
}

impl ObjectHandle for Handle {
    fn get_attribute(&self, attr: CK_ATTRIBUTE_TYPE) -> Option<Attribute> {
        match attr {
            CKA_TOKEN => Some(Attribute::Token(true)),
            CKA_CLASS => Some(match self {
                Self::PrivateKey(_) => Attribute::Class(ObjectClass::PRIVATE_KEY),
                Self::PublicKey(_) => Attribute::Class(ObjectClass::PUBLIC_KEY),
                Self::SecretKey(_) => Attribute::Class(ObjectClass::SECRET_KEY),
            }),
            CKA_PRIVATE => Some(Attribute::Private(self.is_private())),
            CKA_ID => Some(Attribute::Id(self.id().to_string().into())),
            CKA_SENSITIVE => Some(Attribute::Sensitive(self.is_private())),
            CKA_EXTRACTABLE => Some(Attribute::Extractable(!self.is_private())),
            CKA_ALWAYS_AUTHENTICATE => Some(Attribute::AlwaysAuthenticate(false)),
            CKA_LOCAL => Some(Attribute::Local(false)),
            CKA_ALWAYS_SENSITIVE => Some(Attribute::AlwaysSensitive(false)),
            CKA_NEVER_EXTRACTABLE => Some(Attribute::NeverExtractable(false)),
            CKA_SIGN_RECOVER => Some(Attribute::SignRecover(false)),
            CKA_VERIFY_RECOVER => Some(Attribute::VerifyRecover(false)),
            _ => None,
        }
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Handle {
    PrivateKey(String),
    PublicKey(String),
    SecretKey(String),
}

impl Handle {
    pub fn id(&self) -> &str {
        match self {
            Handle::PrivateKey(id) | Handle::PublicKey(id) | Handle::SecretKey(id) => id,
        }
    }

    pub fn is_private(&self) -> bool {
        match self {
            Self::PrivateKey(_) | Self::SecretKey(_) => true,
            Self::PublicKey(_) => false,
        }
    }
}

pub struct HandleStore {
    handles: Slab<Handle>,
    hashes: HashMap<Handle, u64>,
}

impl HandleStore {
    pub(super) fn new() -> Self {
        Self {
            handles: Slab::new(),
            hashes: HashMap::new(),
        }
    }

    pub(super) fn store(&mut self, hdl: Handle) -> u64 {
        if let Some(id) = self.hashes.get(&hdl) {
            return *id;
        }
        let handle = self.handles.insert(hdl.clone()) as u64;
        self.hashes.insert(hdl, handle);
        handle
    }

    pub(super) fn load(&self, key: u64) -> Option<&Handle> {
        self.handles.get(key as usize)
    }

    pub(super) fn remove(&mut self, key: u64) -> Option<Handle> {
        let hdl = self.handles.try_remove(key as usize)?;
        self.hashes.remove(&hdl);
        Some(hdl)
    }
}
