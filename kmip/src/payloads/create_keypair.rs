use ttlv::{Decodable, Encodable};

use crate::{Tags, TemplateAttribute};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct CreateKeyPairRequestPayload {
    #[ttlv(tag = Tags::CommonTemplateAttribute)]
    pub common_template_attribute: Option<TemplateAttribute>,
    #[ttlv(tag = Tags::PrivateKeyTemplateAttribute)]
    pub private_key_template_attribute: Option<TemplateAttribute>,
    #[ttlv(tag = Tags::PublicKeyTemplateAttribute)]
    pub public_key_template_attribute: Option<TemplateAttribute>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct CreateKeyPairResponsePayload {
    #[ttlv(tag = Tags::PrivateKeyUniqueIdentifier)]
    pub private_key_unique_identifier: String,
    #[ttlv(tag = Tags::PublicKeyUniqueIdentifier)]
    pub public_key_unique_identifier: String,

    #[ttlv(tag = Tags::PrivateKeyTemplateAttribute)]
    pub private_key_template_attribute: Option<TemplateAttribute>,
    #[ttlv(tag = Tags::PublicKeyTemplateAttribute)]
    pub public_key_template_attribute: Option<TemplateAttribute>,
}
