use ttlv::{Decodable, Encodable};

use crate::{Tags, types::TemplateAttribute};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct ReKeyKeyPairRequestPayload {
    #[ttlv(tag = Tags::PrivateKeyUniqueIdentifier)]
    pub private_key_unique_identifier: Option<String>,
    #[ttlv(tag = Tags::Offset)]
    pub offset: Option<chrono::Duration>,
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
pub struct ReKeyKeyPairResponsePayload {
    #[ttlv(tag = Tags::PrivateKeyUniqueIdentifier)]
    pub private_key_unique_identifier: String,
    #[ttlv(tag = Tags::PublicKeyUniqueIdentifier)]
    pub public_key_unique_identifier: String,
    #[ttlv(tag = Tags::PrivateKeyTemplateAttribute)]
    pub private_key_template_attribute: Option<TemplateAttribute>,
    #[ttlv(tag = Tags::PublicKeyTemplateAttribute)]
    pub public_key_template_attribute: Option<TemplateAttribute>,
}
