use ttlv::{Decodable, Encodable};

use crate::{Tags, types::TemplateAttribute};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct ReKeyRequestPayload {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: Option<String>,
    #[ttlv(tag = Tags::Offset)]
    pub offset: Option<chrono::Duration>,
    #[ttlv(tag = Tags::TemplateAttribute)]
    pub template_attribute: Option<TemplateAttribute>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct ReKeyResponsePayload {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    #[ttlv(tag = Tags::TemplateAttribute)]
    pub template_attribute: Option<TemplateAttribute>,
}
