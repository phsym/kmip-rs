use ttlv::{Decodable, Encodable};

use crate::{Tags, enums::ObjectType, types::TemplateAttribute};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct CreateRequestPayload {
    pub object_type: ObjectType,
    #[ttlv(tag = Tags::TemplateAttribute)]
    pub attributes: TemplateAttribute,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct CreateResponsePayload {
    pub object_type: ObjectType,
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    #[ttlv(tag = Tags::TemplateAttribute)]
    pub attributes: Option<TemplateAttribute>,
}
