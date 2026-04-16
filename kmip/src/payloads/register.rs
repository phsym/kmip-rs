use ttlv::{Decodable, Encodable};

use crate::{Object, ObjectType, Tags, TemplateAttribute};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct RegisterRequestPayload {
    pub object_type: ObjectType,
    #[ttlv(tag = Tags::TemplateAttribute)]
    pub template_attribute: TemplateAttribute,
    pub object: Object,
}

impl RegisterRequestPayload {
    pub fn new(obj: impl Into<Object>) -> Self {
        let obj = obj.into();
        Self {
            object_type: obj.object_type(),
            object: obj,
            template_attribute: TemplateAttribute::default(),
        }
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct RegisterResponsePayload {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    #[ttlv(tag = Tags::TemplateAttribute)]
    pub template_attribute: Option<TemplateAttribute>,
}
