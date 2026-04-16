use std::borrow::Borrow;

use ttlv::{Decodable, Encodable};

use crate::{Attribute, AttributeName, Tags};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct GetAttributesRequestPayload {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: Option<String>,
    #[ttlv(tag = Tags::AttributeName)]
    pub attribute_name: Vec<String>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct GetAttributesResponsePayload {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    pub attribute: Vec<Attribute>,
}

impl GetAttributesResponsePayload {
    pub fn get_attribute_by_str_name(&self, name: &str) -> Option<&Attribute> {
        self.attribute
            .iter()
            .find(|a| a.name == name && a.index.unwrap_or_default() == 0)
    }

    pub fn get_attribute_by_name(&self, name: impl Borrow<AttributeName>) -> Option<&Attribute> {
        self.get_attribute_by_str_name(name.borrow().as_str())
    }
}
