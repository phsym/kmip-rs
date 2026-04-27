use ttlv::{Decodable, Encodable};

use crate::{Tags, attributes::Attribute};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct DeleteAttributeRequestPayload {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: Option<String>,
    #[ttlv(tag = Tags::AttributeName)]
    pub attribute_name: String,
    #[ttlv(tag = Tags::AttributeIndex)]
    pub attribute_index: Option<i32>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct DeleteAttributeResponsePayload {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    pub attribute: Attribute,
}
