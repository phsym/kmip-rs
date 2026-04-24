use ttlv::{Decodable, Encodable};

use super::unique_identifier_request_payload;
use crate::Tags;

unique_identifier_request_payload!(GetAttributeListRequestPayload);

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct GetAttributeListResponsePayload {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    #[ttlv(tag = Tags::AttributeName)]
    pub attribute_name: Vec<String>,
}
