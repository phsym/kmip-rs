use crate::{Tags, types::ProtocolVersion};
use ttlv::{Decodable, Encodable};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable, Default)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct DiscoverVersionsRequestPayload {
    pub protocol_version: Vec<ProtocolVersion>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct DiscoverVersionsResponsePayload {
    pub protocol_version: Vec<ProtocolVersion>,
}
