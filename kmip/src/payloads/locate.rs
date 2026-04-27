use ttlv::{Decodable, Encodable};

use crate::{
    StorageStatusMask, Tags, attributes::Attribute, enums::ObjectGroupMember,
    types::ProtocolVersion,
};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable, Default)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct LocateRequestPayload {
    #[ttlv(tag = Tags::MaximumItems)]
    pub maximum_items: Option<i32>,
    #[ttlv(tag = Tags::OffsetItems, if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub offset_items: Option<i32>,
    pub storage_status_mask: Option<StorageStatusMask>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_1..)))]
    pub object_group_member: Option<ObjectGroupMember>,
    //TODO: Accept partial attributes structures
    pub attributes: Vec<Attribute>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Decodable, Encodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct LocateResponsePayload {
    #[ttlv(tag = Tags::LocatedItems, if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub located_items: Option<i32>,
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: Vec<String>,
}
