use ttlv::{Decodable, Encodable};

use super::unique_identifier_request_payload;
use crate::Tags;

unique_identifier_request_payload!(ObtainLeaseRequestPayload);

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct ObtainLeaseResponsePayload {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    #[ttlv(tag = Tags::LeaseTime)]
    pub lease_time: chrono::Duration,
    #[ttlv(tag = Tags::LastChangeDate)]
    pub last_change_date: chrono::DateTime<chrono::Local>,
}
