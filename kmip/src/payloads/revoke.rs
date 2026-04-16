use chrono::Local;
use ttlv::{Decodable, Encodable};

use crate::{RevocationReason, Tags};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct RevokeRequestPayload {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: Option<String>,
    pub revocation_reason: RevocationReason,
    #[ttlv(tag = Tags::CompromiseOccurrenceDate)]
    pub compromise_occurrence_date: Option<chrono::DateTime<Local>>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct RevokeResponsePayload {
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
}
