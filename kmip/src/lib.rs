#![doc = include_str!("../../README.md")]

pub mod attributes;
mod bitmasks;
pub mod client;
pub mod enums;
mod errors;
pub mod interop;
pub mod objects;
pub mod payloads;
pub mod server;
mod tags;
pub mod types;

pub use bitmasks::*;
pub use errors::*;
pub use tags::*;

use chrono::Local;
use ttlv::{Decodable, Decoder, Encodable, Encoder};

use crate::{
    enums::{
        AttestationType, BatchErrorContinuationOption, Operations, ResultReason, ResultStatus,
    },
    payloads::{RequestPayload, ResponsePayload},
    types::{Authentication, MessageExtension, Nonce, ProtocolVersion},
};

pub trait TryAsRef<T> {
    fn try_as_ref(&self) -> Option<&T>;
}

pub trait TryAsMut<T> {
    fn try_as_mut(&mut self) -> Option<&mut T>;
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RequestMessage)]
pub struct RequestMessage {
    pub header: RequestHeader,
    pub batch_item: Vec<RequestBatchItem>,
}

impl RequestMessage {
    pub fn new(version: ProtocolVersion, payload: impl Into<RequestPayload>) -> Self {
        Self {
            header: RequestHeader {
                protocol_version: version,
                batch_count: 1,
                asynchronous_indicator: None,
                authentication: None,
                maximum_response_size: None,
                batch_error_continuation_option: None,
                batch_order_option: None,
                timestamp: Some(chrono::Local::now()),
                attestation_capable_indicator: None,
                attestation_type: None,
                client_correlation_value: None,
                server_correlation_value: None,
            },
            batch_item: vec![RequestBatchItem::new(payload, None)],
        }
    }

    pub fn new_batched<I, P>(version: ProtocolVersion, payloads: I) -> Result<Self>
    where
        I: IntoIterator<Item = P>,
        P: Into<RequestPayload>,
    {
        let items = payloads
            .into_iter()
            .enumerate()
            .map(|(id, pl)| RequestBatchItem::new(pl, Some(id.to_be_bytes().to_vec())))
            .collect::<Vec<_>>();

        let batch_count =
            i32::try_from(items.len()).map_err(|_| Error::BatchCountOverflow(items.len()))?;
        Ok(Self {
            header: RequestHeader {
                protocol_version: version,
                batch_count,
                asynchronous_indicator: None,
                authentication: None,
                maximum_response_size: None,
                batch_error_continuation_option: None,
                batch_order_option: None,
                timestamp: Some(chrono::Local::now()),
                attestation_capable_indicator: None,
                attestation_type: None,
                client_correlation_value: None,
                server_correlation_value: None,
            },
            batch_item: items,
        })
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ResponseMessage)]
pub struct ResponseMessage {
    pub header: ResponseHeader,
    pub batch_item: Vec<ResponseBatchItem>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RequestHeader)]
pub struct RequestHeader {
    #[ttlv(set_ext)]
    pub protocol_version: ProtocolVersion,
    #[ttlv(tag = Tags::MaximumResponseSize)]
    pub maximum_response_size: Option<i32>,
    #[ttlv(tag = Tags::ClientCorrelationValue, if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub client_correlation_value: Option<String>,
    #[ttlv(tag = Tags::ServerCorrelationValue, if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub server_correlation_value: Option<String>,
    #[ttlv(tag = Tags::AsynchronousIndicator)]
    pub asynchronous_indicator: Option<bool>,
    #[ttlv(tag = Tags::AttestationCapableIndicator, if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub attestation_capable_indicator: Option<bool>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub attestation_type: Option<Vec<AttestationType>>,
    pub authentication: Option<Authentication>,
    pub batch_error_continuation_option: Option<BatchErrorContinuationOption>,
    #[ttlv(tag = Tags::BatchOrderOption)]
    pub batch_order_option: Option<bool>,
    #[ttlv(tag = Tags::TimeStamp)]
    pub timestamp: Option<chrono::DateTime<Local>>,
    #[ttlv(tag = Tags::BatchCount)]
    pub batch_count: i32,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ResponseHeader)]
pub struct ResponseHeader {
    #[ttlv(set_ext)]
    pub protocol_version: ProtocolVersion,
    #[ttlv(tag = Tags::TimeStamp)]
    pub timestamp: chrono::DateTime<Local>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub nonce: Option<Nonce>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub attestation_type: Option<Vec<AttestationType>>,
    #[ttlv(tag = Tags::ClientCorrelationValue, if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub client_correlation_value: Option<String>,
    #[ttlv(tag = Tags::ServerCorrelationValue, if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub server_correlation_value: Option<String>,
    #[ttlv(tag = Tags::BatchCount)]
    pub batch_count: i32,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq)]
// #[derive(Encodable)]
// #[ttlv(tag = Tags::BatchItem)]
pub struct RequestBatchItem {
    pub operation: Operations,
    // #[ttlv(tag = Tags::UniqueBatchItemID)]
    pub unique_batch_item_id: Option<Vec<u8>>,
    pub request_payload: RequestPayload,
    pub message_extension: Option<MessageExtension>,
}

impl RequestBatchItem {
    pub fn new(payload: impl Into<RequestPayload>, id: Option<Vec<u8>>) -> Self {
        let payload = payload.into();
        Self {
            operation: payload.operation(),
            unique_batch_item_id: id,
            request_payload: payload,
            message_extension: None,
        }
    }
}

impl Encodable for RequestBatchItem {
    fn encode(&self, encoder: &mut impl Encoder) -> ttlv::Result<()> {
        encoder.write_struct(Tags::BatchItem, |e| {
            e.encode(&self.operation)?;
            e.tag_encode(Tags::UniqueBatchItemID, &self.unique_batch_item_id)?;
            e.encode(&self.request_payload)?;
            e.encode(&self.message_extension)?;
            Ok(())
        })
    }
}

impl Decodable for RequestBatchItem {
    fn decode(decoder: &mut impl Decoder) -> ttlv::Result<Self> {
        decoder.read_struct(Tags::BatchItem, |d| {
            let op = d.decode::<Operations>()?;
            Ok(Self {
                operation: op.clone(),
                unique_batch_item_id: d.tag_decode(Tags::UniqueBatchItemID)?,
                request_payload: RequestPayload::decode_with(op, d)?,
                message_extension: d.decode()?,
            })
        })
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq)]
// #[derive(Encodable)]
// #[ttlv(tag = Tags::BatchItem)]
pub struct ResponseBatchItem {
    pub operation: Option<Operations>,
    // #[ttlv(tag = Tags::UniqueBatchItemID)]
    pub unique_batch_item_id: Option<Vec<u8>>,
    pub result_status: ResultStatus,
    pub result_reason: Option<ResultReason>,
    pub result_message: Option<String>,
    pub asynchronous_correlation_value: Option<Vec<u8>>,
    pub response_payload: Option<ResponsePayload>,
    pub message_extension: Option<MessageExtension>,
}

impl Encodable for ResponseBatchItem {
    fn encode(&self, encoder: &mut impl Encoder) -> ttlv::Result<()> {
        encoder.write_struct(Tags::BatchItem, |e| {
            e.encode(&self.operation)?;
            e.tag_encode(Tags::UniqueBatchItemID, &self.unique_batch_item_id)?;
            e.encode(&self.result_status)?;
            e.encode(&self.result_reason)?;
            e.tag_encode(Tags::ResultMessage, &self.result_message)?;
            e.tag_encode(
                Tags::AsynchronousCorrelationValue,
                &self.asynchronous_correlation_value,
            )?;
            e.encode(&self.response_payload)?;
            e.encode(&self.message_extension)?;
            Ok(())
        })
    }
}

impl Decodable for ResponseBatchItem {
    fn decode(decoder: &mut impl Decoder) -> ttlv::Result<Self> {
        decoder.read_struct(Tags::BatchItem, |d| {
            let op = d.decode::<Option<Operations>>()?;
            Ok(Self {
                operation: op.clone(),
                unique_batch_item_id: d.tag_decode(Tags::UniqueBatchItemID)?,
                result_status: d.decode()?,
                result_reason: d.decode()?,
                result_message: d.tag_decode(Tags::ResultMessage)?,
                asynchronous_correlation_value: d.tag_decode(Tags::AsynchronousCorrelationValue)?,
                response_payload: op
                    .map(|op| ResponsePayload::decode_with_opt(op, d))
                    .transpose()?
                    .flatten(),
                message_extension: d.decode()?,
            })
        })
    }
}

impl ResponseBatchItem {
    pub fn success(self) -> std::result::Result<Option<ResponsePayload>, ProtocolError> {
        if self.result_status != ResultStatus::Success {
            return Err(ProtocolError {
                status: self.result_status,
                reason: self.result_reason,
                message: self.result_message,
            });
        }
        Ok(self.response_payload)
    }
}
