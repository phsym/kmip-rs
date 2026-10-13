use ttlv::{Decodable, Encodable};

use crate::{
    Tags,
    enums::ValidityIndicator,
    types::{CryptographicParameters, ProtocolVersion},
};

/// This operation requests the server to perform a MAC operation on the provided data using a Managed
/// Cryptographic Object as the key for the MAC operation.
/// The request contains information about the cryptographic parameters (cryptographic algorithm) and
/// the data to be MACed. The cryptographic parameters MAY be omitted from the request as they can be
/// specified as associated attributes of the Managed Cryptographic Object.
///
/// If the Managed Cryptographic Object referenced has a Usage Limits attribute then the server SHALL
/// obtain an allocation from the current Usage Limits value prior to performing the MAC operation. If the
/// allocation is unable to be obtained the operation SHALL return with a result status of Operation Failed
/// and result reason of Permission Denied.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct MacRequestPayload {
    /// The Unique Identifier of the Managed Cryptographic Object that is the key to use for the MAC operation. If
    /// omitted, then the ID Placeholder value SHALL be used by the server as the Unique Identifier.
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: Option<String>,
    /// The Cryptographic Parameters (Cryptographic Algorithm) corresponding to the particular MAC method requested.
    /// If omitted then the Cryptographic Parameters associated with the Managed Cryptographic Object with the lowest
    /// Attribute Index SHALL be used.
    /// If there are no Cryptographic Parameters associated with the Managed Cryptographic Object and the algorithm
    /// requires parameters then the operation SHALL return with a Result Status of Operation Failed.
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// Specifies the existing stream or by-parts cryptographic operation (as returned from a previous call to this operation).
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::CorrelationValue, if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub correlation_value: Option<Vec<u8>>,
    /// Initial operation.
    #[ttlv(tag = Tags::InitIndicator, if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub init_indicator: Option<bool>,
    /// Final operation.
    #[ttlv(tag = Tags::FinalIndicator, if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub final_indicator: Option<bool>,
}

/// Response for the MAC operation.
///
/// The response contains the Unique Identifier of the Managed Cryptographic Object used as the key and
/// the result of the MAC operation.
///
/// The success or failure of the operation is indicated by the Result Status (and if failure the Result Reason)
/// in the response header.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Decodable, Encodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct MacResponsePayload {
    /// The Unique Identifier of the Managed Cryptographic Object that is the key used for the MAC operation.
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    /// The data MACed. Mandatory for kmip 1.2 or single-part operation, not for multi-part.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::MACData)]
    pub mac_data: Option<Vec<u8>>,
    /// Specifies the stream or by-parts value to be provided in subsequent calls to this operation for performing cryptographic operations.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::CorrelationValue, if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub correlation_value: Option<Vec<u8>>,
}

/// This operation requests the server to perform a MAC verify operation on the provided data using a
/// Managed Cryptographic Object as the key for the MAC verification operation.
/// The request contains information about the cryptographic parameters (cryptographic algorithm) and the
/// MAC to be verified and MAY contain the data that was passed to the MAC operation.
///
/// The cryptographic parameters MAY be omitted from the request as they can be specified as associated
/// attributes of the Managed Cryptographic Object.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct MacVerifyRequestPayload {
    /// The Unique Identifier of the Managed Cryptographic Object that is the key to use for the MAC verify operation.
    /// If omitted, then the ID Placeholder value SHALL be used by the server as the Unique Identifier.
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: Option<String>,
    /// The Cryptographic Parameters (Cryptographic Algorithm) corresponding to the particular MAC verification method
    /// requested. If omitted then the Cryptographic Parameters associated with the Managed Cryptographic Object with the
    /// lowest Attribute Index SHALL be used.
    ///
    /// If there are no Cryptographic Parameters associated with the Managed Cryptographic Object and the algorithm requires
    /// parameters then the operation SHALL return with a Result Status of Operation Failed.
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// The MAC to be verified. Mandatory for kmip 1.2 or for single-part operation. Not for multi-part.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::MACData)]
    pub mac_data: Option<Vec<u8>>,
    /// Specifies the existing stream or by-parts cryptographic operation (as returned from a previous call to this operation).
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::CorrelationValue, if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub correlation_value: Option<Vec<u8>>,
    /// Initial operation.
    #[ttlv(tag = Tags::InitIndicator, if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub init_indicator: Option<bool>,
    /// Final operation.
    #[ttlv(tag = Tags::FinalIndicator, if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub final_indicator: Option<bool>,
}

/// Response for the MAC Verify operation.
///
/// The response contains the Unique Identifier of the Managed Cryptographic Object used as the key.
/// The validity of the MAC is indicated by the Validity Indicator field.
///
/// The success or failure of the operation is indicated by the Result Status (and if failure the Result Reason)
/// in the response header.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Decodable, Encodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct MacVerifyResponsePayload {
    /// The Unique Identifier of the Managed Cryptographic Object that is the key used for the verification operation.
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    /// An Enumeration object indicating whether the MAC is valid, invalid, or unknown.
    #[ttlv(tag = Tags::ValidityIndicator)]
    pub validity_indicator: ValidityIndicator,
    /// Specifies the stream or by-parts value to be provided in subsequent calls to this operation for performing cryptographic operations.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::CorrelationValue, if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub correlation_value: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use ttlv::{Decodable, Encodable, Encoder, TtlvDecoder, TtlvEncoder};

    use super::*;
    use crate::{
        RequestMessage, ResponseBatchItem, ResponseHeader, ResponseMessage,
        enums::{Operations, ResultStatus},
        payloads::{RequestPayload, ResponsePayload},
    };

    fn roundtrip<T: Encodable + Decodable>(value: &T) -> T {
        let mut enc = TtlvEncoder::new();
        enc.encode(value).unwrap();
        T::decode(&mut TtlvDecoder::new(enc.bytes())).unwrap()
    }

    fn request_roundtrip(
        version: ProtocolVersion,
        pl: impl Into<RequestPayload>,
    ) -> RequestPayload {
        let msg = RequestMessage::new(version, pl);
        roundtrip(&msg).batch_item.remove(0).request_payload
    }

    fn response_roundtrip(
        version: ProtocolVersion,
        op: Operations,
        pl: impl Into<ResponsePayload>,
    ) -> ResponsePayload {
        let msg = ResponseMessage {
            header: ResponseHeader {
                protocol_version: version,
                timestamp: chrono::Local::now(),
                nonce: None,
                attestation_type: None,
                client_correlation_value: None,
                server_correlation_value: None,
                batch_count: 1,
            },
            batch_item: vec![ResponseBatchItem {
                operation: Some(op),
                unique_batch_item_id: None,
                result_status: ResultStatus::Success,
                result_reason: None,
                result_message: None,
                asynchronous_correlation_value: None,
                response_payload: Some(pl.into()),
                message_extension: None,
            }],
        };
        roundtrip(&msg)
            .batch_item
            .remove(0)
            .response_payload
            .unwrap()
    }

    fn mac_request() -> MacRequestPayload {
        MacRequestPayload {
            unique_identifier: Some("key-1".into()),
            cryptographic_parameters: None,
            correlation_value: Some(vec![1, 2, 3]),
            init_indicator: Some(true),
            final_indicator: Some(false),
        }
    }

    fn mac_verify_request() -> MacVerifyRequestPayload {
        MacVerifyRequestPayload {
            unique_identifier: Some("key-1".into()),
            cryptographic_parameters: None,
            mac_data: Some(vec![0xAA; 32]),
            correlation_value: Some(vec![1, 2, 3]),
            init_indicator: Some(true),
            final_indicator: Some(false),
        }
    }

    #[test]
    fn mac_request_roundtrip() {
        let pl = mac_request();
        assert_eq!(
            request_roundtrip(ProtocolVersion::V1_4, pl.clone()),
            RequestPayload::MAC(pl)
        );
    }

    #[test]
    fn mac_request_drops_multipart_fields_before_v1_3() {
        let pl = mac_request();
        let want = MacRequestPayload {
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
            ..pl.clone()
        };
        assert_eq!(
            request_roundtrip(ProtocolVersion::V1_2, pl),
            RequestPayload::MAC(want)
        );
    }

    #[test]
    fn mac_response_roundtrip() {
        let pl = MacResponsePayload {
            unique_identifier: "key-1".into(),
            mac_data: Some(vec![0xAA; 32]),
            correlation_value: Some(vec![1, 2, 3]),
        };
        assert_eq!(
            response_roundtrip(ProtocolVersion::V1_4, Operations::MAC, pl.clone()),
            ResponsePayload::MAC(pl)
        );
    }

    #[test]
    fn mac_verify_request_roundtrip() {
        let pl = mac_verify_request();
        assert_eq!(
            request_roundtrip(ProtocolVersion::V1_4, pl.clone()),
            RequestPayload::MACVerify(pl)
        );
    }

    #[test]
    fn mac_verify_request_drops_multipart_fields_before_v1_3() {
        let pl = mac_verify_request();
        let want = MacVerifyRequestPayload {
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
            ..pl.clone()
        };
        assert_eq!(
            request_roundtrip(ProtocolVersion::V1_2, pl),
            RequestPayload::MACVerify(want)
        );
    }

    #[test]
    fn mac_verify_response_roundtrip() {
        let pl = MacVerifyResponsePayload {
            unique_identifier: "key-1".into(),
            validity_indicator: ValidityIndicator::Valid,
            correlation_value: Some(vec![1, 2, 3]),
        };
        assert_eq!(
            response_roundtrip(ProtocolVersion::V1_4, Operations::MACVerify, pl.clone()),
            ResponsePayload::MACVerify(pl)
        );
    }
}
