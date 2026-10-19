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
    /// The data to be MACed. Mandatory for kmip 1.2 or single-part operation. Optional for multi-part.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::Data)]
    pub data: Option<Vec<u8>>,
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
    /// The data that was MACed.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::Data)]
    pub data: Option<Vec<u8>>,
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
    ///
    /// Mandatory for a single-part operation and for the final part of a multi-part
    /// operation. The intermediate parts of a multi-part operation only return the
    /// Correlation Value (see the OASIS test case TC-STREAM-MAC-1-14).
    #[ttlv(tag = Tags::ValidityIndicator)]
    pub validity_indicator: ValidityIndicator,
    /// Specifies the stream or by-parts value to be provided in subsequent calls to this operation for performing cryptographic operations.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::CorrelationValue, if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub correlation_value: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use ttlv::{Decodable, Encodable, Encoder, TtlvDecoder, TtlvEncoder, XmlDecoder};

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
            data: Some("data".into()),
            cryptographic_parameters: None,
            correlation_value: Some(vec![1, 2, 3]),
            init_indicator: Some(true),
            final_indicator: Some(false),
        }
    }

    fn mac_verify_request() -> MacVerifyRequestPayload {
        MacVerifyRequestPayload {
            unique_identifier: Some("key-1".into()),
            data: Some("data".into()),
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

    // Messages taken from the OASIS KMIP 1.4 test case TC-STREAM-MAC-1-14
    // (docs.oasis-open.org/kmip/testcases/v1.4/cn01/test-cases/kmip-v1.4/),
    // with the `$...` placeholders replaced by concrete values.
    const XML_REQ_HDR: &str = r#"<RequestHeader><ProtocolVersion><ProtocolVersionMajor type="Integer" value="1"/><ProtocolVersionMinor type="Integer" value="4"/></ProtocolVersion><BatchCount type="Integer" value="1"/></RequestHeader>"#;
    const XML_RESP_HDR: &str = r#"<ResponseHeader><ProtocolVersion><ProtocolVersionMajor type="Integer" value="1"/><ProtocolVersionMinor type="Integer" value="4"/></ProtocolVersion><TimeStamp type="DateTime" value="2026-10-14T10:00:00+00:00"/><BatchCount type="Integer" value="1"/></ResponseHeader>"#;

    fn xml_request(op: &str, payload: &str) -> RequestPayload {
        let xml = format!(
            r#"<RequestMessage>{XML_REQ_HDR}<BatchItem><Operation type="Enumeration" value="{op}"/><RequestPayload>{payload}</RequestPayload></BatchItem></RequestMessage>"#
        );
        RequestMessage::decode(&mut XmlDecoder::new(xml.as_bytes()).unwrap())
            .unwrap()
            .batch_item
            .remove(0)
            .request_payload
    }

    fn xml_response(op: &str, payload: &str) -> ResponsePayload {
        let xml = format!(
            r#"<ResponseMessage>{XML_RESP_HDR}<BatchItem><Operation type="Enumeration" value="{op}"/><ResultStatus type="Enumeration" value="Success"/><ResponsePayload>{payload}</ResponsePayload></BatchItem></ResponseMessage>"#
        );
        ResponseMessage::decode(&mut XmlDecoder::new(xml.as_bytes()).unwrap())
            .unwrap()
            .batch_item
            .remove(0)
            .response_payload
            .unwrap()
    }

    #[test]
    fn oasis_tc_stream_mac_1_14_mac() {
        let got = xml_request(
            "MAC",
            r#"<UniqueIdentifier type="TextString" value="TC-STREAM-MAC-1-14"/><Data type="ByteString" value="0102"/><InitIndicator type="Boolean" value="true"/>"#,
        );
        assert_eq!(
            got,
            RequestPayload::MAC(MacRequestPayload {
                unique_identifier: Some("TC-STREAM-MAC-1-14".into()),
                cryptographic_parameters: None,
                data: Some(vec![0x01, 0x02]),
                correlation_value: None,
                init_indicator: Some(true),
                final_indicator: None,
            })
        );

        let got = xml_request(
            "MAC",
            r#"<UniqueIdentifier type="TextString" value="TC-STREAM-MAC-1-14"/><Data type="ByteString" value="1516"/><CorrelationValue type="ByteString" value="abcd"/><FinalIndicator type="Boolean" value="true"/>"#,
        );
        assert_eq!(
            got,
            RequestPayload::MAC(MacRequestPayload {
                unique_identifier: Some("TC-STREAM-MAC-1-14".into()),
                cryptographic_parameters: None,
                data: Some(vec![0x15, 0x16]),
                correlation_value: Some(vec![0xab, 0xcd]),
                init_indicator: None,
                final_indicator: Some(true),
            })
        );

        let got = xml_response(
            "MAC",
            r#"<UniqueIdentifier type="TextString" value="TC-STREAM-MAC-1-14"/><CorrelationValue type="ByteString" value="abcd"/>"#,
        );
        assert_eq!(
            got,
            ResponsePayload::MAC(MacResponsePayload {
                unique_identifier: "TC-STREAM-MAC-1-14".into(),
                mac_data: None,
                correlation_value: Some(vec![0xab, 0xcd]),
            })
        );

        let got = xml_response(
            "MAC",
            r#"<UniqueIdentifier type="TextString" value="TC-STREAM-MAC-1-14"/><MACData type="ByteString" value="c911e78196d64c30f631bb079ea37b97a95936d4da764d6a171df030c895ecf9"/>"#,
        );
        let ResponsePayload::MAC(pl) = got else {
            panic!("expected MAC response, got {got:?}");
        };
        assert_eq!(pl.unique_identifier, "TC-STREAM-MAC-1-14");
        assert_eq!(pl.correlation_value, None);
        let mac = pl.mac_data.unwrap();
        assert_eq!(mac.len(), 32);
        assert_eq!(&mac[..4], &[0xc9, 0x11, 0xe7, 0x81]);
        assert_eq!(&mac[28..], &[0xc8, 0x95, 0xec, 0xf9]);
    }

    #[test]
    fn oasis_tc_stream_mac_1_14_mac_verify() {
        let got = xml_request(
            "MACVerify",
            r#"<UniqueIdentifier type="TextString" value="TC-STREAM-MAC-1-14"/><Data type="ByteString" value="01020304"/><MACData type="ByteString" value="c911e781"/><InitIndicator type="Boolean" value="true"/>"#,
        );
        assert_eq!(
            got,
            RequestPayload::MACVerify(MacVerifyRequestPayload {
                unique_identifier: Some("TC-STREAM-MAC-1-14".into()),
                cryptographic_parameters: None,
                data: Some(vec![0x01, 0x02, 0x03, 0x04]),
                mac_data: Some(vec![0xc9, 0x11, 0xe7, 0x81]),
                correlation_value: None,
                init_indicator: Some(true),
                final_indicator: None,
            })
        );

        let got = xml_request(
            "MACVerify",
            r#"<UniqueIdentifier type="TextString" value="TC-STREAM-MAC-1-14"/><Data type="ByteString" value="13141516"/><CorrelationValue type="ByteString" value="abcd"/><FinalIndicator type="Boolean" value="true"/>"#,
        );
        assert_eq!(
            got,
            RequestPayload::MACVerify(MacVerifyRequestPayload {
                unique_identifier: Some("TC-STREAM-MAC-1-14".into()),
                cryptographic_parameters: None,
                data: Some(vec![0x13, 0x14, 0x15, 0x16]),
                mac_data: None,
                correlation_value: Some(vec![0xab, 0xcd]),
                init_indicator: None,
                final_indicator: Some(true),
            })
        );

        let got = xml_response(
            "MACVerify",
            r#"<UniqueIdentifier type="TextString" value="TC-STREAM-MAC-1-14"/><ValidityIndicator type="Enumeration" value="Valid"/>"#,
        );
        assert_eq!(
            got,
            ResponsePayload::MACVerify(MacVerifyResponsePayload {
                unique_identifier: "TC-STREAM-MAC-1-14".into(),
                validity_indicator: ValidityIndicator::Valid,
                correlation_value: None,
            })
        );
    }
}
