use ttlv::{Decodable, Encodable};

use crate::{
    Tags,
    enums::ValidityIndicator,
    types::{CryptographicParameters, ProtocolVersion},
};

/// This operation requests the server to perform a signature operation on the provided data using a
/// Managed Cryptographic Object as the key for the signature operation.
/// The request contains information about the cryptographic parameters (digital signature algorithm or
/// cryptographic algorithm and hash algorithm) and the data to be signed. The cryptographic parameters
/// MAY be omitted from the request as they can be specified as associated attributes of the Managed
/// Cryptographic Object.
///
/// If the Managed Cryptographic Object referenced has a Usage Limits attribute then the server SHALL
/// obtain an allocation from the current Usage Limits value prior to performing the signing operation. If the
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
pub struct SignRequestPayload {
    /// The Unique Identifier of the Managed Cryptographic Object that is the key to use for the signature operation. If
    /// omitted, then the ID Placeholder value SHALL be used by the server as the Unique Identifier.
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: Option<String>,
    /// The Cryptographic Parameters (Digital Signature Algorithm or Cryptographic Algorithm and Hashing Algorithm) corresponding
    /// to the particular signature generation method requested. If omitted then the Cryptographic Parameters associated
    /// with the Managed Cryptographic Object with the lowest Attribute Index SHALL be used.
    /// If there are no Cryptographic Parameters associated with the Managed Cryptographic Object and the algorithm requires parameters then
    /// the operation SHALL return with a Result Status of Operation Failed.
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// The data to be signed. Mandatory for kmip 1.2 or single-part operation, unless Digested Data is supplied. Optional for multi-part.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::Data)]
    pub data: Option<Vec<u8>>,
    /// The digested data to be signed.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::DigestedData, if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub digested_data: Option<Vec<u8>>,
    /// Specifies the existing stream or by parts cryptographic operation (as returned from a previous call to this operation).
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

/// Response for the sign operation.
///
/// The response contains the Unique Identifier of the Managed Cryptographic Object used as the key and
/// the result of the signature operation.
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
pub struct SignResponsePayload {
    /// The Unique Identifier of the Managed Cryptographic Object that is the key used for the signature operation.
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    /// The signed data. Mandatory for kmip 1.2 or single-part operation, not for multi-part.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::SignatureData)]
    pub signature_data: Option<Vec<u8>>,
    /// Specifies the stream or by-parts value to be provided in subsequent calls to this operation for performing cryptographic operations.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::CorrelationValue, if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub correlation_value: Option<Vec<u8>>,
}

/// This operation requests the server to perform a signature verify operation on the provided data using a
/// Managed Cryptographic Object as the key for the signature verification operation.
/// The request contains information about the cryptographic parameters (digital signature algorithm or
/// cryptographic algorithm and hash algorithm) and the signature to be verified and MAY contain the data
/// that was passed to the signing operation (for those algorithms which need the original data to verify a
/// signature).
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
pub struct SignatureVerifyRequestPayload {
    /// The Unique Identifier of the Managed Cryptographic Object that is the key to use for the signature verify operation.
    /// If omitted, then the ID Placeholder value SHALL be used by the server as the Unique Identifier.
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: Option<String>,
    /// The Cryptographic Parameters (Digital Signature Algorithm or Cryptographic Algorithm and Hashing Algorithm)
    /// corresponding to the particular signature verification method requested. If omitted then the Cryptographic
    /// Parameters associated with the Managed Cryptographic Object with the lowest Attribute Index SHALL be used.
    ///
    /// If there are no Cryptographic Parameters associated with the Managed Cryptographic Object and the algorithm requires
    /// parameters then the operation SHALL return with a Result Status of Operation Failed.
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// The data that was signed.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::Data)]
    pub data: Option<Vec<u8>>,
    /// The digested data to be verified.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::DigestedData, if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub digested_data: Option<Vec<u8>>,
    /// The signature to be verified. Mandatory for kmip 1.2 or for single-part operation. Not for multi-part.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::SignatureData)]
    pub signature_data: Option<Vec<u8>>,
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

/// Response for SignatureVerify operation.
///
/// The response contains the Unique Identifier of the Managed Cryptographic Object used as the key and
/// the OPTIONAL data recovered from the signature (for those signature algorithms where data recovery
/// from the signature is supported). The validity of the signature is indicated by the Validity Indicator field.
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
pub struct SignatureVerifyResponsePayload {
    /// The Unique Identifier of the Managed Cryptographic Object that is the key used for the verification operation.
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    /// An Enumeration object indicating whether the signature is valid, invalid, or unknown.
    #[ttlv(tag = Tags::ValidityIndicator)]
    pub validity_indicator: ValidityIndicator,
    /// The OPTIONAL recovered data (as a Byte String) for those signature algorithms where data recovery from the signature is supported.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::Data)]
    pub data: Option<Vec<u8>>,
    /// Specifies the stream or by-parts value to be provided in subsequent calls to this operation for performing cryptographic operations.
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::CorrelationValue, if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub correlation_value: Option<Vec<u8>>,
}
