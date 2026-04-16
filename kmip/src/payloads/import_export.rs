use ttlv::{Decodable, Encodable};

use crate::{
    Attribute, KeyCompressionType, KeyFormatType, KeyWrapType, KeyWrappingSpecification, Object,
    ObjectType, Tags,
};

/// This operation requests the server to Import a Managed Object specified by its Unique Identifier.
/// The request specifies the object being imported and all the attributes to be assigned to the object.
/// The attribute rules for each attribute for “Initially set by” and “When implicitly set” SHALL NOT be enforced as all attributes
/// MUST be set to the supplied values rather than any server generated values.
///
/// Special authentication and authorization SHOULD be enforced to perform this request.
/// Only the object owner or an authorized security officer SHOULD be allowed to issue this request.
///
/// The response contains the Unique Identifier provided in the request or assigned by the server.
/// The server SHALL copy the Unique Identifier returned by this operations into the ID Placeholder variable.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Decodable, Encodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct ImportRequestPayload {
    /// The Unique Identifier of the object to be imported.
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    /// A Boolean.  If specified and true then any existing object with the same Unique Identifier SHALL be replaced by this operation.
    /// If absent or false then the operation SHALL fail if there is an existing object with the same Unique Identifier.
    #[ttlv(tag = Tags::ReplaceExisting)]
    pub replace_existing: Option<bool>,
    /// If Not Wrapped then the server SHALL unwrap the object before storing it, and return an error if the wrapping key is not available.
    /// Otherwise the server SHALL store the object as provided.
    pub key_wrap_type: Option<KeyWrapType>,
    /// All of the object’s Attributes.
    pub attribute: Vec<Attribute>,
    /// The object value being imported, in the same manner as the Register operation.
    pub object: Object,
}

/// Response for the Import operation. See [`ImportRequestPayload`].
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Decodable, Encodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct ImportResponsePayload {
    /// The Unique Identifier of the object.
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
}

/// This operation requests that the server returns a Managed Object specified by its Unique Identifier, together with its attributes.
///
/// The Key Format Type, Key Wrap Type, Key Compression Type and Key Wrapping Specification SHALL have the same semantics as for the Get operation.
/// If the Managed Object has been Destroyed then the key material for the specified managed object SHALL not be returned in the response.
///
/// The server SHALL copy the Unique Identifier returned by this operations into the ID Placeholder variable.
/// Special authentication and authorization SHOULD be enforced to perform this request.
///
/// Only the object owner or an authorized security officer SHOULD be allowed to issue this request.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Decodable, Encodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct ExportRequestPayload {
    /// Determines the object being requested. If omitted, then the IDPlaceholder value is used by the server as the Unique Identifier.
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: Option<String>,
    /// Determines the key format type to be returned.
    pub key_format_type: Option<KeyFormatType>,
    /// Determines the Key Wrap Type of the returned key value.
    pub key_wrap_type: Option<KeyWrapType>,
    /// Determines the compression method for elliptic curve public keys.
    pub key_compression_type: Option<KeyCompressionType>,
    /// Specifies keys and other information for wrapping the returned object.
    pub key_wrapping_specification: Option<KeyWrappingSpecification>,
}

/// Response for the Export operation. See [`ExportRequestPayload`].
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Decodable, Encodable)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct ExportResponsePayload {
    /// Type of object.
    pub object_type: ObjectType,
    /// The Unique Identifier of the object.
    #[ttlv(tag = Tags::UniqueIdentifier)]
    pub unique_identifier: String,
    /// All of the object’s Attributes.
    pub attribute: Vec<Attribute>,
    /// The object value being returned, in the same manner as the Get operation.
    pub object: Object,
}
