use ttlv::{Decodable, Encodable, MaybeKnownTag, Value};

use crate::{
    AttestationType, CapabilityInformation, ClientRegistrationMethod, ExtensionInformation,
    ObjectType, Operations, ProfileInformation, ProtocolVersion, QueryFunction, RNGParameters,
    Tags, ValidationInformation,
};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RequestPayload)]
pub struct QueryRequestPayload {
    pub query_function: Vec<QueryFunction>,
}

impl QueryRequestPayload {
    pub fn all() -> Self {
        Self {
            query_function: vec![
                QueryFunction::QueryOperations,
                QueryFunction::QueryObjects,
                QueryFunction::QueryServerInformation,
                QueryFunction::QueryApplicationNamespaces,
                QueryFunction::QueryExtensionList,
                QueryFunction::QueryExtensionMap,
                QueryFunction::QueryAttestationTypes,
                QueryFunction::QueryRNGs,
                QueryFunction::QueryValidations,
                QueryFunction::QueryProfiles,
                QueryFunction::QueryCapabilities,
                QueryFunction::QueryClientRegistrationMethods,
            ],
        }
    }
}

impl Default for QueryRequestPayload {
    fn default() -> Self {
        Self::all()
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable, Default)]
#[ttlv(tag = Tags::ResponsePayload)]
pub struct QueryResponsePayload {
    pub operation: Vec<Operations>,
    pub object_type: Vec<ObjectType>,
    #[ttlv(tag = Tags::VendorIdentification)]
    pub vendor_identification: Option<String>,
    #[ttlv(tag = Tags::ServerInformation)]
    pub server_information: Option<Value<MaybeKnownTag<Tags>>>,
    #[ttlv(tag = Tags::ApplicationNamespace)]
    pub application_namespace: Vec<String>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_1..)))]
    pub extension_information: Vec<ExtensionInformation>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub attestation_type: Vec<AttestationType>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub rng_parameters: Vec<RNGParameters>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub profile_information: Vec<ProfileInformation>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub validation_information: Vec<ValidationInformation>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub capability_information: Vec<CapabilityInformation>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_3..)))]
    pub client_registration_method: Vec<ClientRegistrationMethod>,
}
