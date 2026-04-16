#![allow(deprecated)]

use std::{cmp::Ordering, str::FromStr};

use crate::{
    AlternativeNameType, AttestationType, BlockCipherMode, CredentialType, CryptographicAlgorithm,
    DRBGAlgorithm, DestroyAction, DigitalSignatureAlgorithm, FIPS186Variation, HashingAlgorithm,
    KeyFormatType, KeyRoleType, KeyValueLocationType, LinkType, MaskGenerator, NameType,
    PaddingMethod, ProfileName, RNGAlgorithm, RNGMode, RecommendedCurve, RevocationReasonCode,
    ShreddingAlgorithm, UnwrapMode, UsageLimitsUnit, ValidationAuthorityType, ValidationType,
    attributes::Attribute,
};

use super::Tags;
use strum_macros::{EnumIs, EnumTryAs};
use thiserror::Error;
use ttlv::{Decodable, Decoder, Encodable, MaybeKnownTag};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable)]
#[ttlv(tag = Tags::ProtocolVersion)]
pub struct ProtocolVersion {
    #[ttlv(tag = Tags::ProtocolVersionMajor)]
    pub protocol_version_major: i32,
    #[ttlv(tag = Tags::ProtocolVersionMinor)]
    pub protocol_version_minor: i32,
}

impl ProtocolVersion {
    pub const V1_0: Self = Self::new(1, 0);
    pub const V1_1: Self = Self::new(1, 1);
    pub const V1_2: Self = Self::new(1, 2);
    pub const V1_3: Self = Self::new(1, 3);
    pub const V1_4: Self = Self::new(1, 4);
    pub const V2_0: Self = Self::new(2, 0);
    pub const V2_1: Self = Self::new(2, 1);

    const DEFAULT_VERSION: Self = Self::V1_0;

    pub const ALL: &'static [Self] = &[
        Self::V2_1,
        Self::V2_0,
        Self::V1_4,
        Self::V1_3,
        Self::V1_2,
        Self::V1_1,
        Self::V1_0,
    ];

    pub const fn new(major: i32, minor: i32) -> Self {
        Self {
            protocol_version_major: major,
            protocol_version_minor: minor,
        }
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::DEFAULT_VERSION
    }
}

#[derive(Debug, Clone, Error)]
#[error("Cannot parse protocol version")]
pub struct ProtocolVersionParseError;

impl FromStr for ProtocolVersion {
    type Err = ProtocolVersionParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((mut major, minor)) = s.split_once('.') else {
            return Err(ProtocolVersionParseError);
        };
        if major.starts_with('v') {
            major = &major[1..];
        }
        Ok(Self {
            protocol_version_major: major.parse().or(Err(ProtocolVersionParseError))?,
            protocol_version_minor: minor.parse().or(Err(ProtocolVersionParseError))?,
        })
    }
}

impl PartialOrd for ProtocolVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProtocolVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self
            .protocol_version_major
            .cmp(&other.protocol_version_major)
        {
            Ordering::Equal => self
                .protocol_version_minor
                .cmp(&other.protocol_version_minor),
            other => other,
        }
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}",
            self.protocol_version_major, self.protocol_version_minor
        )
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(untagged))]
#[derive(Debug, Clone, PartialEq, Encodable, EnumIs, EnumTryAs)]
#[ttlv(flatten)]
pub enum CredentialValue {
    UserPassword(CredentialValueUserPassword),
    Device(CredentialValueDevice),
    Attestation(CredentialValueAttestation),
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::CredentialValue)]
pub struct CredentialValueUserPassword {
    #[ttlv(tag = Tags::Username)]
    pub username: String,
    #[ttlv(tag = Tags::Password)]
    pub password: Option<String>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable, Default)]
#[ttlv(tag = Tags::CredentialValue)]
pub struct CredentialValueDevice {
    #[ttlv(tag = Tags::DeviceSerialNumber)]
    pub device_serial_number: Option<String>,
    #[ttlv(tag = Tags::Password)]
    pub password: Option<String>,
    #[ttlv(tag = Tags::DeviceIdentifier)]
    pub device_identifier: Option<String>,
    #[ttlv(tag = Tags::NetworkIdentifier)]
    pub network_identifier: Option<String>,
    #[ttlv(tag = Tags::MachineIdentifier)]
    pub machine_identifier: Option<String>,
    #[ttlv(tag = Tags::MediaIdentifier)]
    pub media_identifier: Option<String>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::CredentialValue)]
pub struct CredentialValueAttestation {
    pub nonce: Nonce,
    pub attestation_type: AttestationType,
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::AttestationMeasurement)]
    pub attestation_measurement: Option<Vec<u8>>,
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::AttestationAssertion)]
    pub attestation_assertion: Option<Vec<u8>>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable)]
#[ttlv(tag = Tags::Credential)]
pub struct Credential {
    pub credential_type: CredentialType,
    pub credential_value: CredentialValue,
}

impl Decodable for Credential {
    fn decode(decoder: &mut impl ttlv::Decoder) -> ttlv::Result<Self> {
        decoder.read_struct(Tags::Credential, |d| {
            let ctype = d.decode()?;
            let cval = match ctype {
                CredentialType::UsernameAndPassword => CredentialValue::UserPassword(d.decode()?),
                CredentialType::Device => CredentialValue::Device(d.decode()?),
                CredentialType::Attestation => CredentialValue::Attestation(d.decode()?),
            };
            Ok(Self {
                credential_type: ctype,
                credential_value: cval,
            })
        })
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::Authentication)]
pub struct Authentication {
    pub credential: Credential,
    // Starting from KMIP 1.2, Credential can be repeated
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub additional_credentials: Vec<Credential>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::MessageExtension)]
pub struct MessageExtension {
    #[ttlv(tag = Tags::VendorIdentification)]
    pub vendor_identification: String,
    #[ttlv(tag = Tags::CriticalityIndicator)]
    pub criticality_indicator: bool,
    #[ttlv(tag = Tags::VendorExtension)]
    pub vendor_extension: ttlv::Struct<MaybeKnownTag<Tags>>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable, Default)]
#[ttlv(tag = Tags::CryptographicDomainParameters)]
pub struct CryptographicDomainParameters {
    #[ttlv(tag = Tags::Qlength)]
    pub qlength: Option<i32>,
    pub recommended_curve: Option<RecommendedCurve>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable, Default)]
#[ttlv(tag = Tags::CryptographicParameters)]
pub struct CryptographicParameters {
    pub block_cipher_mode: Option<BlockCipherMode>,
    pub padding_method: Option<PaddingMethod>,
    pub hashing_algorithm: Option<HashingAlgorithm>,
    pub key_role_type: Option<KeyRoleType>,

    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub digital_signature_algorithm: Option<DigitalSignatureAlgorithm>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    #[ttlv(tag = Tags::RandomIV, if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub random_iv: Option<bool>,
    #[ttlv(tag = Tags::IVLength, if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub iv_length: Option<i32>,
    #[ttlv(tag = Tags::TagLength, if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub tag_length: Option<i32>,
    #[ttlv(tag = Tags::FixedFieldLength, if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub fixed_field_length: Option<i32>,
    #[ttlv(tag = Tags::InvocationFieldLength, if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub invocation_field_length: Option<i32>,
    #[ttlv(tag = Tags::CounterLength, if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub counter_length: Option<i32>,
    #[ttlv(tag = Tags::InitialCounterValue, if(_ext.is_in(ProtocolVersion::V1_2..)))]
    pub initial_counter_value: Option<i32>,

    #[ttlv(tag = Tags::SaltLength, if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub salt_length: Option<i32>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub mask_generator: Option<MaskGenerator>,
    #[ttlv(tag = Tags::MaskGeneratorHashingAlgorithm, if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub mask_generator_hashing_algorithm: Option<HashingAlgorithm>,
    #[cfg_attr(feature = "serde", serde_as(as = "Option<serde_with::base64::Base64>"))]
    #[ttlv(tag = Tags::PSource, if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub p_source: Option<Vec<u8>>,
    #[ttlv(tag = Tags::TrailerField, if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub trailer_field: Option<i32>,
}

impl CryptographicParameters {
    pub fn aes_cbc_pkcs5() -> Self {
        Self {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::CBC),
            padding_method: Some(PaddingMethod::PKCS5),
            iv_length: Some(16),
            ..Default::default()
        }
    }

    pub fn aes_gcm() -> Self {
        Self {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::GCM),
            iv_length: Some(12),
            tag_length: Some(16),
            ..Default::default()
        }
    }

    fn rsa_oaep(hash: HashingAlgorithm) -> Self {
        Self {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(hash),
            mask_generator: Some(MaskGenerator::MGF1),
            mask_generator_hashing_algorithm: Some(hash),
            ..Default::default()
        }
    }

    pub fn rsa_oaep_sha256() -> Self {
        Self::rsa_oaep(HashingAlgorithm::SHA256)
    }

    pub fn rsa_oaep_sha384() -> Self {
        Self::rsa_oaep(HashingAlgorithm::SHA384)
    }

    pub fn rsa_oaep_sha512() -> Self {
        Self::rsa_oaep(HashingAlgorithm::SHA512)
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::Link)]
pub struct Link {
    pub link_type: LinkType,
    #[ttlv(tag = Tags::LinkedObjectIdentifier)]
    pub linked_object_identifier: String,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::Digest)]
pub struct Digest {
    pub hashing_algorithm: HashingAlgorithm,
    #[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))]
    #[ttlv(tag = Tags::DigestValue)]
    pub digest_value: Vec<u8>,
    #[ttlv(if(_ext.is_in(ProtocolVersion::V1_1..)))]
    pub key_format_type: Option<KeyFormatType>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable, Default)]
pub struct TemplateAttribute {
    #[deprecated = "deprecated as of kmip 1.3"]
    pub name: Vec<Name>,
    pub attribute: Vec<Attribute>,
}

impl TemplateAttribute {
    //TODO: Accept an iterator of impl Into<Attribute>
    pub fn new(attrs: Vec<Attribute>) -> Self {
        Self {
            name: Vec::new(),
            attribute: attrs,
        }
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::Name)]
pub struct Name {
    #[ttlv(tag = Tags::NameValue)]
    pub name_value: String,
    pub name_type: NameType,
}

impl Name {
    pub fn new_uri(value: impl Into<String>) -> Self {
        Self {
            name_value: value.into(),
            name_type: NameType::URI,
        }
    }

    pub fn new_string(value: impl Into<String>) -> Self {
        Self {
            name_value: value.into(),
            name_type: NameType::UninterpretedTextString,
        }
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RevocationReason)]
pub struct RevocationReason {
    pub revocation_reason_code: RevocationReasonCode,
    #[ttlv(tag = Tags::RevocationMessage)]
    pub revocation_message: Option<String>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::CertificateIdentifier)]
#[deprecated = "deprecated as of kmip 1.1"]
pub struct CertificateIdentifier {
    #[ttlv(tag = Tags::Issuer)]
    pub issuer: String,
    #[ttlv(tag = Tags::SerialNumber)]
    pub serial_number: Option<String>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::CertificateSubject)]
#[deprecated = "deprecated as of kmip 1.1"]
pub struct CertificateSubject {
    #[ttlv(tag = Tags::CertificateSubjectDistinguishedName)]
    pub certificate_subject_distinguished_name: String,
    #[ttlv(tag = Tags::CertificateSubjectAlternativeName)]
    pub certificate_subject_alternative_name: Vec<String>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::CertificateIssuer)]
#[deprecated = "deprecated as of kmip 1.1"]
pub struct CertificateIssuer {
    #[ttlv(tag = Tags::CertificateIssuerDistinguishedName)]
    pub certificate_issuer_distinguished_name: String,
    #[ttlv(tag = Tags::CertificateIssuerAlternativeName)]
    pub certificate_issuer_alternative_name: Vec<String>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ApplicationSpecificInformation)]
pub struct ApplicationSpecificInformation {
    #[ttlv(tag = Tags::ApplicationNamespace)]
    pub application_namespace: String,
    #[ttlv(tag = Tags::ApplicationData)]
    pub application_data: Option<String>, //TODO: Optional since kmip 1.3, not before
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::UsageLimits)]
pub struct UsageLimits {
    #[ttlv(tag = Tags::UsageLimitsTotal)]
    pub usage_limits_total: i64,
    #[ttlv(tag = Tags::UsageLimitsCount)]
    pub usage_limits_count: Option<i64>,
    pub usage_limits_unit: UsageLimitsUnit,
}

//KMIP 1.1

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ExtensionInformation)]
pub struct ExtensionInformation {
    #[ttlv(tag = Tags::ExtensionName)]
    pub extension_name: String,
    #[ttlv(tag = Tags::ExtensionTag)]
    pub extension_tag: Option<i32>,
    #[ttlv(tag = Tags::ExtensionType)]
    pub extension_type: Option<i32>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::X509CertificateIdentifier)]
pub struct X509CertificateIdentifier {
    #[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))]
    #[ttlv(tag = Tags::IssuerDistinguishedName)]
    pub issuer_distinguished_name: Vec<u8>,
    #[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))]
    #[ttlv(tag = Tags::CertificateSerialNumber)]
    pub certificate_serial_number: Vec<u8>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::X509CertificateSubject)]
pub struct X509CertificateSubject {
    #[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))]
    #[ttlv(tag = Tags::SubjectDistinguishedName)]
    pub subject_distinguished_name: Vec<u8>,
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "Option<Vec<serde_with::base64::Base64>>")
    )]
    #[ttlv(tag = Tags::SubjectAlternativeName)]
    pub subject_alternative_name: Option<Vec<Vec<u8>>>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::X509CertificateIssuer)]
pub struct X509CertificateIssuer {
    #[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))]
    #[ttlv(tag = Tags::IssuerDistinguishedName)]
    pub issuer_distinguished_name: Vec<u8>,
    #[cfg_attr(
        feature = "serde",
        serde_as(as = "Option<Vec<serde_with::base64::Base64>>")
    )]
    #[ttlv(tag = Tags::IssuerAlternativeName)]
    pub issuer_alternative_name: Option<Vec<Vec<u8>>>,
}

//KMIP 1.2

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(
    feature = "serde",
    cfg_eval::cfg_eval,
    serde_with::serde_as,
    derive(serde::Serialize)
)]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::Nonce)]
pub struct Nonce {
    #[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))]
    #[ttlv(tag = Tags::NonceID)]
    pub nonce_id: Vec<u8>,
    #[cfg_attr(feature = "serde", serde_as(as = "serde_with::base64::Base64"))]
    #[ttlv(tag = Tags::NonceValue)]
    pub nonce_value: Vec<u8>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::AlternativeName)]
pub struct AlternativeName {
    #[ttlv(tag = Tags::AlternativeNameValue)]
    pub alternative_name_value: String,
    pub alternative_name_type: AlternativeNameType,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::KeyValueLocation)]
pub struct KeyValueLocation {
    #[ttlv(tag = Tags::KeyValueLocationValue)]
    pub key_value_location_value: String,
    pub key_value_location_type: KeyValueLocationType,
}

// KMIP 1.3
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::RNGParameters)]
pub struct RNGParameters {
    pub rng_algorithm: RNGAlgorithm,
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    #[ttlv(tag = Tags::CryptographicLength)]
    pub cryptographic_length: Option<i32>,
    pub hashing_algorithm: Option<HashingAlgorithm>,
    pub drbg_algorithm: Option<DRBGAlgorithm>,
    pub recommended_curve: Option<RecommendedCurve>,
    pub fips186_variation: Option<FIPS186Variation>,
    #[ttlv(tag = Tags::PredictionResistance)]
    pub prediction_resistance: Option<bool>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ProfileInformation)]
pub struct ProfileInformation {
    pub profile_name: ProfileName,
    #[ttlv(tag = Tags::ServerURI)]
    pub server_uri: Option<String>,
    #[ttlv(tag = Tags::ServerPort)]
    pub server_port: Option<i32>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable)]
#[ttlv(tag = Tags::ValidationInformation)]
pub struct ValidationInformation {
    pub validation_authority_type: ValidationAuthorityType,
    #[ttlv(tag = Tags::ValidationAuthorityCountry)]
    pub validation_authority_country: Option<String>,
    #[ttlv(tag = Tags::ValidationAuthorityURI)]
    pub validation_authority_uri: Option<String>,
    #[ttlv(tag = Tags::ValidationVersionMajor)]
    pub validation_version_major: i32,
    #[ttlv(tag = Tags::ValidationVersionMinor)]
    pub validation_version_minor: Option<i32>,
    pub validation_type: ValidationType,
    #[ttlv(tag = Tags::ValidationLevel)]
    pub validation_level: i32,
    #[ttlv(tag = Tags::ValidationCertificateIdentifier)]
    pub validation_certificate_identifier: Option<String>,
    #[ttlv(tag = Tags::ValidationCertificateURI)]
    pub validation_certificate_uri: Option<String>,
    #[ttlv(tag = Tags::ValidationVendorURI)]
    pub validation_vendor_uri: Option<String>,
    #[ttlv(tag = Tags::ValidationProfile)]
    pub validation_profile: Vec<String>,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Encodable, Decodable, Default)]
#[ttlv(tag = Tags::CapabilityInformation)]
pub struct CapabilityInformation {
    #[ttlv(tag = Tags::StreamingCapability)]
    pub streaming_capability: Option<bool>,
    #[ttlv(tag = Tags::AsynchronousCapability)]
    pub asynchronous_capability: Option<bool>,
    #[ttlv(tag = Tags::AttestationCapability)]
    pub attestation_capability: Option<bool>,
    #[ttlv(tag = Tags::BatchUndoCapability, if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub batch_undo_capability: Option<bool>,
    #[ttlv(tag = Tags::BatchContinueCapability, if(_ext.is_in(ProtocolVersion::V1_4..)))]
    pub batch_continue_capability: Option<bool>,
    pub unwrap_mode: Option<UnwrapMode>,
    pub destroy_action: Option<DestroyAction>,
    pub shredding_algorithm: Option<ShreddingAlgorithm>,
    pub rng_mode: Option<RNGMode>,
}
