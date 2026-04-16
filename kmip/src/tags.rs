#![allow(deprecated)]

use std::str::FromStr;

use strum_macros::{Display, EnumString, FromRepr, IntoStaticStr};
use ttlv::{Error, RawTag, RawTagRef, Tag};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, IntoStaticStr, Display, FromRepr, EnumString)]
#[repr(u32)]
pub enum Tags {
    ActivationDate = 0x420001,
    ApplicationData = 0x420002,
    ApplicationNamespace = 0x420003,
    ApplicationSpecificInformation = 0x420004,
    ArchiveDate = 0x420005,
    AsynchronousCorrelationValue = 0x420006,
    AsynchronousIndicator = 0x420007,
    Attribute = 0x420008,
    AttributeIndex = 0x420009,
    AttributeName = 0x42000A,
    AttributeValue = 0x42000B,
    Authentication = 0x42000C,
    BatchCount = 0x42000D,
    BatchErrorContinuationOption = 0x42000E,
    BatchItem = 0x42000F,
    BatchOrderOption = 0x420010,
    BlockCipherMode = 0x420011,
    CancellationResult = 0x420012,
    Certificate = 0x420013,
    #[deprecated = "deprecated as of kmip 1.1"]
    CertificateIdentifier = 0x420014,
    #[deprecated = "deprecated as of kmip 1.1"]
    CertificateIssuer = 0x420015,
    #[deprecated = "deprecated as of kmip 1.1"]
    CertificateIssuerAlternativeName = 0x420016,
    #[deprecated = "deprecated as of kmip 1.1"]
    CertificateIssuerDistinguishedName = 0x420017,
    CertificateRequest = 0x420018,
    CertificateRequestType = 0x420019,
    #[deprecated = "deprecated as of kmip 1.1"]
    CertificateSubject = 0x42001A,
    #[deprecated = "deprecated as of kmip 1.1"]
    CertificateSubjectAlternativeName = 0x42001B,
    #[deprecated = "deprecated as of kmip 1.1"]
    CertificateSubjectDistinguishedName = 0x42001C,
    CertificateType = 0x42001D,
    CertificateValue = 0x42001E,
    CommonTemplateAttribute = 0x42001F,
    CompromiseDate = 0x420020,
    CompromiseOccurrenceDate = 0x420021,
    ContactInformation = 0x420022,
    Credential = 0x420023,
    CredentialType = 0x420024,
    CredentialValue = 0x420025,
    CriticalityIndicator = 0x420026,
    CRTCoefficient = 0x420027,
    CryptographicAlgorithm = 0x420028,
    CryptographicDomainParameters = 0x420029,
    CryptographicLength = 0x42002A,
    CryptographicParameters = 0x42002B,
    CryptographicUsageMask = 0x42002C,
    CustomAttribute = 0x42002D,
    D = 0x42002E,
    DeactivationDate = 0x42002F,
    DerivationData = 0x420030,
    DerivationMethod = 0x420031,
    DerivationParameters = 0x420032,
    DestroyDate = 0x420033,
    Digest = 0x420034,
    DigestValue = 0x420035,
    EncryptionKeyInformation = 0x420036,
    G = 0x420037,
    HashingAlgorithm = 0x420038,
    InitialDate = 0x420039,
    InitializationVector = 0x42003A,
    #[deprecated = "deprecated as of kmip 1.1"]
    Issuer = 0x42003B,
    IterationCount = 0x42003C,
    IVCounterNonce = 0x42003D,
    J = 0x42003E,
    Key = 0x42003F,
    KeyBlock = 0x420040,
    KeyCompressionType = 0x420041,
    KeyFormatType = 0x420042,
    KeyMaterial = 0x420043,
    KeyPartIdentifier = 0x420044,
    KeyValue = 0x420045,
    KeyWrappingData = 0x420046,
    KeyWrappingSpecification = 0x420047,
    LastChangeDate = 0x420048,
    LeaseTime = 0x420049,
    Link = 0x42004A,
    LinkType = 0x42004B,
    LinkedObjectIdentifier = 0x42004C,
    MACSignature = 0x42004D,
    MACSignatureKeyInformation = 0x42004E,
    MaximumItems = 0x42004F,
    MaximumResponseSize = 0x420050,
    MessageExtension = 0x420051,
    Modulus = 0x420052,
    Name = 0x420053,
    NameType = 0x420054,
    NameValue = 0x420055,
    ObjectGroup = 0x420056,
    ObjectType = 0x420057,
    Offset = 0x420058,
    OpaqueDataType = 0x420059,
    OpaqueDataValue = 0x42005A,
    OpaqueObject = 0x42005B,
    Operation = 0x42005C,
    #[deprecated = "deprecated as of kmip 1.3"]
    OperationPolicyName = 0x42005D,
    P = 0x42005E,
    PaddingMethod = 0x42005F,
    PrimeExponentP = 0x420060,
    PrimeExponentQ = 0x420061,
    PrimeFieldSize = 0x420062,
    PrivateExponent = 0x420063,
    PrivateKey = 0x420064,
    PrivateKeyTemplateAttribute = 0x420065,
    PrivateKeyUniqueIdentifier = 0x420066,
    ProcessStartDate = 0x420067,
    ProtectStopDate = 0x420068,
    ProtocolVersion = 0x420069,
    ProtocolVersionMajor = 0x42006A,
    ProtocolVersionMinor = 0x42006B,
    PublicExponent = 0x42006C,
    PublicKey = 0x42006D,
    PublicKeyTemplateAttribute = 0x42006E,
    PublicKeyUniqueIdentifier = 0x42006F,
    PutFunction = 0x420070,
    Q = 0x420071,
    QString = 0x420072,
    Qlength = 0x420073,
    QueryFunction = 0x420074,
    RecommendedCurve = 0x420075,
    ReplacedUniqueIdentifier = 0x420076,
    RequestHeader = 0x420077,
    RequestMessage = 0x420078,
    RequestPayload = 0x420079,
    ResponseHeader = 0x42007A,
    ResponseMessage = 0x42007B,
    ResponsePayload = 0x42007C,
    ResultMessage = 0x42007D,
    ResultReason = 0x42007E,
    ResultStatus = 0x42007F,
    RevocationMessage = 0x420080,
    RevocationReason = 0x420081,
    RevocationReasonCode = 0x420082,
    KeyRoleType = 0x420083,
    Salt = 0x420084,
    SecretData = 0x420085,
    SecretDataType = 0x420086,
    #[deprecated = "deprecated as of kmip 1.1"]
    SerialNumber = 0x420087,
    ServerInformation = 0x420088,
    SplitKey = 0x420089,
    SplitKeyMethod = 0x42008A,
    SplitKeyParts = 0x42008B,
    SplitKeyThreshold = 0x42008C,
    State = 0x42008D,
    StorageStatusMask = 0x42008E,
    SymmetricKey = 0x42008F,
    Template = 0x420090,
    TemplateAttribute = 0x420091,
    TimeStamp = 0x420092,
    UniqueBatchItemID = 0x420093,
    UniqueIdentifier = 0x420094,
    UsageLimits = 0x420095,
    UsageLimitsCount = 0x420096,
    UsageLimitsTotal = 0x420097,
    UsageLimitsUnit = 0x420098,
    Username = 0x420099,
    ValidityDate = 0x42009A,
    ValidityIndicator = 0x42009B,
    VendorExtension = 0x42009C,
    VendorIdentification = 0x42009D,
    WrappingMethod = 0x42009E,
    X = 0x42009F,
    Y = 0x4200A0,
    Password = 0x4200A1,

    // KMIP 1.1
    DeviceIdentifier = 0x4200A2,
    EncodingOption = 0x4200A3,
    ExtensionInformation = 0x4200A4,
    ExtensionName = 0x4200A5,
    ExtensionTag = 0x4200A6,
    ExtensionType = 0x4200A7,
    Fresh = 0x4200A8,
    MachineIdentifier = 0x4200A9,
    MediaIdentifier = 0x4200AA,
    NetworkIdentifier = 0x4200AB,
    ObjectGroupMember = 0x4200AC,
    CertificateLength = 0x4200AD,
    DigitalSignatureAlgorithm = 0x4200AE,
    CertificateSerialNumber = 0x4200AF,
    DeviceSerialNumber = 0x4200B0,
    IssuerAlternativeName = 0x4200B1,
    IssuerDistinguishedName = 0x4200B2,
    SubjectAlternativeName = 0x4200B3,
    SubjectDistinguishedName = 0x4200B4,
    #[strum(serialize = "X_509CertificateIdentifier")]
    X509CertificateIdentifier = 0x4200B5,
    #[strum(serialize = "X_509CertificateIssuer")]
    X509CertificateIssuer = 0x4200B6,
    #[strum(serialize = "X_509CertificateSubject")]
    X509CertificateSubject = 0x4200B7,

    // KMIP 1.2
    KeyValueLocationValue = 0x4200B9,
    KeyValueLocationType = 0x4200BA,
    KeyValuePresent = 0x4200BB,
    OriginalCreationDate = 0x4200BC,
    PGPKey = 0x4200BD,
    PGPKeyVersion = 0x4200BE,
    AlternativeName = 0x4200BF,
    AlternativeNameValue = 0x4200C0,
    AlternativeNameType = 0x4200C1,
    Data = 0x4200C2,
    SignatureData = 0x4200C3,
    DataLength = 0x4200C4,
    RandomIV = 0x4200C5,
    MACData = 0x4200C6,
    AttestationType = 0x4200C7,
    Nonce = 0x4200C8,
    NonceID = 0x4200C9,
    NonceValue = 0x4200CA,
    AttestationMeasurement = 0x4200CB,
    AttestationAssertion = 0x4200CC,
    IVLength = 0x4200CD,
    TagLength = 0x4200CE,
    FixedFieldLength = 0x4200CF,
    CounterLength = 0x4200D0,
    InitialCounterValue = 0x4200D1,
    InvocationFieldLength = 0x4200D2,
    AttestationCapableIndicator = 0x4200D3,
    KeyValueLocation = 0x4200B8,

    // KMIP 1.3
    OffsetItems = 0x4200D4,
    LocatedItems = 0x4200D5,
    CorrelationValue = 0x4200D6,
    InitIndicator = 0x4200D7,
    FinalIndicator = 0x4200D8,
    RNGParameters = 0x4200D9,
    RNGAlgorithm = 0x4200DA,
    DRBGAlgorithm = 0x4200DB,
    FIPS186Variation = 0x4200DC,
    PredictionResistance = 0x4200DD,
    RandomNumberGenerator = 0x4200DE,
    ValidationInformation = 0x4200DF,
    ValidationAuthorityType = 0x4200E0,
    ValidationAuthorityCountry = 0x4200E1,
    ValidationAuthorityURI = 0x4200E2,
    ValidationVersionMajor = 0x4200E3,
    ValidationVersionMinor = 0x4200E4,
    ValidationType = 0x4200E5,
    ValidationLevel = 0x4200E6,
    ValidationCertificateIdentifier = 0x4200E7,
    ValidationCertificateURI = 0x4200E8,
    ValidationVendorURI = 0x4200E9,
    ValidationProfile = 0x4200EA,
    ProfileInformation = 0x4200EB,
    ProfileName = 0x4200EC,
    ServerURI = 0x4200ED,
    ServerPort = 0x4200EE,
    StreamingCapability = 0x4200EF,
    AsynchronousCapability = 0x4200F0,
    AttestationCapability = 0x4200F1,
    UnwrapMode = 0x4200F2,
    DestroyAction = 0x4200F3,
    ShreddingAlgorithm = 0x4200F4,
    RNGMode = 0x4200F5,
    ClientRegistrationMethod = 0x4200F6,
    CapabilityInformation = 0x4200F7,

    // KMIP 1.4
    KeyWrapType = 0x4200F8,
    BatchUndoCapability = 0x4200F9,
    BatchContinueCapability = 0x4200FA,
    #[strum(serialize = "PKCS_12FriendlyName")]
    PKCS12FriendlyName = 0x4200FB,
    Description = 0x4200FC,
    Comment = 0x4200FD,
    AuthenticatedEncryptionAdditionalData = 0x4200FE,
    AuthenticatedEncryptionTag = 0x4200FF,
    SaltLength = 0x420100,
    MaskGenerator = 0x420101,
    MaskGeneratorHashingAlgorithm = 0x420102,
    PSource = 0x420103,
    TrailerField = 0x420104,
    ClientCorrelationValue = 0x420105,
    ServerCorrelationValue = 0x420106,
    DigestedData = 0x420107,
    CertificateSubjectCN = 0x420108,
    CertificateSubjectO = 0x420109,
    CertificateSubjectOU = 0x42010A,
    CertificateSubjectEmail = 0x42010B,
    CertificateSubjectC = 0x42010C,
    CertificateSubjectST = 0x42010D,
    CertificateSubjectL = 0x42010E,
    CertificateSubjectUID = 0x42010F,
    CertificateSubjectSerialNumber = 0x420110,
    CertificateSubjectTitle = 0x420111,
    CertificateSubjectDC = 0x420112,
    CertificateSubjectDNQualifier = 0x420113,
    CertificateIssuerCN = 0x420114,
    CertificateIssuerO = 0x420115,
    CertificateIssuerOU = 0x420116,
    CertificateIssuerEmail = 0x420117,
    CertificateIssuerC = 0x420118,
    CertificateIssuerST = 0x420119,
    CertificateIssuerL = 0x42011A,
    CertificateIssuerUID = 0x42011B,
    CertificateIssuerSerialNumber = 0x42011C,
    CertificateIssuerTitle = 0x42011D,
    CertificateIssuerDC = 0x42011E,
    CertificateIssuerDNQualifier = 0x42011F,
    Sensitive = 0x420120,
    AlwaysSensitive = 0x420121,
    Extractable = 0x420122,
    NeverExtractable = 0x420123,
    ReplaceExisting = 0x420124,
    // Unknown(RawTag) = !0,
}

impl Tags {
    fn discriminant(&self) -> u32 {
        // unsafe { *<*const _>::from(self).cast::<_>() }
        *self as _
    }
}

impl TryFrom<RawTagRef<'_>> for Tags {
    type Error = Error;
    fn try_from(value: RawTagRef) -> Result<Self, Self::Error> {
        match value {
            RawTagRef::Num(n) | RawTagRef::NumStr(n, ..) => {
                Self::from_repr(n).ok_or(Error::InvalidTag(value.to_owned()))
            }
            RawTagRef::Str(s) => {
                FromStr::from_str(s).map_err(|_| Error::InvalidTag(value.to_owned()))
            }
        }
    }
}

impl TryFrom<RawTag> for Tags {
    type Error = Error;
    fn try_from(value: RawTag) -> Result<Self, Self::Error> {
        Self::try_from(value.get_ref())
    }
}

impl Tag for Tags {
    fn numeric(&self) -> Option<u32> {
        // if let Self::Unknown(tag) = self {
        //     return tag.numeric();
        // }
        Some(self.discriminant())
    }

    fn name(&self) -> Option<&str> {
        // if let Self::Unknown(tag) = self {
        //     return tag.name();
        // }
        Some(self.into())
    }
}
