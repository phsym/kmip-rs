#![allow(deprecated)]
use super::Tags;
use ttlv::{Decodable, Encodable, Enum, RawTag, Tag};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::Operation)]
#[repr(u32)]
pub enum Operations {
    Create = 0x00000001,
    CreateKeyPair = 0x00000002,
    Register = 0x00000003,
    ReKey = 0x00000004,
    // DeriveKey = 0x00000005,
    // Certify = 0x00000006,
    // ReCertify = 0x00000007,
    Locate = 0x00000008,
    // Check = 0x00000009
    Get = 0x0000000A,
    GetAttributes = 0x0000000B,
    GetAttributeList = 0x0000000C,
    AddAttribute = 0x0000000D,
    ModifyAttribute = 0x0000000E,
    DeleteAttribute = 0x0000000F,
    ObtainLease = 0x00000010,
    GetUsageAllocation = 0x00000011,
    Activate = 0x00000012,
    Revoke = 0x00000013,
    Destroy = 0x00000014,
    Archive = 0x00000015,
    Recover = 0x00000016,
    // Validate = 0x00000017,
    Query = 0x00000018,
    // Cancel = 0x00000019,
    // Poll = 0x0000001A,
    // Notify = 0x0000001B,
    // Put = 0x0000001C,

    //KMIP 1.1
    ReKeyKeyPair = 0x0000001D,
    DiscoverVersions = 0x0000001E,

    // // KMIP 1.2
    Encrypt = 0x0000001F,
    Decrypt = 0x00000020,
    Sign = 0x00000021,
    SignatureVerify = 0x00000022,
    // MAC              = 0x00000023,
    // MACVerify        = 0x00000024,
    // RNGRetrieve      = 0x00000025,
    // RNGSeed          = 0x00000026,
    // Hash             = 0x00000027,
    // CreateSplitKey   = 0x00000028,
    // JoinSplitKey     = 0x00000029,

    // // KMIP 1.4
    Import = 0x0000002A,
    Export = 0x0000002B,
    #[ttlv(default)]
    Unknown(RawTag),
    // Extensions 8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::ResultStatus)]
pub enum ResultStatus {
    Success = 0,
    OperationFailed = 1,
    OperationPending = 2,
    OperationUndone = 3,
}

/// See <https://docs.oasis-open.org/kmip/spec/v1.4/errata01/os/kmip-spec-v1.4-errata01-os-redlined.html#_Toc490660949>
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::ResultReason)]
pub enum ResultReason {
    ItemNotFound = 1,
    ResponseTooLarge = 2,
    AuthenticationNotSuccessful = 0x00000003,
    InvalidMessage = 0x00000004,
    OperationNotSupported = 0x00000005,
    MissingData = 0x00000006,
    InvalidField = 0x00000007,
    FeatureNotSupported = 0x00000008,
    OperationCanceledByRequester = 0x00000009,
    CryptographicFailure = 0x0000000A,
    IllegalOperation = 0x0000000B,
    PermissionDenied = 0x0000000C,
    ObjectArchived = 0x0000000D,
    IndexOutofBounds = 0x0000000E,
    ApplicationNamespaceNotSupported = 0x0000000F,
    KeyFormatTypeNotSupported = 0x00000010,
    KeyCompressionTypeNotSupported = 0x00000011,

    // KMIP 1.1
    EncodingOptionError = 0x00000012,
    // KMIP 1.2
    KeyValueNotPresent = 0x00000013,
    AttestationRequired = 0x00000014,
    AttestationFailed = 0x00000015,
    // KMIP 1.4
    Sensitive = 0x00000016,
    NotExtractable = 0x00000017,
    ObjectAlreadyExists = 0x00000018,

    GeneralFailure = 0x00000100,
    // Extensions 8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::CredentialType)]
pub enum CredentialType {
    UsernameAndPassword = 0x00000001,
    // KMIP 1.1
    Device = 0x00000002,
    //KMIP 1.2
    Attestation = 0x00000003,
    // Extension(u32)
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::BatchErrorContinuationOption)]
pub enum BatchErrorContinuationOption {
    Continue = 1,
    Stop = 2,
    Undo = 3,
    // Extension(u32)
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::ObjectType)]
pub enum ObjectType {
    Certificate = 0x00000001,
    SymmetricKey = 0x00000002,
    PublicKey = 0x00000003,
    PrivateKey = 0x00000004,
    SplitKey = 0x00000005,
    #[deprecated = "deprecated as of kmip 1.3"]
    Template = 0x00000006,
    SecretData = 0x00000007,
    OpaqueObject = 0x00000008,

    //KMIP 1.2
    PGPKey = 0x00000009,
    // Extension(u32)
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::NameType)]
pub enum NameType {
    UninterpretedTextString = 1,
    URI = 2,
    // Extension(u32)
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::CryptographicAlgorithm)]
pub enum CryptographicAlgorithm {
    DES = 0x00000001,
    DES3 = 0x00000002,
    AES = 0x00000003,
    RSA = 0x00000004,
    DSA = 0x00000005,
    ECDSA = 0x00000006,
    #[ttlv(rename = "HMAC_SHA1")]
    HmacSha1 = 0x00000007,
    #[ttlv(rename = "HMAC_SHA224")]
    HmacSha224 = 0x00000008,
    #[ttlv(rename = "HMAC_SHA256")]
    HmacSha256 = 0x00000009,
    #[ttlv(rename = "HMAC_SHA384")]
    HmacSha384 = 0x0000000A,
    #[ttlv(rename = "HMAC_SHA512")]
    HmacSha512 = 0x0000000B,
    #[ttlv(rename = "HMAC_MD5")]
    HmacMd5 = 0x0000000C,
    DH = 0x0000000D,
    ECDH = 0x0000000E,
    ECMQV = 0x0000000F,
    Blowfish = 0x00000010,
    Camellia = 0x00000011,
    CAST5 = 0x00000012,
    IDEA = 0x00000013,
    MARS = 0x00000014,
    RC2 = 0x00000015,
    RC4 = 0x00000016,
    RC5 = 0x00000017,
    SKIPJACK = 0x00000018,
    Twofish = 0x00000019,

    //KMIP 1.2
    EC = 0x0000001A,

    // KMIP 1.3
    OneTimePad = 0x0000001B,

    // KMIP 1.4
    ChaCha20 = 0x0000001C,
    Poly1305 = 0x0000001D,
    ChaCha20Poly1305 = 0x0000001E,
    SHA3_224 = 0x0000001F,
    SHA3_256 = 0x00000020,
    SHA3_384 = 0x00000021,
    SHA3_512 = 0x00000022,
    #[ttlv(rename = "HMAC_SHA3_224")]
    HmacSha3_224 = 0x00000023,
    #[ttlv(rename = "HMAC_SHA3_256")]
    HmacSha3_256 = 0x00000024,
    #[ttlv(rename = "HMAC_SHA3_384")]
    HmacSha3_384 = 0x00000025,
    #[ttlv(rename = "HMAC_SHA3_512")]
    HmacSha3_512 = 0x00000026,
    #[ttlv(rename = "SHAKE_128")]
    Shake128 = 0x00000027,
    #[ttlv(rename = "SHAKE_256")]
    Shake256 = 0x00000028,
    // Extensions 8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::BlockCipherMode)]
pub enum BlockCipherMode {
    CBC = 0x00000001,
    ECB = 0x00000002,
    PCBC = 0x00000003,
    CFB = 0x00000004,
    OFB = 0x00000005,
    CTR = 0x00000006,
    CMAC = 0x00000007,
    CCM = 0x00000008,
    GCM = 0x00000009,
    #[ttlv(rename = "CBC_MAC")]
    CBCMAC = 0x0000000A,
    XTS = 0x0000000B,
    AESKeyWrapPadding = 0x0000000C,
    NISTKeyWrap = 0x0000000D,
    X9_102AESKW = 0x0000000E,
    X9_102TDKW = 0x0000000F,
    X9_102AKW1 = 0x00000010,
    X9_102AKW2 = 0x00000011,

    // KMIP 1.4
    AEAD = 0x00000012,
    // Extensions =0x8XXXXXXX,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::PaddingMethod)]
pub enum PaddingMethod {
    None = 0x00000001,
    OAEP = 0x00000002,
    PKCS5 = 0x00000003,
    SSL3 = 0x00000004,
    Zeros = 0x00000005,
    ANSIX9_23 = 0x00000006,
    ISO10126 = 0x00000007,
    PKCS1V1_5 = 0x00000008,
    X9_31 = 0x00000009,
    PSS = 0x0000000A,
    // Extensions =0x8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::HashingAlgorithm)]
pub enum HashingAlgorithm {
    MD2 = 0x00000001,
    MD4 = 0x00000002,
    MD5 = 0x00000003,
    #[ttlv(rename = "SHA_1")]
    SHA1 = 0x00000004,
    #[ttlv(rename = "SHA_224")]
    SHA224 = 0x00000005,
    #[ttlv(rename = "SHA_256")]
    SHA256 = 0x00000006,
    #[ttlv(rename = "SHA_384")]
    SHA384 = 0x00000007,
    #[ttlv(rename = "SHA_512")]
    SHA512 = 0x00000008,
    #[ttlv(rename = "RIPEMD_160")]
    RIPEMD160 = 0x00000009,
    Tiger = 0x0000000A,
    Whirlpool = 0x0000000B,

    // KMIP 1.2
    #[ttlv(rename = "SHA_512_224")]
    SHA512_224 = 0x0000000C,
    #[ttlv(rename = "SHA_512_256")]
    SHA512_256 = 0x0000000D,

    // KMIP 1.4
    #[ttlv(rename = "SHA_3_224")]
    SHA3_224 = 0x0000000E,
    #[ttlv(rename = "SHA_3_256")]
    SHA3_256 = 0x0000000F,
    #[ttlv(rename = "SHA_3_384")]
    SHA3_384 = 0x00000010,
    #[ttlv(rename = "SHA_3_512")]
    SHA3_512 = 0x00000011,
    // Extensions =0x8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::KeyRoleType)]
pub enum KeyRoleType {
    BDK = 0x00000001,
    CVK = 0x00000002,
    DEK = 0x00000003,
    MKAC = 0x00000004,
    MKSMC = 0x00000005,
    MKSMI = 0x00000006,
    MKDAC = 0x00000007,
    MKDN = 0x00000008,
    MKCP = 0x00000009,
    MKOTH = 0x0000000A,
    KEK = 0x0000000B,
    MAC16609 = 0x0000000C,
    MAC97971 = 0x0000000D,
    MAC97972 = 0x0000000E,
    MAC97973 = 0x0000000F,
    MAC97974 = 0x00000010,
    MAC97975 = 0x00000011,
    ZPK = 0x00000012,
    PVKIBM = 0x00000013,
    PVKPVV = 0x00000014,
    PVKOTH = 0x00000015,

    // KMIP 1.4
    DUKPT = 0x00000016,
    IV = 0x00000017,
    TRKBK = 0x00000018,
    // Extensions 8XXXXXXX,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::RecommendedCurve)]
pub enum RecommendedCurve {
    #[ttlv(rename = "P_192")]
    P192 = 0x00000001,
    #[ttlv(rename = "K_163")]
    K163 = 0x00000002,
    #[ttlv(rename = "B_163")]
    B163 = 0x00000003,
    #[ttlv(rename = "P_224")]
    P224 = 0x00000004,
    #[ttlv(rename = "K_233")]
    K233 = 0x00000005,
    #[ttlv(rename = "B_233")]
    B233 = 0x00000006,
    #[ttlv(rename = "P_256")]
    P256 = 0x00000007,
    #[ttlv(rename = "K_283")]
    K283 = 0x00000008,
    #[ttlv(rename = "B_283")]
    B283 = 0x00000009,
    #[ttlv(rename = "P_384")]
    P384 = 0x0000000A,
    #[ttlv(rename = "K_409")]
    K409 = 0x0000000B,
    #[ttlv(rename = "B_409")]
    B409 = 0x0000000C,
    #[ttlv(rename = "P_521")]
    P521 = 0x0000000D,
    #[ttlv(rename = "K_571")]
    K571 = 0x0000000E,
    #[ttlv(rename = "B_571")]
    B571 = 0x0000000F,

    //KMIP 1.2
    SECP112R1 = 0x00000010,
    SECP112R2 = 0x00000011,
    SECP128R1 = 0x00000012,
    SECP128R2 = 0x00000013,
    SECP160K1 = 0x00000014,
    SECP160R1 = 0x00000015,
    SECP160R2 = 0x00000016,
    SECP192K1 = 0x00000017,
    SECP224K1 = 0x00000018,
    SECP256K1 = 0x00000019,
    SECT113R1 = 0x0000001A,
    SECT113R2 = 0x0000001B,
    SECT131R1 = 0x0000001C,
    SECT131R2 = 0x0000001D,
    SECT163R1 = 0x0000001E,
    SECT193R1 = 0x0000001F,
    SECT193R2 = 0x00000020,
    SECT239K1 = 0x00000021,
    ANSIX9P192V2 = 0x00000022,
    ANSIX9P192V3 = 0x00000023,
    ANSIX9P239V1 = 0x00000024,
    ANSIX9P239V2 = 0x00000025,
    ANSIX9P239V3 = 0x00000026,
    ANSIX9C2PNB163V1 = 0x00000027,
    ANSIX9C2PNB163V2 = 0x00000028,
    ANSIX9C2PNB163V3 = 0x00000029,
    ANSIX9C2PNB176V1 = 0x0000002A,
    ANSIX9C2TNB191V1 = 0x0000002B,
    ANSIX9C2TNB191V2 = 0x0000002C,
    ANSIX9C2TNB191V3 = 0x0000002D,
    ANSIX9C2PNB208W1 = 0x0000002E,
    ANSIX9C2TNB239V1 = 0x0000002F,
    ANSIX9C2TNB239V2 = 0x00000030,
    ANSIX9C2TNB239V3 = 0x00000031,
    ANSIX9C2PNB272W1 = 0x00000032,
    ANSIX9C2PNB304W1 = 0x00000033,
    ANSIX9C2TNB359V1 = 0x00000034,
    ANSIX9C2PNB368W1 = 0x00000035,
    ANSIX9C2TNB431R1 = 0x00000036,
    BRAINPOOLP160R1 = 0x00000037,
    BRAINPOOLP160T1 = 0x00000038,
    BRAINPOOLP192R1 = 0x00000039,
    BRAINPOOLP192T1 = 0x0000003A,
    BRAINPOOLP224R1 = 0x0000003B,
    BRAINPOOLP224T1 = 0x0000003C,
    BRAINPOOLP256R1 = 0x0000003D,
    BRAINPOOLP256T1 = 0x0000003E,
    BRAINPOOLP320R1 = 0x0000003F,
    BRAINPOOLP320T1 = 0x00000040,
    BRAINPOOLP384R1 = 0x00000041,
    BRAINPOOLP384T1 = 0x00000042,
    BRAINPOOLP512R1 = 0x00000043,
    BRAINPOOLP512T1 = 0x00000044,
    // Extensions 8XXXXXXX
}

impl RecommendedCurve {
    pub fn bitlen(&self) -> i32 {
        use RecommendedCurve::*;
        match self {
            P192 | SECP192K1 | ANSIX9P192V2 | ANSIX9P192V3 | BRAINPOOLP192R1 | BRAINPOOLP192T1 => {
                192
            }
            K163 | B163 | SECT163R1 | ANSIX9C2PNB163V1 | ANSIX9C2PNB163V2 | ANSIX9C2PNB163V3 => 163,
            P256 | SECP256K1 | BRAINPOOLP256R1 | BRAINPOOLP256T1 => 256,
            P224 | SECP224K1 => 224,
            K233 | B233 => 233,
            K283 | B283 => 283,
            P384 | BRAINPOOLP384R1 | BRAINPOOLP384T1 => 384,
            K409 | B409 => 409,
            P521 => 521,
            K571 | B571 => 571,
            SECP112R1 | SECP112R2 => 112,
            SECP128R1 | SECP128R2 => 128,
            SECP160K1 | SECP160R1 | SECP160R2 | BRAINPOOLP160R1 | BRAINPOOLP160T1 => 160,
            SECT113R1 | SECT113R2 => 113,
            SECT131R1 | SECT131R2 => 131,
            SECT193R1 | SECT193R2 => 193,
            SECT239K1 | ANSIX9P239V1 | ANSIX9P239V2 | ANSIX9P239V3 | ANSIX9C2TNB239V1
            | ANSIX9C2TNB239V2 | ANSIX9C2TNB239V3 => 239,
            ANSIX9C2PNB176V1 => 176,
            ANSIX9C2TNB191V1 | ANSIX9C2TNB191V2 | ANSIX9C2TNB191V3 => 191,
            ANSIX9C2PNB208W1 => 208,
            ANSIX9C2PNB272W1 => 272,
            ANSIX9C2PNB304W1 => 304,
            ANSIX9C2TNB359V1 => 359,
            ANSIX9C2PNB368W1 => 368,
            ANSIX9C2TNB431R1 => 431,
            BRAINPOOLP224R1 | BRAINPOOLP224T1 => 224,
            BRAINPOOLP320R1 | BRAINPOOLP320T1 => 320,
            BRAINPOOLP512R1 | BRAINPOOLP512T1 => 512,
        }
    }
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::LinkType)]
pub enum LinkType {
    CertificateLink = 0x00000101,
    PublicKeyLink = 0x00000102,
    PrivateKeyLink = 0x00000103,
    DerivationBaseObjectLink = 0x00000104,
    DerivedKeyLink = 0x00000105,
    ReplacementObjectLink = 0x00000106,
    ReplacedObjectLink = 0x00000107,

    // KMIP 1.2
    ParentLink = 0x00000108,
    ChildLink = 0x00000109,
    PreviousLink = 0x0000010A,
    NextLink = 0x0000010B,

    // KMPI 1.4
    #[ttlv(rename = "PKCS_12CertificateLink")]
    PKCS12CertificateLink = 0x0000010C,
    #[ttlv(rename = "PKCS_12PasswordLink")]
    PKCS12PasswordLink = 0x0000010D,

    //FIXME: This is defined in KMIP 2.0+ only
    WrappingKeyLink = 0x0000010E,
    // Extensions 8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::State)]
pub enum State {
    PreActive = 0x00000001,
    Active = 0x00000002,
    Deactivated = 0x00000003,
    Compromised = 0x00000004,
    Destroyed = 0x00000005,
    DestroyedCompromised = 0x00000006,
    // Extensions 8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::KeyFormatType)]
pub enum KeyFormatType {
    Raw = 0x00000001,
    Opaque = 0x00000002,
    #[ttlv(rename = "PKCS_1")]
    PKCS1 = 0x00000003,
    #[ttlv(rename = "PKCS_8")]
    PKCS8 = 0x00000004,
    #[ttlv(rename = "X_509")]
    X509 = 0x00000005,
    ECPrivateKey = 0x00000006,
    TransparentSymmetricKey = 0x00000007,
    TransparentDSAPrivateKey = 0x00000008,
    TransparentDSAPublicKey = 0x00000009,
    TransparentRSAPrivateKey = 0x0000000A,
    TransparentRSAPublicKey = 0x0000000B,
    TransparentDHPrivateKey = 0x0000000C,
    TransparentDHPublicKey = 0x0000000D,
    #[deprecated = "deprecated as of kmip 1.3"]
    TransparentECDSAPrivateKey = 0x0000000E,
    #[deprecated = "deprecated as of kmip 1.3"]
    TransparentECDSAPublicKey = 0x0000000F,
    #[deprecated = "deprecated as of kmip 1.3"]
    TransparentECDHPrivateKey = 0x00000010,
    #[deprecated = "deprecated as of kmip 1.3"]
    TransparentECDHPublicKey = 0x00000011,
    #[deprecated = "deprecated as of kmip 1.3"]
    TransparentECMQVPrivateKey = 0x00000012,
    #[deprecated = "deprecated as of kmip 1.3"]
    TransparentECMQVPublicKey = 0x00000013,

    // KMIP 1.3
    TransparentECPrivateKey = 0x00000014,
    TransparentECPublicKey = 0x00000015,

    // KMIP 1.4
    #[ttlv(rename = "KeyFormatPKCS_12")]
    KeyFormatPKCS12 = 0x00000016,
    // Extensions 8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::KeyCompressionType)]
pub enum KeyCompressionType {
    ECPublicKeyTypeUncompressed = 0x00000001,
    ECPublicKeyTypeX9_62CompressedPrime = 0x00000002,
    ECPublicKeyTypeX9_62CompressedChar2 = 0x00000003,
    ECPublicKeyTypeX9_62Hybrid = 0x00000004,
    // Extensions 8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::WrappingMethod)]
pub enum WrappingMethod {
    Encrypt = 0x00000001,
    MACSign = 0x00000002,
    EncryptThenMACSign = 0x00000003,
    MACSignThenEncrypt = 0x00000004,
    #[ttlv(rename = "TR_31")]
    TR31 = 0x00000005,
    // Extensions 8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::SecretDataType)]
pub enum SecretDataType {
    Password = 0x00000001,
    Seed = 0x00000002,
    // Extensions 0x8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::RevocationReasonCode)]
pub enum RevocationReasonCode {
    Unspecified = 0x00000001,
    KeyCompromise = 0x00000002,
    CACompromise = 0x00000003,
    AffiliationChanged = 0x00000004,
    Superseded = 0x00000005,
    CessationOfOperation = 0x00000006,
    PrivilegeWithdrawn = 0x00000007,
    // Extensions 8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::QueryFunction)]
pub enum QueryFunction {
    QueryOperations = 0x00000001,
    QueryObjects = 0x00000002,
    QueryServerInformation = 0x00000003,
    QueryApplicationNamespaces = 0x00000004,
    // KMIP 1.1
    QueryExtensionList = 0x0000005,
    QueryExtensionMap = 0x00000006,
    //KMIP 1.2
    QueryAttestationTypes = 0x00000007,
    // KMIP 1.3
    QueryRNGs = 0x00000008,
    QueryValidations = 0x00000009,
    QueryProfiles = 0x0000000A,
    QueryCapabilities = 0x0000000B,
    QueryClientRegistrationMethods = 0x0000000C,
    // Extensions 8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::CertificateType)]
pub enum CertificateType {
    #[ttlv(rename = "X_509")]
    X509 = 0x00000001,
    #[deprecated = "deprecated as of kmip 1.2"]
    PGP = 0x00000002,
    // Extensions 8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::UsageLimitsUnit)]
pub enum UsageLimitsUnit {
    Byte = 0x00000001,
    Object = 0x00000002,
    // Extensions 8XXXXXXX
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::OpaqueObject)]
pub enum OpaqueDataType {
    #[ttlv(default)]
    Extension(RawTag),
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::CancellationResult)]
pub enum CancellationResult {
    Canceled = 0x00000001,
    UnableToCancel = 0x00000002,
    Completed = 0x00000003,
    Failed = 0x00000004,
    Unavailable = 0x00000005,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::PutFunction)]
pub enum PutFunction {
    New = 0x00000001,
    Replace = 0x00000002,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::CertificateRequestType)]
pub enum CertificateRequestType {
    CRMF = 0x00000001,
    #[ttlv(rename = "PKCS_10")]
    PKCS10 = 0x00000002,
    PEM = 0x00000003,
    PGP = 0x00000004,
}

// kmip 1.1

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::SplitKeyMethod)]
pub enum SplitKeyMethod {
    XOR = 0x00000001,
    PolynomialSharingGF216 = 0x00000002,
    PolynomialSharingPrimeField = 0x00000003,
    //KMIP 1.2
    PolynomialSharingGF28 = 0x00000004,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::ObjectGroupMember)]
pub enum ObjectGroupMember {
    GroupMemberFresh = 0x00000001,
    GroupMemberDefault = 0x00000002,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::EncodingOption)]
pub enum EncodingOption {
    NoEncoding = 0x00000001,
    TTLVEncoding = 0x00000002,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::DigitalSignatureAlgorithm)]
pub enum DigitalSignatureAlgorithm {
    #[ttlv(rename = "MD2WithRSAEncryption")]
    MD2WithRSAEncryption = 0x00000001,
    #[ttlv(rename = "MD5WithRSAEncryption")]
    MD5WithRSAEncryption = 0x00000002,
    #[ttlv(rename = "SHA_1WithRSAEncryption")]
    SHA1WithRSAEncryption = 0x00000003,
    #[ttlv(rename = "SHA_224WithRSAEncryption")]
    SHA224WithRSAEncryption = 0x00000004,
    #[ttlv(rename = "SHA_256WithRSAEncryption")]
    SHA256WithRSAEncryption = 0x00000005,
    #[ttlv(rename = "SHA_384WithRSAEncryption")]
    SHA384WithRSAEncryption = 0x00000006,
    #[ttlv(rename = "SHA_512WithRSAEncryption")]
    SHA512WithRSAEncryption = 0x00000007,
    #[ttlv(rename = "RSASSA_PSS")]
    RsaSsaPss = 0x00000008,
    #[ttlv(rename = "DSAWithSHA_1")]
    DSAWithSHA1 = 0x00000009,
    DSAWithSHA224 = 0x0000000A,
    DSAWithSHA256 = 0x0000000B,
    #[ttlv(rename = "ECDSAWithSHA_1")]
    ECDSAWithSHA1 = 0x0000000C,
    ECDSAWithSHA224 = 0x0000000D,
    ECDSAWithSHA256 = 0x0000000E,
    ECDSAWithSHA384 = 0x0000000F,
    ECDSAWithSHA512 = 0x00000010,

    // KMIP 1.4
    SHA3_256WithRSAEncryption = 0x00000011,
    SHA3_384WithRSAEncryption = 0x00000012,
    SHA3_512WithRSAEncryption = 0x00000013,
}

// KMIP 1.2

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::AttestationType)]
pub enum AttestationType {
    TPMQuote = 0x00000001,
    TCGIntegrityReport = 0x00000002,
    SAMLAssertion = 0x00000003,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::AlternativeNameType)]
pub enum AlternativeNameType {
    UninterpretedTextString = 0x00000001,
    URI = 0x00000002,
    ObjectSerialNumber = 0x00000003,
    EmailAddress = 0x00000004,
    DNSName = 0x00000005,
    #[ttlv(rename = "X_500DistinguishedName")]
    X500DistinguishedName = 0x00000006,
    IPAddress = 0x00000007,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::KeyValueLocationType)]
pub enum KeyValueLocationType {
    UninterpretedTextString = 0x00000001,
    URI = 0x00000002,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::ValidityIndicator)]
pub enum ValidityIndicator {
    Valid = 0x00000001,
    Invalid = 0x00000002,
    Unknown = 0x00000003,
}

// KMIP 1.3

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::RNGAlgorithm)]
pub enum RNGAlgorithm {
    Unspecified = 0x00000001,
    FIPS186_2 = 0x00000002,
    DRBG = 0x00000003,
    NRBG = 0x00000004,
    ANSIX9_31 = 0x00000005,
    ANSIX9_62 = 0x00000006,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::DRBGAlgorithm)]
pub enum DRBGAlgorithm {
    Unspecified = 0x00000001,
    #[ttlv(rename = "Dual_EC")]
    DualEC = 0x00000002,
    Hash = 0x00000003,
    HMAC = 0x00000004,
    CTR = 0x00000005,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::FIPS186Variation)]
pub enum FIPS186Variation {
    Unspecified = 0x00000001,
    GPXOriginal = 0x00000002,
    GPXChangeNotice = 0x00000003,
    XOriginal = 0x00000004,
    XChangeNotice = 0x00000005,
    KOriginal = 0x00000006,
    KChangeNotice = 0x00000007,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::ProfileName)]
pub enum ProfileName {
    BaselineServerBasicKMIPV1_2 = 0x00000001,
    BaselineServerTLSV1_2KMIPV1_2 = 0x00000002,
    BaselineClientBasicKMIPV1_2 = 0x00000003,
    BaselineClientTLSV1_2KMIPV1_2 = 0x00000004,
    CompleteServerBasicKMIPV1_2 = 0x00000005,
    CompleteServerTLSV1_2KMIPV1_2 = 0x00000006,
    TapeLibraryClientKMIPV1_0 = 0x00000007,
    TapeLibraryClientKMIPV1_1 = 0x00000008,
    TapeLibraryClientKMIPV1_2 = 0x00000009,
    TapeLibraryServerKMIPV1_0 = 0x0000000A,
    TapeLibraryServerKMIPV1_1 = 0x0000000B,
    TapeLibraryServerKMIPV1_2 = 0x0000000C,
    SymmetricKeyLifecycleClientKMIPV1_0 = 0x0000000D,
    SymmetricKeyLifecycleClientKMIPV1_1 = 0x0000000E,
    SymmetricKeyLifecycleClientKMIPV1_2 = 0x0000000F,
    SymmetricKeyLifecycleServerKMIPV1_0 = 0x00000010,
    SymmetricKeyLifecycleServerKMIPV1_1 = 0x00000011,
    SymmetricKeyLifecycleServerKMIPV1_2 = 0x00000012,
    AsymmetricKeyLifecycleClientKMIPV1_0 = 0x00000013,
    AsymmetricKeyLifecycleClientKMIPV1_1 = 0x00000014,
    AsymmetricKeyLifecycleClientKMIPV1_2 = 0x00000015,
    AsymmetricKeyLifecycleServerKMIPV1_0 = 0x00000016,
    AsymmetricKeyLifecycleServerKMIPV1_1 = 0x00000017,
    AsymmetricKeyLifecycleServerKMIPV1_2 = 0x00000018,
    BasicCryptographicClientKMIPV1_2 = 0x00000019,
    BasicCryptographicServerKMIPV1_2 = 0x0000001A,
    AdvancedCryptographicClientKMIPV1_2 = 0x0000001B,
    AdvancedCryptographicServerKMIPV1_2 = 0x0000001C,
    RNGCryptographicClientKMIPV1_2 = 0x0000001D,
    RNGCryptographicServerKMIPV1_2 = 0x0000001E,
    BasicSymmetricKeyFoundryClientKMIPV1_0 = 0x0000001F,
    IntermediateSymmetricKeyFoundryClientKMIPV1_0 = 0x00000020,
    AdvancedSymmetricKeyFoundryClientKMIPV1_0 = 0x00000021,
    BasicSymmetricKeyFoundryClientKMIPV1_1 = 0x00000022,
    IntermediateSymmetricKeyFoundryClientKMIPV1_1 = 0x00000023,
    AdvancedSymmetricKeyFoundryClientKMIPV1_1 = 0x00000024,
    BasicSymmetricKeyFoundryClientKMIPV1_2 = 0x00000025,
    IntermediateSymmetricKeyFoundryClientKMIPV1_2 = 0x00000026,
    AdvancedSymmetricKeyFoundryClientKMIPV1_2 = 0x00000027,
    SymmetricKeyFoundryServerKMIPV1_0 = 0x00000028,
    SymmetricKeyFoundryServerKMIPV1_1 = 0x00000029,
    SymmetricKeyFoundryServerKMIPV1_2 = 0x0000002A,
    OpaqueManagedObjectStoreClientKMIPV1_0 = 0x0000002B,
    OpaqueManagedObjectStoreClientKMIPV1_1 = 0x0000002C,
    OpaqueManagedObjectStoreClientKMIPV1_2 = 0x0000002D,
    OpaqueManagedObjectStoreServerKMIPV1_0 = 0x0000002E,
    OpaqueManagedObjectStoreServerKMIPV1_1 = 0x0000002F,
    OpaqueManagedObjectStoreServerKMIPV1_2 = 0x00000030,
    #[ttlv(rename = "SuiteBMinLOS_128ClientKMIPV1_0")]
    SuiteBMinLOS128ClientKMIPV1_0 = 0x00000031,
    #[ttlv(rename = "SuiteBMinLOS_128ClientKMIPV1_1")]
    SuiteBMinLOS128ClientKMIPV1_1 = 0x00000032,
    #[ttlv(rename = "SuiteBMinLOS_128ClientKMIPV1_2")]
    SuiteBMinLOS128ClientKMIPV1_2 = 0x00000033,
    #[ttlv(rename = "SuiteBMinLOS_128ServerKMIPV1_0")]
    SuiteBMinLOS128ServerKMIPV1_0 = 0x00000034,
    #[ttlv(rename = "SuiteBMinLOS_128ServerKMIPV1_1")]
    SuiteBMinLOS128ServerKMIPV1_1 = 0x00000035,
    #[ttlv(rename = "SuiteBMinLOS_128ServerKMIPV1_2")]
    SuiteBMinLOS128ServerKMIPV1_2 = 0x00000036,
    #[ttlv(rename = "SuiteBMinLOS_192ClientKMIPV1_0")]
    SuiteBMinLOS192ClientKMIPV1_0 = 0x00000037,
    #[ttlv(rename = "SuiteBMinLOS_192ClientKMIPV1_1")]
    SuiteBMinLOS192ClientKMIPV1_1 = 0x00000038,
    #[ttlv(rename = "SuiteBMinLOS_192ClientKMIPV1_2")]
    SuiteBMinLOS192ClientKMIPV1_2 = 0x00000039,
    #[ttlv(rename = "SuiteBMinLOS_192ServerKMIPV1_0")]
    SuiteBMinLOS192ServerKMIPV1_0 = 0x0000003A,
    #[ttlv(rename = "SuiteBMinLOS_192ServerKMIPV1_1")]
    SuiteBMinLOS192ServerKMIPV1_1 = 0x0000003B,
    #[ttlv(rename = "SuiteBMinLOS_192ServerKMIPV1_2")]
    SuiteBMinLOS192ServerKMIPV1_2 = 0x0000003C,
    StorageArrayWithSelfEncryptingDriveClientKMIPV1_0 = 0x0000003D,
    StorageArrayWithSelfEncryptingDriveClientKMIPV1_1 = 0x0000003E,
    StorageArrayWithSelfEncryptingDriveClientKMIPV1_2 = 0x0000003F,
    StorageArrayWithSelfEncryptingDriveServerKMIPV1_0 = 0x00000040,
    StorageArrayWithSelfEncryptingDriveServerKMIPV1_1 = 0x00000041,
    StorageArrayWithSelfEncryptingDriveServerKMIPV1_2 = 0x00000042,
    HTTPSClientKMIPV1_0 = 0x00000043,
    HTTPSClientKMIPV1_1 = 0x00000044,
    HTTPSClientKMIPV1_2 = 0x00000045,
    HTTPSServerKMIPV1_0 = 0x00000046,
    HTTPSServerKMIPV1_1 = 0x00000047,
    HTTPSServerKMIPV1_2 = 0x00000048,
    JSONClientKMIPV1_0 = 0x00000049,
    JSONClientKMIPV1_1 = 0x0000004A,
    JSONClientKMIPV1_2 = 0x0000004B,
    JSONServerKMIPV1_0 = 0x0000004C,
    JSONServerKMIPV1_1 = 0x0000004D,
    JSONServerKMIPV1_2 = 0x0000004E,
    XMLClientKMIPV1_0 = 0x0000004F,
    XMLClientKMIPV1_1 = 0x00000050,
    XMLClientKMIPV1_2 = 0x00000051,
    XMLServerKMIPV1_0 = 0x00000052,
    XMLServerKMIPV1_1 = 0x00000053,
    XMLServerKMIPV1_2 = 0x00000054,
    BaselineServerBasicKMIPV1_3 = 0x00000055,
    BaselineServerTLSV1_2KMIPV1_3 = 0x00000056,
    BaselineClientBasicKMIPV1_3 = 0x00000057,
    BaselineClientTLSV1_2KMIPV1_3 = 0x00000058,
    CompleteServerBasicKMIPV1_3 = 0x00000059,
    CompleteServerTLSV1_2KMIPV1_3 = 0x0000005A,
    TapeLibraryClientKMIPV1_3 = 0x0000005B,
    TapeLibraryServerKMIPV1_3 = 0x0000005C,
    SymmetricKeyLifecycleClientKMIPV1_3 = 0x0000005D,
    SymmetricKeyLifecycleServerKMIPV1_3 = 0x0000005E,
    AsymmetricKeyLifecycleClientKMIPV1_3 = 0x0000005F,
    AsymmetricKeyLifecycleServerKMIPV1_3 = 0x00000060,
    BasicCryptographicClientKMIPV1_3 = 0x00000061,
    BasicCryptographicServerKMIPV1_3 = 0x00000062,
    AdvancedCryptographicClientKMIPV1_3 = 0x00000063,
    AdvancedCryptographicServerKMIPV1_3 = 0x00000064,
    RNGCryptographicClientKMIPV1_3 = 0x00000065,
    RNGCryptographicServerKMIPV1_3 = 0x00000066,
    BasicSymmetricKeyFoundryClientKMIPV1_3 = 0x00000067,
    IntermediateSymmetricKeyFoundryClientKMIPV1_3 = 0x00000068,
    AdvancedSymmetricKeyFoundryClientKMIPV1_3 = 0x00000069,
    SymmetricKeyFoundryServerKMIPV1_3 = 0x0000006A,
    OpaqueManagedObjectStoreClientKMIPV1_3 = 0x0000006B,
    #[ttlv(rename = "OpaqueManagedObjectStoreServerKMIPV1_3")]
    OpaqueManagedObjectStoreServerKMIPV1_3 = 0x0000006C,
    #[ttlv(rename = "SuiteBMinLOS_128ClientKMIPV1_3")]
    SuiteBMinLOS128ClientKMIPV1_3 = 0x0000006D,
    #[ttlv(rename = "SuiteBMinLOS_128ServerKMIPV1_3")]
    SuiteBMinLOS128ServerKMIPV1_3 = 0x0000006E,
    #[ttlv(rename = "SuiteBMinLOS_192ClientKMIPV1_3")]
    SuiteBMinLOS192ClientKMIPV1_3 = 0x0000006F,
    #[ttlv(rename = "SuiteBMinLOS_192ServerKMIPV1_3")]
    SuiteBMinLOS192ServerKMIPV1_3 = 0x00000070,
    StorageArrayWithSelfEncryptingDriveClientKMIPV1_3 = 0x00000071,
    StorageArrayWithSelfEncryptingDriveServerKMIPV1_3 = 0x00000072,
    HTTPSClientKMIPV1_3 = 0x00000073,
    HTTPSServerKMIPV1_3 = 0x00000074,
    JSONClientKMIPV1_3 = 0x00000075,
    JSONServerKMIPV1_3 = 0x00000076,
    XMLClientKMIPV1_3 = 0x00000077,
    XMLServerKMIPV1_3 = 0x00000078,

    // KMIP 1.4
    BaselineServerBasicKMIPV1_4 = 0x00000079,
    BaselineServerTLSV1_2KMIPV1_4 = 0x0000007A,
    BaselineClientBasicKMIPV1_4 = 0x0000007B,
    BaselineClientTLSV1_2KMIPV1_4 = 0x0000007C,
    CompleteServerBasicKMIPV1_4 = 0x0000007D,
    CompleteServerTLSV1_2KMIPV1_4 = 0x0000007E,
    TapeLibraryClientKMIPV1_4 = 0x0000007F,
    TapeLibraryServerKMIPV1_4 = 0x00000080,
    SymmetricKeyLifecycleClientKMIPV1_4 = 0x00000081,
    SymmetricKeyLifecycleServerKMIPV1_4 = 0x00000082,
    AsymmetricKeyLifecycleClientKMIPV1_4 = 0x00000083,
    AsymmetricKeyLifecycleServerKMIPV1_4 = 0x00000084,
    BasicCryptographicClientKMIPV1_4 = 0x00000085,
    BasicCryptographicServerKMIPV1_4 = 0x00000086,
    AdvancedCryptographicClientKMIPV1_4 = 0x00000087,
    AdvancedCryptographicServerKMIPV1_4 = 0x00000088,
    RNGCryptographicClientKMIPV1_4 = 0x00000089,
    RNGCryptographicServerKMIPV1_4 = 0x0000008A,
    BasicSymmetricKeyFoundryClientKMIPV1_4 = 0x0000008B,
    IntermediateSymmetricKeyFoundryClientKMIPV1_4 = 0x0000008C,
    AdvancedSymmetricKeyFoundryClientKMIPV1_4 = 0x0000008D,
    SymmetricKeyFoundryServerKMIPV1_4 = 0x0000008E,
    OpaqueManagedObjectStoreClientKMIPV1_4 = 0x0000008F,
    OpaqueManagedObjectStoreServerKMIPV1_4 = 0x00000090,
    #[ttlv(rename = "SuiteBMinLOS_128ClientKMIPV1_4")]
    SuiteBMinLOS128ClientKMIPV1_4 = 0x00000091,
    #[ttlv(rename = "SuiteBMinLOS_128ServerKMIPV1_4")]
    SuiteBMinLOS128ServerKMIPV1_4 = 0x00000092,
    #[ttlv(rename = "SuiteBMinLOS_192ClientKMIPV1_4")]
    SuiteBMinLOS192ClientKMIPV1_4 = 0x00000093,
    #[ttlv(rename = "SuiteBMinLOS_192ServerKMIPV1_4")]
    SuiteBMinLOS192ServerKMIPV1_4 = 0x00000094,
    StorageArrayWithSelfEncryptingDriveClientKMIPV1_4 = 0x00000095,
    StorageArrayWithSelfEncryptingDriveServerKMIPV1_4 = 0x00000096,
    HTTPSClientKMIPV1_4 = 0x00000097,
    HTTPSServerKMIPV1_4 = 0x00000098,
    JSONClientKMIPV1_4 = 0x00000099,
    JSONServerKMIPV1_4 = 0x0000009A,
    XMLClientKMIPV1_4 = 0x0000009B,
    XMLServerKMIPV1_4 = 0x0000009C,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::ValidationAuthorityType)]
pub enum ValidationAuthorityType {
    Unspecified = 0x00000001,
    NISTCMVP = 0x00000002,
    CommonCriteria = 0x00000003,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::ValidationType)]
pub enum ValidationType {
    Unspecified = 0x00000001,
    Hardware = 0x00000002,
    Software = 0x00000003,
    Firmware = 0x00000004,
    Hybrid = 0x00000005,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::UnwrapMode)]
pub enum UnwrapMode {
    Unspecified = 0x00000001,
    Processed = 0x00000002,
    NotProcessed = 0x00000003,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::DestroyAction)]
pub enum DestroyAction {
    Unspecified = 0x00000001,
    KeyMaterialDeleted = 0x00000002,
    KeyMaterialShredded = 0x00000003,
    MetaDataDeleted = 0x00000004,
    MetaDataShredded = 0x00000005,
    Deleted = 0x00000006,
    Shredded = 0x00000007,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::ShreddingAlgorithm)]
pub enum ShreddingAlgorithm {
    Unspecified = 0x00000001,
    Cryptographic = 0x00000002,
    Unsupported = 0x00000003,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::RNGMode)]
pub enum RNGMode {
    Unspecified = 0x00000001,
    SharedInstantiation = 0x00000002,
    NonSharedInstantiation = 0x00000003,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::ClientRegistrationMethod)]
pub enum ClientRegistrationMethod {
    Unspecified = 0x00000001,
    ServerPreGenerated = 0x00000002,
    ServerOnDemand = 0x00000003,
    ClientGenerated = 0x00000004,
    ClientRegistered = 0x00000005,
}

// KMIP 1.4

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::MaskGenerator)]
pub enum MaskGenerator {
    MGF1 = 0x00000001,
}

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = Tags::KeyWrapType)]
pub enum KeyWrapType {
    NotWrapped = 0x00000001,
    AsRegistered = 0x00000002,
}
