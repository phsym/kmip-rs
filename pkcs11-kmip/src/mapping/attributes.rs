#![allow(deprecated)]

use chrono::{DateTime, Datelike, Local, NaiveDate, TimeZone};
use cryptoki::{
    object::{
        Attribute as Pkcs11Attribute, AttributeType as Pkcs11AttributeType,
        CertificateType as Pkcs11CertificateType, KeyType, ObjectClass,
    },
    types::Date,
};
use kmip::{
    CryptographicUsageMask,
    attributes::{
        ActivationDate, AlwaysSensitive, AttributeName as KmipAttributeName,
        AttributeValue as KmipAttribute, CryptographicLength, DeactivationDate, Extractable,
        NeverExtractable, Sensitive, UniqueIdentifier,
    },
    enums::{CertificateType, CryptographicAlgorithm, ObjectType},
    types::{Name, X509CertificateIssuer, X509CertificateSubject},
};

// pub trait KmipAttributeExt {
//     fn into_pkcs11(self) -> Vec<Pkcs11Attribute>;
// }

pub trait Pkcs11AttributeExt {
    fn into_kmip(self) -> Option<KmipAttribute>;
}

// pub trait KmipAttributeNameExt {
//     fn into_pkcs11(self) -> Option<Pkcs11AttributeType>;
// }

// pub trait Pkcs11AttributeTypeExt {
//     fn into_kmip(self) -> Option<KmipAttributeName>;
// }

// fn date_from_chrono(dt: DateTime<Local>) -> Option<Date> {
//     let year = format!("{:04}", dt.year());
//     let month = format!("{:02}", dt.month());
//     let day = format!("{:02}", dt.day());
//     Date::new_from_str_slice(&year, &month, &day).ok()
// }

fn usage_mask(b: bool, flag: CryptographicUsageMask) -> CryptographicUsageMask {
    if b {
        flag
    } else {
        CryptographicUsageMask::empty()
    }
}

fn date_to_chrono(date: Date) -> Option<DateTime<Local>> {
    let year: i32 = std::str::from_utf8(&date.year).ok()?.parse().ok()?;
    let month: u32 = std::str::from_utf8(&date.month).ok()?.parse().ok()?;
    let day: u32 = std::str::from_utf8(&date.day).ok()?.parse().ok()?;
    let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(0, 0, 0)?;
    Local.from_local_datetime(&naive).single()
}

// impl KmipAttributeExt for KmipAttribute {
//     fn into_pkcs11(self) -> Vec<Pkcs11Attribute> {
//         match self {
//             KmipAttribute::UniqueIdentifier(unique_identifier) => {
//                 vec![Pkcs11Attribute::Id(unique_identifier.0.into_bytes())]
//             }
//             KmipAttribute::Name(name) => {
//                 vec![Pkcs11Attribute::Label(name.name_value.into_bytes())]
//             }
//             KmipAttribute::ObjectType(object_type) => {
//                 let class = match object_type {
//                     ObjectType::Certificate => ObjectClass::CERTIFICATE,
//                     ObjectType::SymmetricKey => ObjectClass::SECRET_KEY,
//                     ObjectType::PublicKey => ObjectClass::PUBLIC_KEY,
//                     ObjectType::PrivateKey => ObjectClass::PRIVATE_KEY,
//                     ObjectType::SecretData => ObjectClass::DATA,
//                     ObjectType::SplitKey
//                     | ObjectType::Template
//                     | ObjectType::OpaqueObject
//                     | ObjectType::PGPKey => return vec![],
//                 };
//                 vec![Pkcs11Attribute::Class(class)]
//             }
//             KmipAttribute::CryptographicAlgorithm(cryptographic_algorithm) => {
//                 let kt = match cryptographic_algorithm {
//                     CryptographicAlgorithm::DES => KeyType::DES,
//                     CryptographicAlgorithm::DES3 => KeyType::DES3,
//                     CryptographicAlgorithm::AES => KeyType::AES,
//                     CryptographicAlgorithm::RSA => KeyType::RSA,
//                     CryptographicAlgorithm::DSA => KeyType::DSA,
//                     CryptographicAlgorithm::ECDSA
//                     | CryptographicAlgorithm::EC
//                     | CryptographicAlgorithm::ECDH => KeyType::EC,
//                     CryptographicAlgorithm::HmacSha1 => KeyType::SHA_1_HMAC,
//                     CryptographicAlgorithm::HmacSha224 => KeyType::SHA224_HMAC,
//                     CryptographicAlgorithm::HmacSha256 => KeyType::SHA256_HMAC,
//                     CryptographicAlgorithm::HmacSha384 => KeyType::SHA384_HMAC,
//                     CryptographicAlgorithm::HmacSha512 => KeyType::SHA512_HMAC,
//                     CryptographicAlgorithm::HmacMd5 => KeyType::MD5_HMAC,
//                     CryptographicAlgorithm::DH => KeyType::DH,
//                     CryptographicAlgorithm::Blowfish => KeyType::BLOWFISH,
//                     CryptographicAlgorithm::Camellia => KeyType::CAMELLIA,
//                     CryptographicAlgorithm::CAST5 => KeyType::CAST128,
//                     CryptographicAlgorithm::IDEA => KeyType::IDEA,
//                     CryptographicAlgorithm::RC2 => KeyType::RC2,
//                     CryptographicAlgorithm::RC4 => KeyType::RC4,
//                     CryptographicAlgorithm::RC5 => KeyType::RC5,
//                     CryptographicAlgorithm::SKIPJACK => KeyType::SKIPJACK,
//                     CryptographicAlgorithm::Twofish => KeyType::TWOFISH,
//                     _ => return vec![],
//                 };
//                 vec![Pkcs11Attribute::KeyType(kt)]
//             }
//             KmipAttribute::CryptographicLength(_) => vec![],
//             KmipAttribute::CryptographicParameters(_) => vec![],
//             KmipAttribute::CryptographicDomainParameters(_) => vec![],
//             KmipAttribute::CertificateType(certificate_type) => {
//                 let ct = match certificate_type {
//                     CertificateType::X509 => Pkcs11CertificateType::X_509,
//                     CertificateType::PGP => return vec![],
//                 };
//                 vec![Pkcs11Attribute::CertificateType(ct)]
//             }
//             KmipAttribute::CertificateIdentifier(_) => vec![],
//             KmipAttribute::CertificateSubject(_) => vec![],
//             KmipAttribute::CertificateIssuer(_) => vec![],
//             KmipAttribute::Digest(_) => vec![],
//             KmipAttribute::OperationPolicyName(_) => vec![],
//             KmipAttribute::CryptographicUsageMask(mask) => {
//                 let mut out = Vec::new();
//                 if mask.contains(CryptographicUsageMask::Sign) {
//                     out.push(Pkcs11Attribute::Sign(true));
//                 }
//                 if mask.contains(CryptographicUsageMask::Verify) {
//                     out.push(Pkcs11Attribute::Verify(true));
//                 }
//                 if mask.contains(CryptographicUsageMask::Encrypt) {
//                     out.push(Pkcs11Attribute::Encrypt(true));
//                 }
//                 if mask.contains(CryptographicUsageMask::Decrypt) {
//                     out.push(Pkcs11Attribute::Decrypt(true));
//                 }
//                 if mask.contains(CryptographicUsageMask::WrapKey) {
//                     out.push(Pkcs11Attribute::Wrap(true));
//                 }
//                 if mask.contains(CryptographicUsageMask::UnwrapKey) {
//                     out.push(Pkcs11Attribute::Unwrap(true));
//                 }
//                 if mask.contains(CryptographicUsageMask::DeriveKey) {
//                     out.push(Pkcs11Attribute::Derive(true));
//                 }
//                 out
//             }
//             KmipAttribute::LeaseTime(_) => vec![],
//             KmipAttribute::UsageLimits(_) => vec![],
//             KmipAttribute::State(_) => vec![],
//             KmipAttribute::InitialDate(initial_date) => date_from_chrono(initial_date.0)
//                 .map(|d| vec![Pkcs11Attribute::StartDate(d)])
//                 .unwrap_or_default(),
//             KmipAttribute::ActivationDate(activation_date) => date_from_chrono(activation_date.0)
//                 .map(|d| vec![Pkcs11Attribute::StartDate(d)])
//                 .unwrap_or_default(),
//             KmipAttribute::ProcessStartDate(_) => vec![],
//             KmipAttribute::ProtectStopDate(_) => vec![],
//             KmipAttribute::DeactivationDate(deactivation_date) => {
//                 date_from_chrono(deactivation_date.0)
//                     .map(|d| vec![Pkcs11Attribute::EndDate(d)])
//                     .unwrap_or_default()
//             }
//             KmipAttribute::DestroyDate(_) => vec![],
//             KmipAttribute::CompromiseOccurrenceDate(_) => vec![],
//             KmipAttribute::CompromiseDate(_) => vec![],
//             KmipAttribute::RevocationReason(_) => vec![],
//             KmipAttribute::ArchiveDate(_) => vec![],
//             KmipAttribute::ObjectGroup(_) => vec![],
//             KmipAttribute::Link(_) => vec![],
//             KmipAttribute::ApplicationSpecificInformation(_) => vec![],
//             KmipAttribute::ContactInformation(_) => vec![],
//             KmipAttribute::LastChangeDate(_) => vec![],
//             KmipAttribute::CertificateLength(_) => vec![],
//             KmipAttribute::Fresh(_) => vec![],
//             KmipAttribute::X509CertificateIdentifier(id) => vec![
//                 Pkcs11Attribute::Issuer(id.issuer_distinguished_name),
//                 Pkcs11Attribute::SerialNumber(id.certificate_serial_number),
//             ],
//             KmipAttribute::X509CertificateSubject(subject) => {
//                 vec![Pkcs11Attribute::Subject(subject.subject_distinguished_name)]
//             }
//             KmipAttribute::X509CertificateIssuer(issuer) => {
//                 vec![Pkcs11Attribute::Issuer(issuer.issuer_distinguished_name)]
//             }
//             KmipAttribute::DigitalSignatureAlgorithm(_) => vec![],
//             KmipAttribute::AlternativeName(_) => vec![],
//             KmipAttribute::KeyValuePresent(_) => vec![],
//             KmipAttribute::KeyValueLocation(_) => vec![],
//             KmipAttribute::OriginalCreationDate(_) => vec![],
//             KmipAttribute::RandomNumberGenerator(_) => vec![],
//             KmipAttribute::PKCS12FriendlyName(_) => vec![],
//             KmipAttribute::Description(_) => vec![],
//             KmipAttribute::Comment(_) => vec![],
//             KmipAttribute::Sensitive(sensitive) => {
//                 vec![Pkcs11Attribute::Sensitive(sensitive.0)]
//             }
//             KmipAttribute::AlwaysSensitive(always_sensitive) => {
//                 vec![Pkcs11Attribute::AlwaysSensitive(always_sensitive.0)]
//             }
//             KmipAttribute::Extractable(extractable) => {
//                 vec![Pkcs11Attribute::Extractable(extractable.0)]
//             }
//             KmipAttribute::NeverExtractable(never_extractable) => {
//                 vec![Pkcs11Attribute::NeverExtractable(never_extractable.0)]
//             }
//             KmipAttribute::Unknown { .. } => vec![],
//         }
//     }
// }

impl Pkcs11AttributeExt for Pkcs11Attribute {
    fn into_kmip(self) -> Option<KmipAttribute> {
        match self {
            Pkcs11Attribute::AcIssuer(_) => None,
            Pkcs11Attribute::AllowedMechanisms(_) => None,
            Pkcs11Attribute::AlwaysAuthenticate(_) => None,
            Pkcs11Attribute::AlwaysSensitive(b) => {
                Some(KmipAttribute::AlwaysSensitive(AlwaysSensitive(b)))
            }
            Pkcs11Attribute::Application(_) => None,
            Pkcs11Attribute::AttrTypes(_) => None,
            Pkcs11Attribute::Base(_) => None,
            Pkcs11Attribute::CertificateType(certificate_type) => {
                Some(KmipAttribute::CertificateType(match certificate_type {
                    Pkcs11CertificateType::X_509 => CertificateType::X509,
                    _ => return None,
                }))
            }
            Pkcs11Attribute::CheckValue(_) => None,
            Pkcs11Attribute::Class(object_class) => {
                Some(KmipAttribute::ObjectType(match object_class {
                    ObjectClass::CERTIFICATE => ObjectType::Certificate,
                    ObjectClass::PUBLIC_KEY => ObjectType::PublicKey,
                    ObjectClass::PRIVATE_KEY => ObjectType::PrivateKey,
                    ObjectClass::SECRET_KEY => ObjectType::SymmetricKey,
                    ObjectClass::DATA => ObjectType::SecretData,
                    _ => return None,
                }))
            }
            Pkcs11Attribute::Coefficient(_) => None,
            Pkcs11Attribute::Copyable(_) => None,
            Pkcs11Attribute::Decapsulate(_) => None,
            Pkcs11Attribute::Decrypt(b) => Some(KmipAttribute::CryptographicUsageMask(usage_mask(
                b,
                CryptographicUsageMask::Decrypt,
            ))),
            Pkcs11Attribute::Derive(b) => Some(KmipAttribute::CryptographicUsageMask(usage_mask(
                b,
                CryptographicUsageMask::DeriveKey,
            ))),
            Pkcs11Attribute::Destroyable(_) => None,
            Pkcs11Attribute::EcParams(_) => None,
            Pkcs11Attribute::EcPoint(_) => None,
            Pkcs11Attribute::Encapsulate(_) => None,
            Pkcs11Attribute::Encrypt(b) => Some(KmipAttribute::CryptographicUsageMask(usage_mask(
                b,
                CryptographicUsageMask::Encrypt,
            ))),
            Pkcs11Attribute::EndDate(date) => {
                date_to_chrono(date).map(|d| KmipAttribute::DeactivationDate(DeactivationDate(d)))
            }
            Pkcs11Attribute::Exponent1(_) => None,
            Pkcs11Attribute::Exponent2(_) => None,
            Pkcs11Attribute::Extractable(b) => Some(KmipAttribute::Extractable(Extractable(b))),
            Pkcs11Attribute::HashOfIssuerPublicKey(_) => None,
            Pkcs11Attribute::HashOfSubjectPublicKey(_) => None,
            Pkcs11Attribute::Id(items) => {
                let s = String::from_utf8(items).ok()?;
                Some(KmipAttribute::UniqueIdentifier(UniqueIdentifier(s)))
            }
            Pkcs11Attribute::Issuer(items) => Some(KmipAttribute::X509CertificateIssuer(
                X509CertificateIssuer {
                    issuer_distinguished_name: items,
                    issuer_alternative_name: None,
                },
            )),
            Pkcs11Attribute::KeyGenMechanism(_) => None,
            Pkcs11Attribute::KeyType(key_type) => {
                Some(KmipAttribute::CryptographicAlgorithm(match key_type {
                    KeyType::RSA => CryptographicAlgorithm::RSA,
                    KeyType::DSA => CryptographicAlgorithm::DSA,
                    KeyType::DH => CryptographicAlgorithm::DH,
                    KeyType::EC => CryptographicAlgorithm::EC,
                    KeyType::DES => CryptographicAlgorithm::DES,
                    KeyType::DES3 => CryptographicAlgorithm::DES3,
                    KeyType::AES => CryptographicAlgorithm::AES,
                    KeyType::RC2 => CryptographicAlgorithm::RC2,
                    KeyType::RC4 => CryptographicAlgorithm::RC4,
                    KeyType::RC5 => CryptographicAlgorithm::RC5,
                    KeyType::IDEA => CryptographicAlgorithm::IDEA,
                    KeyType::SKIPJACK => CryptographicAlgorithm::SKIPJACK,
                    KeyType::BLOWFISH => CryptographicAlgorithm::Blowfish,
                    KeyType::TWOFISH => CryptographicAlgorithm::Twofish,
                    KeyType::CAMELLIA => CryptographicAlgorithm::Camellia,
                    KeyType::CAST128 => CryptographicAlgorithm::CAST5,
                    KeyType::MD5_HMAC => CryptographicAlgorithm::HmacMd5,
                    KeyType::SHA_1_HMAC => CryptographicAlgorithm::HmacSha1,
                    KeyType::SHA256_HMAC => CryptographicAlgorithm::HmacSha256,
                    _ => return None,
                }))
            }
            Pkcs11Attribute::Label(items) => {
                let s = String::from_utf8(items).ok()?;
                Some(KmipAttribute::Name(Name::new_string(s)))
            }
            Pkcs11Attribute::Local(_) => None,
            Pkcs11Attribute::Modifiable(_) => None,
            Pkcs11Attribute::Modulus(_) => None,
            Pkcs11Attribute::ModulusBits(ulong) => {
                let bits: i32 = u64::from(ulong).try_into().ok()?;
                Some(KmipAttribute::CryptographicLength(CryptographicLength(
                    bits,
                )))
            }
            Pkcs11Attribute::NeverExtractable(b) => {
                Some(KmipAttribute::NeverExtractable(NeverExtractable(b)))
            }
            Pkcs11Attribute::ObjectValidationFlags(_) => None,
            Pkcs11Attribute::ObjectId(_) => None,
            Pkcs11Attribute::Owner(_) => None,
            Pkcs11Attribute::ParameterSet(_) => None,
            Pkcs11Attribute::Prime(_) => None,
            Pkcs11Attribute::Prime1(_) => None,
            Pkcs11Attribute::Prime2(_) => None,
            Pkcs11Attribute::Private(_) => None,
            Pkcs11Attribute::PrivateExponent(_) => None,
            Pkcs11Attribute::ProfileId(_) => None,
            Pkcs11Attribute::PublicExponent(_) => None,
            Pkcs11Attribute::PublicKeyInfo(_) => None,
            Pkcs11Attribute::Seed(_) => None,
            Pkcs11Attribute::Sensitive(b) => Some(KmipAttribute::Sensitive(Sensitive(b))),
            Pkcs11Attribute::SerialNumber(_) => None,
            Pkcs11Attribute::Sign(b) => Some(KmipAttribute::CryptographicUsageMask(usage_mask(
                b,
                CryptographicUsageMask::Sign,
            ))),
            Pkcs11Attribute::SignRecover(_) => None,
            Pkcs11Attribute::StartDate(date) => {
                date_to_chrono(date).map(|d| KmipAttribute::ActivationDate(ActivationDate(d)))
            }
            Pkcs11Attribute::Subject(items) => Some(KmipAttribute::X509CertificateSubject(
                X509CertificateSubject {
                    subject_distinguished_name: items,
                    subject_alternative_name: None,
                },
            )),
            Pkcs11Attribute::Token(_) => None,
            Pkcs11Attribute::Trusted(_) => None,
            Pkcs11Attribute::UniqueId(items) => {
                let s = String::from_utf8(items).ok()?;
                Some(KmipAttribute::UniqueIdentifier(UniqueIdentifier(s)))
            }
            Pkcs11Attribute::Unwrap(b) => Some(KmipAttribute::CryptographicUsageMask(usage_mask(
                b,
                CryptographicUsageMask::UnwrapKey,
            ))),
            Pkcs11Attribute::Url(_) => None,
            Pkcs11Attribute::ValidationType(_) => None,
            Pkcs11Attribute::ValidationVersion(_) => None,
            Pkcs11Attribute::ValidationLevel(_) => None,
            Pkcs11Attribute::ValidationModuleId(_) => None,
            Pkcs11Attribute::ValidationFlag(_) => None,
            Pkcs11Attribute::ValidationAuthorityType(_) => None,
            Pkcs11Attribute::ValidationCountry(_) => None,
            Pkcs11Attribute::ValidationCertificateIdentifier(_) => None,
            Pkcs11Attribute::ValidationCertificateUri(_) => None,
            Pkcs11Attribute::ValidationVendorUri(_) => None,
            Pkcs11Attribute::ValidationProfile(_) => None,
            Pkcs11Attribute::Value(_) => None,
            Pkcs11Attribute::ValueLen(ulong) => {
                let bytes = u64::from(ulong);
                let bits: i32 = bytes.checked_mul(8)?.try_into().ok()?;
                Some(KmipAttribute::CryptographicLength(CryptographicLength(
                    bits,
                )))
            }
            Pkcs11Attribute::VendorDefined(_) => None,
            Pkcs11Attribute::Verify(b) => Some(KmipAttribute::CryptographicUsageMask(usage_mask(
                b,
                CryptographicUsageMask::Verify,
            ))),
            Pkcs11Attribute::VerifyRecover(_) => None,
            Pkcs11Attribute::Wrap(b) => Some(KmipAttribute::CryptographicUsageMask(usage_mask(
                b,
                CryptographicUsageMask::WrapKey,
            ))),
            Pkcs11Attribute::WrapWithTrusted(_) => None,
            _ => None,
        }
    }
}

// impl KmipAttributeNameExt for KmipAttributeName {
//     fn into_pkcs11(self) -> Option<Pkcs11AttributeType> {
//         match self {
//             KmipAttributeName::UniqueIdentifier => Some(Pkcs11AttributeType::Id),
//             KmipAttributeName::Name => Some(Pkcs11AttributeType::Label),
//             KmipAttributeName::ObjectType => Some(Pkcs11AttributeType::Class),
//             KmipAttributeName::CryptographicAlgorithm => Some(Pkcs11AttributeType::KeyType),
//             KmipAttributeName::CryptographicLength => None,
//             KmipAttributeName::CryptographicParameters => None,
//             KmipAttributeName::CryptographicDomainParameters => None,
//             KmipAttributeName::CertificateType => Some(Pkcs11AttributeType::CertificateType),
//             KmipAttributeName::CertificateIdentifier => None,
//             KmipAttributeName::CertificateSubject => None,
//             KmipAttributeName::CertificateIssuer => None,
//             KmipAttributeName::Digest => None,
//             KmipAttributeName::OperationPolicyName => None,
//             KmipAttributeName::CryptographicUsageMask => None,
//             KmipAttributeName::LeaseTime => None,
//             KmipAttributeName::UsageLimits => None,
//             KmipAttributeName::State => None,
//             KmipAttributeName::InitialDate => Some(Pkcs11AttributeType::StartDate),
//             KmipAttributeName::ActivationDate => Some(Pkcs11AttributeType::StartDate),
//             KmipAttributeName::ProcessStartDate => None,
//             KmipAttributeName::ProtectStopDate => None,
//             KmipAttributeName::DeactivationDate => Some(Pkcs11AttributeType::EndDate),
//             KmipAttributeName::DestroyDate => None,
//             KmipAttributeName::CompromiseOccurrenceDate => None,
//             KmipAttributeName::CompromiseDate => None,
//             KmipAttributeName::RevocationReason => None,
//             KmipAttributeName::ArchiveDate => None,
//             KmipAttributeName::ObjectGroup => None,
//             KmipAttributeName::Link => None,
//             KmipAttributeName::ApplicationSpecificInformation => None,
//             KmipAttributeName::ContactInformation => None,
//             KmipAttributeName::LastChangeDate => None,
//             KmipAttributeName::CertificateLength => None,
//             KmipAttributeName::Fresh => None,
//             KmipAttributeName::X509CertificateIdentifier => None,
//             KmipAttributeName::X509CertificateSubject => Some(Pkcs11AttributeType::Subject),
//             KmipAttributeName::X509CertificateIssuer => Some(Pkcs11AttributeType::Issuer),
//             KmipAttributeName::DigitalSignatureAlgorithm => None,
//             KmipAttributeName::AlternativeName => None,
//             KmipAttributeName::KeyValuePresent => None,
//             KmipAttributeName::KeyValueLocation => None,
//             KmipAttributeName::OriginalCreationDate => None,
//             KmipAttributeName::RandomNumberGenerator => None,
//             KmipAttributeName::PKCS12FriendlyName => None,
//             KmipAttributeName::Description => None,
//             KmipAttributeName::Comment => None,
//             KmipAttributeName::Sensitive => Some(Pkcs11AttributeType::Sensitive),
//             KmipAttributeName::AlwaysSensitive => Some(Pkcs11AttributeType::AlwaysSensitive),
//             KmipAttributeName::Extractable => Some(Pkcs11AttributeType::Extractable),
//             KmipAttributeName::NeverExtractable => Some(Pkcs11AttributeType::NeverExtractable),
//             KmipAttributeName::Unknown(_) => None,
//         }
//     }
// }

// impl Pkcs11AttributeTypeExt for Pkcs11AttributeType {
//     fn into_kmip(self) -> Option<KmipAttributeName> {
//         match self {
//             Pkcs11AttributeType::AcIssuer => None,
//             Pkcs11AttributeType::AllowedMechanisms => None,
//             Pkcs11AttributeType::AlwaysAuthenticate => None,
//             Pkcs11AttributeType::AlwaysSensitive => Some(KmipAttributeName::AlwaysSensitive),
//             Pkcs11AttributeType::Application => None,
//             Pkcs11AttributeType::AttrTypes => None,
//             Pkcs11AttributeType::Base => None,
//             Pkcs11AttributeType::CertificateType => Some(KmipAttributeName::CertificateType),
//             Pkcs11AttributeType::CheckValue => None,
//             Pkcs11AttributeType::Class => Some(KmipAttributeName::ObjectType),
//             Pkcs11AttributeType::Coefficient => None,
//             Pkcs11AttributeType::Copyable => None,
//             Pkcs11AttributeType::Decapsulate => None,
//             Pkcs11AttributeType::Decrypt => Some(KmipAttributeName::CryptographicUsageMask),
//             Pkcs11AttributeType::Derive => Some(KmipAttributeName::CryptographicUsageMask),
//             Pkcs11AttributeType::Destroyable => None,
//             Pkcs11AttributeType::EcParams => None,
//             Pkcs11AttributeType::EcPoint => None,
//             Pkcs11AttributeType::Encapsulate => None,
//             Pkcs11AttributeType::Encrypt => Some(KmipAttributeName::CryptographicUsageMask),
//             Pkcs11AttributeType::EndDate => Some(KmipAttributeName::DeactivationDate),
//             Pkcs11AttributeType::Exponent1 => None,
//             Pkcs11AttributeType::Exponent2 => None,
//             Pkcs11AttributeType::Extractable => Some(KmipAttributeName::Extractable),
//             Pkcs11AttributeType::HashOfIssuerPublicKey => None,
//             Pkcs11AttributeType::HashOfSubjectPublicKey => None,
//             Pkcs11AttributeType::Id => Some(KmipAttributeName::UniqueIdentifier),
//             Pkcs11AttributeType::Issuer => Some(KmipAttributeName::X509CertificateIssuer),
//             Pkcs11AttributeType::KeyGenMechanism => None,
//             Pkcs11AttributeType::KeyType => Some(KmipAttributeName::CryptographicAlgorithm),
//             Pkcs11AttributeType::Label => Some(KmipAttributeName::Name),
//             Pkcs11AttributeType::Local => None,
//             Pkcs11AttributeType::Modifiable => None,
//             Pkcs11AttributeType::Modulus => None,
//             Pkcs11AttributeType::ModulusBits => Some(KmipAttributeName::CryptographicLength),
//             Pkcs11AttributeType::NeverExtractable => Some(KmipAttributeName::NeverExtractable),
//             Pkcs11AttributeType::ObjectId => None,
//             Pkcs11AttributeType::ObjectValidationFlags => None,
//             Pkcs11AttributeType::Owner => None,
//             Pkcs11AttributeType::ParameterSet => None,
//             Pkcs11AttributeType::Prime => None,
//             Pkcs11AttributeType::Prime1 => None,
//             Pkcs11AttributeType::Prime2 => None,
//             Pkcs11AttributeType::Private => None,
//             Pkcs11AttributeType::PrivateExponent => None,
//             Pkcs11AttributeType::PublicExponent => None,
//             Pkcs11AttributeType::PublicKeyInfo => None,
//             Pkcs11AttributeType::ProfileId => None,
//             Pkcs11AttributeType::Seed => None,
//             Pkcs11AttributeType::Sensitive => Some(KmipAttributeName::Sensitive),
//             Pkcs11AttributeType::SerialNumber => None,
//             Pkcs11AttributeType::Sign => Some(KmipAttributeName::CryptographicUsageMask),
//             Pkcs11AttributeType::SignRecover => None,
//             Pkcs11AttributeType::StartDate => Some(KmipAttributeName::ActivationDate),
//             Pkcs11AttributeType::Subject => Some(KmipAttributeName::X509CertificateSubject),
//             Pkcs11AttributeType::Token => None,
//             Pkcs11AttributeType::Trusted => None,
//             Pkcs11AttributeType::UniqueId => Some(KmipAttributeName::UniqueIdentifier),
//             Pkcs11AttributeType::Unwrap => Some(KmipAttributeName::CryptographicUsageMask),
//             Pkcs11AttributeType::Url => None,
//             Pkcs11AttributeType::ValidationType => None,
//             Pkcs11AttributeType::ValidationVersion => None,
//             Pkcs11AttributeType::ValidationLevel => None,
//             Pkcs11AttributeType::ValidationModuleId => None,
//             Pkcs11AttributeType::ValidationFlag => None,
//             Pkcs11AttributeType::ValidationAuthorityType => None,
//             Pkcs11AttributeType::ValidationCountry => None,
//             Pkcs11AttributeType::ValidationCertificateIdentifier => None,
//             Pkcs11AttributeType::ValidationCertificateUri => None,
//             Pkcs11AttributeType::ValidationVendorUri => None,
//             Pkcs11AttributeType::ValidationProfile => None,
//             Pkcs11AttributeType::Value => None,
//             Pkcs11AttributeType::ValueLen => Some(KmipAttributeName::CryptographicLength),
//             Pkcs11AttributeType::VendorDefined(_) => None,
//             Pkcs11AttributeType::Verify => Some(KmipAttributeName::CryptographicUsageMask),
//             Pkcs11AttributeType::VerifyRecover => None,
//             Pkcs11AttributeType::Wrap => Some(KmipAttributeName::CryptographicUsageMask),
//             Pkcs11AttributeType::WrapWithTrusted => None,
//             _ => None,
//         }
//     }
// }
