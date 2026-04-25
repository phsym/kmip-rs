use ttlv::{Decodable, Decoder, Encodable, Encoder};

use crate::Tags;

ttlv::bitmask! {
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    #[cfg_attr(feature="serde", derive(serde::Serialize))]
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct CryptographicUsageMask: u32 {
        const Sign = 1;
        const Verify = 1<<1;
        const Encrypt = 1<<2;
        const Decrypt = 1<<3;
        const WrapKey = 1<<4;
        const UnwrapKey = 1<<5;
        const Export = 1<<6;
        const MACGenerate = 1<<7;
        const MACVerify = 1 << 8;
        const DeriveKey = 1<<9;
        const ContentCommitment = 1<<10;
        const KeyAgreement = 1<<11;
        const CertificateSign = 1<<12;
        const CRLSign = 1<<13;
        const GenerateCryptogram = 1<<14;
        const ValidateCryptogram = 1<<15;
        const TranslateEncrypt = 1<<16;
        const TranslateDecrypt = 1<<17;
        const TranslateWrap = 1<<18;
        const TranslateUnwrap = 1<<19;
    }
}

impl Encodable for CryptographicUsageMask {
    fn encode(&self, encoder: &mut impl Encoder) -> ttlv::Result<()> {
        encoder.write_bitmask(Tags::CryptographicUsageMask, *self)
    }
}

impl Decodable for CryptographicUsageMask {
    fn decode(decoder: &mut impl Decoder) -> ttlv::Result<Self> {
        decoder.read_bitmask(Tags::CryptographicUsageMask)
    }
}

ttlv::bitmask! {
    #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
    #[cfg_attr(feature="serde", derive(serde::Serialize))]
    #[derive(Debug, Clone, Copy, PartialEq)]
    pub struct StorageStatusMask: u32 {
        const OnLineStorage = 1;
        const ArchivalStorage = 2;
    }
}

impl Encodable for StorageStatusMask {
    fn encode(&self, encoder: &mut impl Encoder) -> ttlv::Result<()> {
        encoder.write_bitmask(Tags::StorageStatusMask, *self)
    }
}

impl Decodable for StorageStatusMask {
    fn decode(decoder: &mut impl Decoder) -> ttlv::Result<Self> {
        decoder.read_bitmask(Tags::StorageStatusMask)
    }
}
