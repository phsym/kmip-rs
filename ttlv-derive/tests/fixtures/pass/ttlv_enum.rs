#![deny(warnings)]

use ttlv::{RawTag, Tag};
use ttlv_derive::{Decodable, Encodable, Enum};

#[derive(Clone, Enum, Encodable, Decodable)]
#[ttlv(enum, tag = 0x42_00_50u32)]
#[repr(u32)]
pub enum Operation {
    Create = 0x01,
    Destroy = 0x02,
    #[ttlv(rename = "Archive (legacy)")]
    Archive = 0x03,
    #[ttlv(default)]
    Unknown(RawTag),
}

fn main() {}
