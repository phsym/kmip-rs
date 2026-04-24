#![deny(warnings)]

use ttlv_derive::{Decodable, Encodable};

#[derive(Encodable, Decodable)]
pub struct Untagged {
    #[ttlv(tag = 0x42_00_30u32)]
    pub a: i32,
    #[ttlv(tag = 0x42_00_31u32)]
    pub b: i32,
}

fn main() {}
