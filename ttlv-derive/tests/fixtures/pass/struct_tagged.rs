#![deny(warnings)]

use ttlv_derive::{Decodable, Encodable};

#[derive(Encodable, Decodable)]
#[ttlv(tag = 0x42_00_01u32)]
pub struct Message {
    #[ttlv(tag = 0x42_00_02u32)]
    pub id: i32,
    #[ttlv(tag = 0x42_00_03u32)]
    pub name: String,
    #[ttlv(tag = 0x42_00_04u32)]
    pub optional: Option<i64>,
}

fn main() {}
