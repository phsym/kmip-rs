#![deny(warnings)]

use ttlv_derive::{Decodable, Encodable};

#[derive(Encodable, Decodable)]
#[ttlv(tag = 0x42_00_40u32)]
pub struct WithAttrs {
    #[ttlv(tag = 0x42_00_41u32, set_ext)]
    pub version: i32,
    #[ttlv(tag = 0x42_00_42u32, if(_ext.get::<i32>().is_some_and(|v| *v >= 2)))]
    pub conditional: Option<i32>,
    #[ttlv(skip)]
    pub computed: i32,
}

fn main() {}
