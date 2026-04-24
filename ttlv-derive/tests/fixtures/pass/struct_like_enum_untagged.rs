#![deny(warnings)]

use ttlv_derive::Encodable;

#[derive(Encodable)]
#[ttlv(tag = 0x42_00_80u32)]
pub struct Leaf {
    #[ttlv(tag = 0x42_00_81u32)]
    pub value: i32,
}

// Untagged struct-like enum: gets `TagEncodable` + inherent `flatten_encode`,
// no `Encodable` impl (call sites pass a tag in).
#[derive(Encodable)]
pub enum Either {
    Left(Leaf),
    Right(Leaf),
}

fn main() {}
