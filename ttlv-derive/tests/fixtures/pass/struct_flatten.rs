#![deny(warnings)]

use ttlv_derive::{Decodable, Encodable};

// Struct-level `#[ttlv(flatten)]`: this struct's `Encodable::encode` emits its
// fields inline without a struct wrapper. No `TagEncodable` / `TagDecodable`
// impls are generated.
#[derive(Encodable, Decodable)]
#[ttlv(flatten)]
pub struct Flat {
    #[ttlv(tag = 0x42_00_11u32)]
    pub a: i32,
    #[ttlv(tag = 0x42_00_12u32)]
    pub b: String,
}

fn main() {}
