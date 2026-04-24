#![deny(warnings)]

use ttlv_derive::{Decodable, Encodable};

// Inner struct tagged so `flatten_encode` / `flatten_decode` inherent
// methods are generated and can be invoked by the outer struct's
// field-level `#[ttlv(flatten)]` attribute.
#[derive(Encodable, Decodable)]
#[ttlv(tag = 0x42_00_20u32)]
pub struct Inner {
    #[ttlv(tag = 0x42_00_21u32)]
    pub a: i32,
    #[ttlv(tag = 0x42_00_22u32)]
    pub b: String,
}

// Field-level `#[ttlv(flatten)]`: the outer struct delegates to
// `Inner::flatten_{encode,decode}` to inline Inner's fields into
// the outer's TTLV struct body.
#[derive(Encodable, Decodable)]
#[ttlv(tag = 0x42_00_10u32)]
pub struct Outer {
    #[ttlv(flatten)]
    pub inner: Inner,
    #[ttlv(tag = 0x42_00_13u32)]
    pub extra: i32,
}

fn main() {}
