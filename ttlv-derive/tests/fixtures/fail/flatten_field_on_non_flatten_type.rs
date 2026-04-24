// Applying `#[ttlv(flatten)]` to a field whose type doesn't have the
// derive-generated `flatten_encode` / `flatten_decode` inherent methods
// (e.g., a primitive `i32`) must fail at the field's type, not silently
// succeed — see issue #64.

use ttlv_derive::{Decodable, Encodable};

#[derive(Encodable, Decodable)]
#[ttlv(tag = 0x42_00_01u32)]
pub struct Outer {
    #[ttlv(flatten)]
    pub bad: i32,
}

fn main() {}
