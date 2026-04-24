#![deny(warnings)]

use ttlv::{RawTag, Struct, Value};
use ttlv_derive::{Decodable, Encodable};

#[derive(Encodable, Decodable)]
#[ttlv(tag = 0x42_00_90u32)]
pub struct Leaf {
    #[ttlv(tag = 0x42_00_91u32)]
    pub value: i32,
}

// Exercises codegen through common generic containers (`Vec<T>`, `Option<T>`,
// `Struct<T>`, `Value<T>`) to lock in the trait-bound shape the macros emit.
#[derive(Encodable, Decodable)]
#[ttlv(tag = 0x42_00_92u32)]
pub struct Container {
    #[ttlv(tag = 0x42_00_93u32)]
    pub leaves: Vec<Leaf>,
    #[ttlv(tag = 0x42_00_94u32)]
    pub maybe: Option<Leaf>,
    #[ttlv(tag = 0x42_00_95u32)]
    pub raw_struct: Struct<RawTag>,
    #[ttlv(tag = 0x42_00_96u32)]
    pub raw_value: Value<RawTag>,
}

fn main() {}
