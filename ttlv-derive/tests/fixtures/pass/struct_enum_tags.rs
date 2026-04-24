#![deny(warnings)]

use ttlv::Tag;
use ttlv_derive::{Decodable, Encodable};

// A user-defined tag set. `#[ttlv(tag = ...)]` accepts any expression that
// evaluates to a type implementing `ttlv::Tag`, so an enum of named tags
// can stand in anywhere a raw `u32` would (this is how the `kmip` crate
// exposes its `Tags` enum).
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum Tags {
    Message = 0x42_00_A0,
    Id = 0x42_00_A1,
    Name = 0x42_00_A2,
    Nested = 0x42_00_A3,
    Value = 0x42_00_A4,
}

impl Tag for Tags {
    fn numeric(&self) -> Option<u32> {
        Some(*self as u32)
    }

    fn name(&self) -> Option<&str> {
        Some(match self {
            Self::Message => "Message",
            Self::Id => "Id",
            Self::Name => "Name",
            Self::Nested => "Nested",
            Self::Value => "Value",
        })
    }
}

#[derive(Encodable, Decodable)]
#[ttlv(tag = Tags::Nested)]
pub struct Nested {
    #[ttlv(tag = Tags::Value)]
    pub value: i32,
}

#[derive(Encodable, Decodable)]
#[ttlv(tag = Tags::Message)]
pub struct Message {
    #[ttlv(tag = Tags::Id)]
    pub id: i32,
    #[ttlv(tag = Tags::Name)]
    pub name: String,
    #[ttlv(tag = Tags::Nested)]
    pub nested: Nested,
}

fn main() {}
