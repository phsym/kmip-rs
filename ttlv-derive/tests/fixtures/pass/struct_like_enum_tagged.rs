#![deny(warnings)]

use ttlv_derive::Encodable;

#[derive(Encodable)]
#[ttlv(tag = 0x42_00_70u32)]
pub struct LoginDetails {
    #[ttlv(tag = 0x42_00_71u32)]
    pub user: String,
}

#[derive(Encodable)]
#[ttlv(tag = 0x42_00_72u32)]
pub struct TokenDetails {
    #[ttlv(tag = 0x42_00_73u32)]
    pub token: String,
}

// Tagged struct-like enum: each variant encodes its payload, wrapped in the
// outer struct header via `write_struct`.
#[derive(Encodable)]
#[ttlv(tag = 0x42_00_74u32)]
pub enum AuthKind {
    Login(LoginDetails),
    Token(TokenDetails),
}

fn main() {}
