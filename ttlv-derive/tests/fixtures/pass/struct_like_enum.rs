#![deny(warnings)]

use ttlv_derive::Encodable;

#[derive(Encodable)]
#[ttlv(tag = 0x42_00_60u32)]
pub struct UserPassword {
    #[ttlv(tag = 0x42_00_61u32)]
    pub username: String,
}

#[derive(Encodable)]
#[ttlv(tag = 0x42_00_62u32)]
pub struct Token {
    #[ttlv(tag = 0x42_00_63u32)]
    pub value: String,
}

#[derive(Encodable)]
#[ttlv(flatten)]
pub enum Credential {
    UserPassword(UserPassword),
    Token(Token),
}

fn main() {}
