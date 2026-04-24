#![deny(warnings)]

use ttlv_derive::{Decodable, Encodable, Enum};

#[derive(Enum, Encodable, Decodable)]
#[ttlv(enum)]
#[repr(u32)]
pub enum Status {
    Ok = 1,
    Failed = 2,
}

fn main() {}
