use ttlv_derive::Encodable;

#[derive(Encodable)]
#[ttlv(enum)]
enum Foo {
    #[ttlv(default)]
    Unknown(u32, u32),
}

fn main() {}
