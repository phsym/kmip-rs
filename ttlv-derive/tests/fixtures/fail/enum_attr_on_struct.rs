use ttlv_derive::Encodable;

#[derive(Encodable)]
#[ttlv(enum)]
struct Foo {
    x: u32,
}

fn main() {}
