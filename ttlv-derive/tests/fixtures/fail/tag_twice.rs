use ttlv_derive::Encodable;

#[derive(Encodable)]
#[ttlv(tag = 1, tag = 2)]
struct Foo {
    x: u32,
}

fn main() {}
