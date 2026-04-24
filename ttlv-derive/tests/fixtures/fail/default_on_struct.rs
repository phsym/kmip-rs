use ttlv_derive::Encodable;

#[derive(Encodable)]
#[ttlv(tag = 1, default)]
struct Foo {
    x: u32,
}

fn main() {}
