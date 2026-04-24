use ttlv_derive::Encodable;

#[derive(Encodable)]
#[ttlv(tag = 1, flatten)]
struct Foo {
    x: u32,
}

fn main() {}
