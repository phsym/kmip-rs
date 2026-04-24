use ttlv_derive::Encodable;

#[derive(Encodable)]
#[ttlv(bogus)]
struct Foo {
    x: u32,
}

fn main() {}
