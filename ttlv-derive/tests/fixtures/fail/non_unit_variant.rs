use ttlv_derive::Encodable;

#[derive(Encodable)]
#[ttlv(enum)]
enum Foo {
    B(u32),
}

fn main() {}
