use ttlv_derive::Enum;

#[derive(Enum)]
#[ttlv(enum)]
struct Foo {
    x: u32,
}

fn main() {}
