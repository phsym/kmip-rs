use ttlv_derive::Encodable;

#[derive(Encodable)]
#[ttlv(enum)]
enum Foo {
    A = 1,
    #[ttlv(default)]
    Unknown,
}

fn main() {}
