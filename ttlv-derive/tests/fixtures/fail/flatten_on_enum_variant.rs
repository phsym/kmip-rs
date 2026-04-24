use ttlv_derive::Encodable;

#[derive(Encodable)]
#[ttlv(enum)]
enum Foo {
    #[ttlv(flatten)]
    A = 1,
}

fn main() {}
