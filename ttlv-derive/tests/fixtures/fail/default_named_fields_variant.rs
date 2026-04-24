use ttlv_derive::Encodable;

#[derive(Encodable)]
#[ttlv(enum)]
enum Foo {
    #[ttlv(default)]
    Unknown { name: String },
}

fn main() {}
