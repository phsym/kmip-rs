//! Integration tests for `#[derive(Encodable)]` and `#[derive(Decodable)]`.
//!
//! These tests verify that derived encode/decode implementations produce correct
//! TTLV binary output and successfully round-trip (encode then decode back).

use ttlv::{Decodable, Encodable, Encoder, Enum, RawTag, Tag, TtlvDecoder, TtlvEncoder};

// -- Struct round-trip --

#[derive(Debug, PartialEq, Encodable, Decodable)]
#[ttlv(tag = 0x420001)]
struct Simple {
    #[ttlv(tag = 0x420002)]
    value: i32,
    #[ttlv(tag = 0x420003)]
    name: String,
}

#[test]
fn test_struct_roundtrip() {
    let original = Simple {
        value: 42,
        name: "hello".into(),
    };

    let mut enc = TtlvEncoder::new();
    original.encode(&mut enc);

    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded = Simple::decode(&mut dec).unwrap();

    assert_eq!(original, decoded);
}

// -- Nested struct round-trip --

#[derive(Debug, PartialEq, Encodable, Decodable)]
#[ttlv(tag = 0x420010)]
struct Inner {
    #[ttlv(tag = 0x420011)]
    x: i32,
}

#[derive(Debug, PartialEq, Encodable, Decodable)]
#[ttlv(tag = 0x420020)]
struct Outer {
    #[ttlv(tag = 0x420010)]
    inner: Inner,
    #[ttlv(tag = 0x420021)]
    label: String,
}

#[test]
fn test_nested_struct_roundtrip() {
    let original = Outer {
        inner: Inner { x: 99 },
        label: "nested".into(),
    };

    let mut enc = TtlvEncoder::new();
    original.encode(&mut enc);

    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded = Outer::decode(&mut dec).unwrap();

    assert_eq!(original, decoded);
}

// -- Optional field round-trip --

#[derive(Debug, PartialEq, Encodable, Decodable)]
#[ttlv(tag = 0x420030)]
struct WithOptional {
    #[ttlv(tag = 0x420031)]
    required: i32,
    #[ttlv(tag = 0x420032)]
    optional: Option<String>,
}

#[test]
fn test_optional_present_roundtrip() {
    let original = WithOptional {
        required: 1,
        optional: Some("present".into()),
    };

    let mut enc = TtlvEncoder::new();
    original.encode(&mut enc);

    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded = WithOptional::decode(&mut dec).unwrap();

    assert_eq!(original, decoded);
}

#[test]
fn test_optional_absent_roundtrip() {
    let original = WithOptional {
        required: 1,
        optional: None,
    };

    let mut enc = TtlvEncoder::new();
    original.encode(&mut enc);

    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded = WithOptional::decode(&mut dec).unwrap();

    assert_eq!(original, decoded);
}

// -- TTLV enum round-trip --

#[derive(Debug, PartialEq, Encodable, Decodable, Enum)]
#[ttlv(enum, tag = 0x420040)]
enum Color {
    Red = 0x01,
    Green = 0x02,
    Blue = 0x03,
}

#[test]
fn test_enum_roundtrip() {
    for color in [Color::Red, Color::Green, Color::Blue] {
        let mut enc = TtlvEncoder::new();
        color.encode(&mut enc);

        let mut dec = TtlvDecoder::new(enc.bytes());
        let decoded = Color::decode(&mut dec).unwrap();

        assert_eq!(color, decoded);
    }
}

// -- TTLV enum with default variant --

#[derive(Debug, PartialEq, Encodable, Decodable, Enum)]
#[ttlv(enum, tag = 0x420050)]
#[repr(u32)]
enum Status {
    Active = 0x01,
    Inactive = 0x02,
    #[ttlv(default)]
    Unknown(RawTag),
}

#[test]
fn test_enum_known_variant_roundtrip() {
    let original = Status::Active;

    let mut enc = TtlvEncoder::new();
    original.encode(&mut enc);

    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded = Status::decode(&mut dec).unwrap();

    assert_eq!(original, decoded);
}

#[test]
fn test_enum_unknown_variant_decoded_to_default() {
    // Manually encode an unknown enum value (0xFF) at tag 0x420050
    let mut enc = TtlvEncoder::new();
    enc.write_enum(0x420050, 0xFFu32);

    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded = Status::decode(&mut dec).unwrap();

    match decoded {
        Status::Unknown(raw) => assert_eq!(raw.numeric(), Some(0xFF)),
        other => panic!("Expected Unknown variant, got {other:?}"),
    }
}

// -- Struct with skipped field --

#[derive(Debug, PartialEq, Encodable, Decodable)]
#[ttlv(tag = 0x420060)]
struct WithSkip {
    #[ttlv(tag = 0x420061)]
    kept: i32,
    #[ttlv(skip)]
    skipped: String,
}

#[test]
fn test_skipped_field_uses_default() {
    let original = WithSkip {
        kept: 7,
        skipped: "this won't be encoded".into(),
    };

    let mut enc = TtlvEncoder::new();
    original.encode(&mut enc);

    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded = WithSkip::decode(&mut dec).unwrap();

    assert_eq!(decoded.kept, 7);
    assert_eq!(decoded.skipped, String::default());
}

// -- Struct with enum field --

#[derive(Debug, PartialEq, Encodable, Decodable)]
#[ttlv(tag = 0x420070)]
struct WithEnum {
    #[ttlv(tag = 0x420040)]
    color: Color,
    #[ttlv(tag = 0x420071)]
    count: i32,
}

#[test]
fn test_struct_with_enum_field_roundtrip() {
    let original = WithEnum {
        color: Color::Blue,
        count: 3,
    };

    let mut enc = TtlvEncoder::new();
    original.encode(&mut enc);

    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded = WithEnum::decode(&mut dec).unwrap();

    assert_eq!(original, decoded);
}

// -- Vec field round-trip --

#[derive(Debug, PartialEq, Encodable, Decodable)]
#[ttlv(tag = 0x420080)]
struct WithVec {
    #[ttlv(tag = 0x420010)]
    items: Vec<Inner>,
}

#[test]
fn test_vec_field_roundtrip() {
    let original = WithVec {
        items: vec![Inner { x: 1 }, Inner { x: 2 }, Inner { x: 3 }],
    };

    let mut enc = TtlvEncoder::new();
    original.encode(&mut enc);

    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded = WithVec::decode(&mut dec).unwrap();

    assert_eq!(original, decoded);
}

#[test]
fn test_empty_vec_roundtrip() {
    let original = WithVec { items: vec![] };

    let mut enc = TtlvEncoder::new();
    original.encode(&mut enc);

    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded = WithVec::decode(&mut dec).unwrap();

    assert_eq!(original, decoded);
}

// -- Field-level `#[ttlv(flatten)]` round-trip --
// Inlines the inner struct's fields into the outer's TTLV body, without
// emitting a nested struct wrapper for the inner.

#[derive(Debug, PartialEq, Encodable, Decodable)]
#[ttlv(tag = 0x420090)]
struct FlattenedInner {
    #[ttlv(tag = 0x420091)]
    a: i32,
    #[ttlv(tag = 0x420092)]
    b: String,
}

#[derive(Debug, PartialEq, Encodable, Decodable)]
#[ttlv(tag = 0x420093)]
struct FlattenedOuter {
    #[ttlv(flatten)]
    inner: FlattenedInner,
    #[ttlv(tag = 0x420094)]
    extra: i32,
}

#[test]
fn test_field_flatten_roundtrip() {
    let original = FlattenedOuter {
        inner: FlattenedInner {
            a: 7,
            b: "flat".into(),
        },
        extra: 42,
    };

    let mut enc = TtlvEncoder::new();
    original.encode(&mut enc);

    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded = FlattenedOuter::decode(&mut dec).unwrap();

    assert_eq!(original, decoded);
}
