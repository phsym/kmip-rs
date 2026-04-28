//! Cross-cutting round-trip and integration tests.
//!
//! Exercises encode/decode pairs through every codec (binary, XML, text) and
//! every blanket impl (`Option<T>`, `Vec<T>`, `Box<T>`) so the trait machinery
//! gets traversed end-to-end. Complements the per-module unit tests by
//! covering paths that only fire when an `Encodable` value actually flows
//! through an encoder.

use ttlv::{
    BigInteger, Decodable, Decoder, Encodable, Encoder, Error, MaybeKnownTag, RawTag, RawTagRef,
    Struct, TTLV, Tag, TagDecodable, TagEncodable, TextEncoder, TtlvDecoder, TtlvEncoder, Type,
    Value, XmlDecoder, XmlEncoder,
};

// =============================================================================
// Value / TTLV round-trips through every codec
// =============================================================================

fn ttlv_roundtrip<T: Encodable + Decodable>(v: &T) -> T {
    let mut enc = TtlvEncoder::new();
    v.encode(&mut enc).unwrap();
    let bytes = enc.into_inner();
    let mut dec = TtlvDecoder::new(&bytes);
    T::decode(&mut dec).unwrap()
}

fn make_value(v: Value<RawTag>) -> TTLV<RawTag> {
    TTLV {
        tag: RawTag::Num(0x420020),
        val: v,
    }
}

#[test]
fn test_value_integer_roundtrip() {
    let item = make_value(Value::Integer(42));
    assert_eq!(ttlv_roundtrip(&item), item);
}

#[test]
fn test_value_long_integer_roundtrip() {
    let item = make_value(Value::LongInteger(i64::MAX));
    assert_eq!(ttlv_roundtrip(&item), item);
}

#[test]
fn test_value_big_integer_roundtrip() {
    // Use an 8-byte-aligned value so encode adds no padding.
    let item = make_value(Value::BigInteger(vec![0, 0, 0, 0, 0, 0, 0, 0x42]));
    assert_eq!(ttlv_roundtrip(&item), item);
}

#[test]
fn test_value_enum_roundtrip() {
    let item = make_value(Value::Enum(RawTag::Num(7)));
    assert_eq!(ttlv_roundtrip(&item), item);
}

#[test]
fn test_value_boolean_roundtrip() {
    for b in [true, false] {
        let item = make_value(Value::Boolean(b));
        assert_eq!(ttlv_roundtrip(&item), item);
    }
}

#[test]
fn test_value_text_string_roundtrip() {
    let item = make_value(Value::TextString("hello".into()));
    assert_eq!(ttlv_roundtrip(&item), item);
}

#[test]
fn test_value_byte_string_roundtrip() {
    let item = make_value(Value::ByteString(vec![0x01, 0x02, 0x03]));
    assert_eq!(ttlv_roundtrip(&item), item);
}

#[test]
fn test_value_datetime_roundtrip() {
    let item = make_value(Value::DateTime(1_205_495_800));
    assert_eq!(ttlv_roundtrip(&item), item);
}

#[test]
fn test_value_interval_roundtrip() {
    let item = make_value(Value::Interval(3600));
    assert_eq!(ttlv_roundtrip(&item), item);
}

#[test]
fn test_value_structure_roundtrip() {
    // Nested structure with multiple value types — exercises Value::encode for
    // Structure, the Struct TagEncodable, and Value::decode for Structure.
    let inner = Struct(vec![
        TTLV {
            tag: RawTag::Num(0x420001),
            val: Value::Integer(1),
        },
        TTLV {
            tag: RawTag::Num(0x420002),
            val: Value::Boolean(true),
        },
    ]);
    let item = make_value(Value::Structure(inner));
    assert_eq!(ttlv_roundtrip(&item), item);
}

#[test]
fn test_ttlv_get_type_after_decode() {
    let item = make_value(Value::Integer(5));
    let decoded = ttlv_roundtrip(&item);
    assert_eq!(decoded.get_type(), Type::Integer);
}

// =============================================================================
// Option / Vec / Box Encodable blanket impls
// =============================================================================

#[derive(Debug, PartialEq, Encodable, Decodable)]
#[ttlv(tag = 0x420001)]
struct Wrap {
    #[ttlv(tag = 0x420002)]
    n: i32,
}

#[test]
fn test_option_encodable_some() {
    let v: Option<Wrap> = Some(Wrap { n: 7 });
    let mut enc = TtlvEncoder::new();
    Encodable::encode(&v, &mut enc).unwrap();

    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded = <Wrap as Decodable>::decode(&mut dec).unwrap();
    assert_eq!(decoded, Wrap { n: 7 });
}

#[test]
fn test_option_encodable_none_emits_nothing() {
    let v: Option<Wrap> = None;
    let mut enc = TtlvEncoder::new();
    Encodable::encode(&v, &mut enc).unwrap();
    assert!(enc.bytes().is_empty());
}

#[test]
fn test_option_tag_encodable_none() {
    let v: Option<i32> = None;
    let mut enc = TtlvEncoder::new();
    TagEncodable::encode(&v, 0x420001u32, &mut enc).unwrap();
    assert!(enc.bytes().is_empty());
}

#[test]
fn test_option_tag_encodable_some() {
    let v: Option<i32> = Some(42);
    let mut enc = TtlvEncoder::new();
    TagEncodable::encode(&v, 0x420001u32, &mut enc).unwrap();
    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded: i32 = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
    assert_eq!(decoded, 42);
}

#[test]
fn test_vec_encodable_iterates() {
    let items: Vec<Wrap> = vec![Wrap { n: 1 }, Wrap { n: 2 }];
    let mut enc = TtlvEncoder::new();
    Encodable::encode(&items, &mut enc).unwrap();

    let bytes = enc.into_inner();
    let mut dec = TtlvDecoder::new(&bytes);
    let decoded: Vec<Wrap> = Decodable::decode(&mut dec).unwrap();
    assert_eq!(decoded, items);
}

#[test]
fn test_vec_tag_encodable_iterates() {
    let items: Vec<i32> = vec![1, 2, 3];
    let mut enc = TtlvEncoder::new();
    TagEncodable::encode(&items, 0x420001u32, &mut enc).unwrap();

    let bytes = enc.into_inner();
    let mut dec = TtlvDecoder::new(&bytes);
    let decoded: Vec<i32> = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
    assert_eq!(decoded, items);
}

#[test]
fn test_box_encodable() {
    let v: Box<Wrap> = Box::new(Wrap { n: 99 });
    let mut enc = TtlvEncoder::new();
    Encodable::encode(&v, &mut enc).unwrap();
    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded: Box<Wrap> = Decodable::decode(&mut dec).unwrap();
    assert_eq!(decoded, v);
}

#[test]
fn test_box_tag_encodable() {
    let v: Box<i32> = Box::new(7);
    let mut enc = TtlvEncoder::new();
    TagEncodable::encode(&v, 0x420001u32, &mut enc).unwrap();
    let mut dec = TtlvDecoder::new(enc.bytes());
    let decoded: Box<i32> = TagDecodable::decode(0x420001u32, &mut dec).unwrap();
    assert_eq!(*decoded, 7);
}

// =============================================================================
// XmlEncoder integration — exercises encode_to_string, default, into_*, as_str,
// extensions, and the inner-error path in write_struct.
// =============================================================================

#[test]
fn test_xml_encoder_default_and_encode_to_string() {
    assert!(XmlEncoder::default().bytes().is_empty());
    let s = XmlEncoder::encode_to_string(&Wrap { n: 7 }).unwrap();
    // Outer Structure (no `type` attr — defaults to Structure) and inner Integer field.
    assert!(s.contains(r#"<TTLV tag="0x420001">"#));
    assert!(s.contains(r#"<TTLV type="Integer" tag="0x420002" value="7"/>"#));
    assert!(s.contains("</TTLV>"));
}

#[test]
fn test_xml_encoder_bytes_and_as_str() {
    let mut enc = XmlEncoder::new();
    enc.write_integer(0x420020u32, 5).unwrap();
    assert_eq!(enc.bytes(), enc.as_str().as_bytes());
    assert!(enc.as_str().contains("Integer"));
}

#[test]
fn test_xml_encoder_extensions() {
    let mut enc = XmlEncoder::new();
    enc.extensions().insert(42u32);
    assert_eq!(enc.extensions().get::<u32>(), Some(&42));
}

#[test]
fn test_xml_encoder_struct_inner_error_propagates() {
    // The closure inside write_struct fails with DateTimeOutOfRange;
    // the encoder must capture and surface it after the writer returns.
    let mut enc = XmlEncoder::new();
    let err = enc
        .write_struct(0x420020u32, |e| e.write_datetime(0x420001u32, i64::MAX))
        .unwrap_err();
    assert!(matches!(err, Error::DateTimeOutOfRange(_)));
}

#[test]
fn test_xml_encoder_full_value_set() {
    // Exercises write_long, write_bigint, write_bool, write_string, write_bytes,
    // write_datetime, write_interval, write_enum, write_bitmask through XML.
    let mut enc = XmlEncoder::new();
    enc.write_struct(0x420020u32, |e| {
        e.write_long(0x420001u32, 1234567890123)?;
        e.write_bigint(0x420002u32, [0x01, 0x02])?;
        e.write_bool(0x420003u32, true)?;
        e.write_string(0x420004u32, "hello")?;
        e.write_bytes(0x420005u32, [0xAB, 0xCD])?;
        e.write_datetime(0x420006u32, 1_205_495_800)?;
        e.write_interval(0x420007u32, 3600)?;
        e.write_enum(0x420008u32, 5u32)?;
        e.write_bitmask(0x420009u32, 0x01i32)?;
        Ok(())
    })
    .unwrap();
    let s = enc.into_string();
    for needle in [
        "LongInteger",
        "BigInteger",
        "Boolean",
        "TextString",
        "ByteString",
        "DateTime",
        "Interval",
        "Enumeration",
    ] {
        assert!(s.contains(needle), "missing {needle} in {s}");
    }
}

// =============================================================================
// XmlEncoder ↔ XmlDecoder round-trip — exercises Value::encode/decode through
// the XML codec, including the `read_bigint` path with an even-length hex value.
// =============================================================================

#[test]
fn test_xml_roundtrip_value_types() {
    let inner = Struct::<RawTag>(vec![
        TTLV {
            tag: RawTag::Num(0x420001),
            val: Value::LongInteger(42),
        },
        TTLV {
            tag: RawTag::Num(0x420002),
            val: Value::Boolean(false),
        },
        TTLV {
            tag: RawTag::Num(0x420003),
            val: Value::TextString("xml".into()),
        },
        TTLV {
            tag: RawTag::Num(0x420004),
            val: Value::ByteString(vec![0xDE, 0xAD]),
        },
        TTLV {
            tag: RawTag::Num(0x420005),
            val: Value::DateTime(1_205_495_800),
        },
        TTLV {
            tag: RawTag::Num(0x420006),
            val: Value::Interval(120),
        },
        TTLV {
            tag: RawTag::Num(0x420007),
            val: Value::Enum(RawTag::Num(2)),
        },
    ]);
    let item: TTLV<RawTag> = TTLV {
        tag: RawTag::Num(0x420020),
        val: Value::Structure(inner),
    };

    let mut enc = XmlEncoder::new();
    item.encode(&mut enc).unwrap();
    let bytes = enc.into_inner();

    let mut dec = XmlDecoder::new(&bytes).unwrap();
    let decoded: TTLV<RawTag> = TTLV::decode(&mut dec).unwrap();
    assert_eq!(decoded, item);
}

// =============================================================================
// TextEncoder integration
// =============================================================================

#[test]
fn test_text_encoder_encode_to_string() {
    let s = TextEncoder::encode_to_string(&Wrap { n: 7 }).unwrap();
    assert!(s.contains("Integer"));
}

#[test]
fn test_text_encoder_without_type() {
    let mut enc = TextEncoder::new().without_type(true);
    enc.write_integer(0x420020u32, 1).unwrap();
    let s = enc.into_string();
    assert!(!s.contains("(Integer)"));
}

#[test]
fn test_text_encoder_extensions() {
    let mut enc = TextEncoder::new();
    enc.extensions().insert(7u32);
    assert_eq!(enc.extensions().get::<u32>(), Some(&7));
}

#[test]
fn test_text_encoder_named_enum() {
    // Hits the `value.name() == Some(_)` branch in write_enum.
    let mut enc = TextEncoder::new();
    enc.write_enum(0x420020u32, "Active").unwrap();
    let s = enc.into_string();
    assert!(s.contains("Active"));
}

#[test]
fn test_text_encoder_interval_components() {
    // Various interval values to hit the days/hours/minutes branches in write_interval.
    let mut enc = TextEncoder::new();
    enc.write_interval(0x420020u32, 86400 + 3600 + 60 + 1)
        .unwrap(); // 1d1h1m1s
    let s = enc.into_string();
    assert!(s.contains("1d"));
    assert!(s.contains("1h"));
    assert!(s.contains("1m"));
    assert!(s.contains("1s"));
}

#[test]
fn test_text_encoder_interval_zero_seconds() {
    // Edge case: exactly zero — should still emit "0s".
    let mut enc = TextEncoder::new();
    enc.write_interval(0x420020u32, 0).unwrap();
    let s = enc.into_string();
    assert!(s.contains("0s"));
}

#[test]
fn test_text_encoder_interval_only_hours() {
    // Hits hours branch without days, minutes, or remainder seconds.
    let mut enc = TextEncoder::new();
    enc.write_interval(0x420020u32, 7200).unwrap(); // 2h
    let s = enc.into_string();
    assert!(s.contains("2h"));
}

// =============================================================================
// `bitmask!` macro integration — covers the BitflagMarker Bitmask impl in lib.rs.
// =============================================================================

ttlv::bitmask! {
    #[derive(Clone, Copy, PartialEq, Debug)]
    pub struct UsageMask: u32 {
        const Encrypt = 0x0000_0004;
        const Decrypt = 0x0000_0008;
    }
}

#[test]
fn test_bitmask_macro_encode_decode_roundtrip() {
    let mask = UsageMask::Encrypt | UsageMask::Decrypt;
    let mut enc = TtlvEncoder::new();
    mask.encode(0x420020u32, &mut enc).unwrap();
    let bytes = enc.into_inner();

    let mut dec = TtlvDecoder::new(&bytes);
    let decoded: UsageMask = TagDecodable::decode(0x420020u32, &mut dec).unwrap();
    assert_eq!(decoded, mask);
}

#[test]
fn test_bitmask_macro_units_iterates_named_and_unnamed() {
    use ttlv::{Bitmask, BitmaskUnit};
    // A mask combining a named flag and an unnamed bit.
    let mask = UsageMask::Encrypt | UsageMask::from_bits_retain(0x10);
    let units: Vec<_> = mask
        .units()
        .map(|u| match u {
            BitmaskUnit::Named(n) => format!("named:{n}"),
            BitmaskUnit::Unnamed(b) => format!("unnamed:{b:#X}"),
        })
        .collect();
    assert!(units.iter().any(|s| s.starts_with("named:")));
    assert!(units.iter().any(|s| s == "unnamed:0x10"));
}

#[test]
fn test_bitmask_macro_insert_named_unit() {
    use ttlv::{Bitmask, BitmaskUnit};
    let mut m = UsageMask::empty();
    m.insert_unit(BitmaskUnit::Named("Encrypt".into())).unwrap();
    assert!(m.contains(UsageMask::Encrypt));
}

#[test]
fn test_bitmask_macro_insert_unknown_named_returns_error() {
    use ttlv::{Bitmask, BitmaskUnit};
    let mut m = UsageMask::empty();
    let err = m
        .insert_unit(BitmaskUnit::Named("NoSuchFlag".into()))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidBitmaskValue(_)));
}

#[test]
fn test_bitmask_macro_value_and_empty() {
    use ttlv::Bitmask;
    let m = UsageMask::Encrypt;
    assert_eq!(m.value(), 0x04);
    let e = <UsageMask as Bitmask>::empty();
    assert_eq!(e.bits(), 0);
}

#[test]
fn test_bitmask_macro_display() {
    let m = UsageMask::Encrypt;
    let s = format!("{m}");
    assert_eq!(s, "Encrypt");
}

#[test]
fn test_bitmask_macro_xml_roundtrip() {
    // Encode through XML — exercises the named unit path in XmlDecoder::read_bitmask.
    let mask = UsageMask::Encrypt | UsageMask::Decrypt;
    let mut enc = XmlEncoder::new();
    mask.encode(0x420020u32, &mut enc).unwrap();
    let bytes = enc.into_inner();

    let mut dec = XmlDecoder::new(&bytes).unwrap();
    let decoded: UsageMask = TagDecodable::decode(0x420020u32, &mut dec).unwrap();
    assert_eq!(decoded, mask);
}

// =============================================================================
// MaybeKnownTag::try_from
// =============================================================================
//
// Build a custom tag type satisfying `Tag + TryFrom<RawTag, Error = Error>`,
// which is what `MaybeKnownTag<T>::try_from` needs.

#[derive(Debug, PartialEq)]
struct KnownTag(u32);

impl Tag for KnownTag {
    fn numeric(&self) -> Option<u32> {
        Some(self.0)
    }
    fn name(&self) -> Option<&str> {
        None
    }
}

impl TryFrom<RawTag> for KnownTag {
    type Error = Error;
    fn try_from(value: RawTag) -> Result<Self, Self::Error> {
        match value {
            RawTag::Num(n) | RawTag::NumStr(n, _) if n == 0x01 || n == 0x02 => Ok(KnownTag(n)),
            other => Err(Error::InvalidTag(other)),
        }
    }
}

#[test]
fn test_maybe_known_tag_try_from_known() {
    let raw = RawTag::Num(0x01);
    let mkt: MaybeKnownTag<KnownTag> = MaybeKnownTag::try_from(raw).unwrap();
    assert!(matches!(mkt, MaybeKnownTag::Known(KnownTag(0x01))));
}

#[test]
fn test_maybe_known_tag_try_from_unknown_falls_back() {
    let raw = RawTag::Num(0xDEAD);
    let mkt: MaybeKnownTag<KnownTag> = MaybeKnownTag::try_from(raw).unwrap();
    match mkt {
        MaybeKnownTag::Unknown(t) => assert_eq!(t.numeric(), Some(0xDEAD)),
        _ => panic!("expected Unknown"),
    }
}

#[test]
fn test_maybe_known_tag_try_from_propagates_other_errors() {
    // A KnownTag that surfaces a non-InvalidTag error should propagate.
    #[derive(Debug)]
    struct FailingTag;
    impl Tag for FailingTag {
        fn numeric(&self) -> Option<u32> {
            Some(0)
        }
        fn name(&self) -> Option<&str> {
            None
        }
    }
    impl TryFrom<RawTag> for FailingTag {
        type Error = Error;
        fn try_from(_: RawTag) -> Result<Self, Self::Error> {
            Err(Error::EOF)
        }
    }

    let err: Error = MaybeKnownTag::<FailingTag>::try_from(RawTag::Num(0x01)).unwrap_err();
    assert!(matches!(err, Error::EOF));
}

// =============================================================================
// RawTagRef::raw — the override that returns a clone instead of the
// (numeric, name) match in the trait default
// =============================================================================

#[test]
fn test_raw_tag_ref_raw_is_self_clone() {
    let r = RawTagRef::NumStr(0x42, "foo");
    assert_eq!(r.raw(), r);
}

// =============================================================================
// TtlvEncoder housekeeping: clear, into_inner
// =============================================================================

#[test]
fn test_ttlv_encoder_clear_resets_buffer_and_extensions() {
    let mut enc = TtlvEncoder::new();
    enc.write_integer(0x420001u32, 1).unwrap();
    enc.extensions().insert(7u32);
    assert!(!enc.bytes().is_empty());

    enc.clear();
    assert!(enc.bytes().is_empty());
    assert_eq!(enc.extensions().get::<u32>(), None);
}

#[test]
fn test_ttlv_encoder_into_inner() {
    let mut enc = TtlvEncoder::new();
    enc.write_integer(0x420001u32, 1).unwrap();
    let bytes = enc.into_inner();
    assert!(!bytes.is_empty());
}

// =============================================================================
// TtlvDecoder: extensions, InvalidTag, UnexpectedType, InvalidStruct propagation
// =============================================================================

#[test]
fn test_ttlv_decoder_extensions() {
    let bytes: Vec<u8> = Vec::new();
    let mut dec = TtlvDecoder::new(&bytes);
    dec.extensions().insert(99u32);
    assert_eq!(dec.extensions().get::<u32>(), Some(&99));
}

#[test]
fn test_ttlv_decoder_invalid_tag_high_byte() {
    // Tag high byte must be 0x42 or 0x54 — anything else is rejected.
    let bytes: Vec<u8> = vec![
        0x99, 0x00, 0x01, // bogus tag
        0x02, 0x00, 0x00, 0x00, 0x04, // type=Integer, len=4
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let dec = TtlvDecoder::new(&bytes);
    let err = dec.tag().unwrap_err();
    assert!(matches!(err, Error::InvalidTag(_)));
}

#[test]
fn test_ttlv_decoder_unexpected_type() {
    // Tag matches, but caller asks for the wrong type.
    let mut enc = TtlvEncoder::new();
    enc.write_bool(0x420001u32, true).unwrap();
    let bytes = enc.into_inner();
    let mut dec = TtlvDecoder::new(&bytes);
    let err = dec.read_integer(0x420001u32).unwrap_err();
    assert!(matches!(err, Error::UnexpectedType { .. }));
}

#[test]
fn test_ttlv_decoder_invalid_struct_propagates_inner_path() {
    // Inner decode produces an InvalidStruct error; the outer read_struct's
    // `e @ Err(Error::InvalidStruct(..)) => return e` arm passes it through
    // verbatim (no double-wrap).
    let mut enc = TtlvEncoder::new();
    enc.write_struct(0x420020u32, |e| {
        e.write_struct(0x420021u32, |e| e.write_integer(0x420022u32, 1))
    })
    .unwrap();
    let bytes = enc.into_inner();

    let mut dec = TtlvDecoder::new(&bytes);
    let err = dec
        .read_struct(0x420020u32, |d| {
            d.read_struct(0x420021u32, |d| d.read_bool(0x420022u32))
        })
        .unwrap_err();
    // Inner read_bool fails with UnexpectedType; middle read_struct wraps
    // that as InvalidStruct(0x420021, UnexpectedType). The outer read_struct
    // sees an InvalidStruct already and returns it without re-wrapping.
    match err {
        Error::InvalidStruct(tag, inner) => {
            assert_eq!(tag, RawTag::Num(0x420021));
            assert!(matches!(*inner, Error::UnexpectedType { .. }));
        }
        other => panic!("expected InvalidStruct, got {other:?}"),
    }
}

#[test]
fn test_ttlv_decoder_read_bitmask() {
    let mut enc = TtlvEncoder::new();
    enc.write_bitmask(0x420001u32, 0x05i32).unwrap();
    let bytes = enc.into_inner();

    let mut dec = TtlvDecoder::new(&bytes);
    let v: i32 = dec.read_bitmask(0x420001u32).unwrap();
    assert_eq!(v, 5);
}

// =============================================================================
// XmlDecoder.next() behaviour after EOF, get_end via Empty element
// =============================================================================

#[test]
fn test_xml_decoder_eof_after_end_returns_eof() {
    // After fully consuming the only element, asking for another item must EOF.
    let input = r#"<TestTag type="Integer" value="1"/>"#;
    let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
    dec.read_integer("TestTag").unwrap();
    let err = dec.read_integer("TestTag").unwrap_err();
    assert!(matches!(err, Error::EOF));
}

// =============================================================================
// XmlEncoder::write_enum with a named value
// =============================================================================

#[test]
fn test_xml_encoder_write_enum_named() {
    // The named-value branch of XmlEncoder::write_enum.
    let mut enc = XmlEncoder::new();
    enc.write_enum(0x420020u32, "Active").unwrap();
    let s = enc.into_string();
    assert!(s.contains("Active"));
}

// =============================================================================
// Option/Vec Decodable: error passthrough for non-EOF, non-UnexpectedTag errors
// =============================================================================

#[test]
fn test_option_tag_decodable_propagates_other_errors() {
    // Encode a Bool, ask for an Option<i32> at the matching tag → UnexpectedType
    // is not EOF/UnexpectedTag, so it must propagate.
    let mut enc = TtlvEncoder::new();
    enc.write_bool(0x420001u32, true).unwrap();
    let bytes = enc.into_inner();

    let mut dec = TtlvDecoder::new(&bytes);
    let err = <Option<i32> as TagDecodable>::decode(0x420001u32, &mut dec).unwrap_err();
    assert!(matches!(err, Error::UnexpectedType { .. }));
}

#[test]
fn test_option_decodable_propagates_other_errors() {
    // Encode a malformed message (invalid type byte 0xFF) → InvalidType propagates.
    let bytes: Vec<u8> = vec![
        0x42, 0x00, 0x01, // tag
        0xFF, // invalid type
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut dec = TtlvDecoder::new(&bytes);
    let err = <Option<TTLV<RawTag>> as Decodable>::decode(&mut dec).unwrap_err();
    assert!(matches!(err, Error::InvalidType(_)));
}

#[test]
fn test_vec_tag_decodable_propagates_other_errors() {
    let mut enc = TtlvEncoder::new();
    enc.write_bool(0x420001u32, true).unwrap();
    let bytes = enc.into_inner();

    let mut dec = TtlvDecoder::new(&bytes);
    let err = <Vec<i32> as TagDecodable>::decode(0x420001u32, &mut dec).unwrap_err();
    assert!(matches!(err, Error::UnexpectedType { .. }));
}

#[test]
fn test_vec_decodable_propagates_other_errors() {
    let bytes: Vec<u8> = vec![
        0x42, 0x00, 0x01, // tag
        0xFF, // invalid type
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut dec = TtlvDecoder::new(&bytes);
    let err = <Vec<TTLV<RawTag>> as Decodable>::decode(&mut dec).unwrap_err();
    assert!(matches!(err, Error::InvalidType(_)));
}

// =============================================================================
// XmlDecoder: extensions, InvalidStruct propagation
// =============================================================================

#[test]
fn test_xml_decoder_extensions() {
    let input = r#"<TestTag type="Integer" value="1"/>"#;
    let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
    dec.extensions().insert(99u32);
    assert_eq!(dec.extensions().get::<u32>(), Some(&99));
}

#[test]
fn test_xml_decoder_invalid_struct_propagates() {
    // Inner struct decode produces an InvalidStruct error; outer must
    // forward it without re-wrapping.
    let input = r#"<TTLV type="Structure" tag="0x420020">
    <TTLV type="Structure" tag="0x420021">
        <TTLV type="Integer" tag="0x420022" value="1"/>
    </TTLV>
</TTLV>"#;
    let mut dec = XmlDecoder::new(input.as_bytes()).unwrap();
    let err = dec
        .read_struct(0x420020u32, |d| {
            d.read_struct(0x420021u32, |d| d.read_bool(0x420022u32))
        })
        .unwrap_err();
    match err {
        Error::InvalidStruct(tag, inner) => {
            assert_eq!(tag, RawTag::Num(0x420021));
            assert!(matches!(*inner, Error::UnexpectedType { .. }));
        }
        other => panic!("expected InvalidStruct, got {other:?}"),
    }
}

// =============================================================================
// BigInteger in Value via XML — exercises Value::Structure containing a BigInt
// =============================================================================

#[test]
fn test_big_integer_via_value_xml_roundtrip() {
    // BigInteger::unsigned([0x80]) prepends a sign byte → [0, 0x80].
    // Encoding pads left to the 8-byte boundary → [0, 0, 0, 0, 0, 0, 0, 0x80].
    let bi = BigInteger::unsigned(vec![0x80]);
    let item: TTLV<RawTag> = TTLV {
        tag: RawTag::Num(0x420020),
        val: Value::BigInteger(bi.into_vec()),
    };
    let mut enc = XmlEncoder::new();
    item.encode(&mut enc).unwrap();
    let bytes = enc.into_inner();
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        r#"<TTLV type="BigInteger" tag="0x420020" value="0000000000000080"/>"#
    );

    let mut dec = XmlDecoder::new(&bytes).unwrap();
    let decoded: TTLV<RawTag> = TTLV::decode(&mut dec).unwrap();
    assert_eq!(decoded.tag, RawTag::Num(0x420020));
    assert_eq!(
        decoded.val,
        Value::BigInteger(vec![0, 0, 0, 0, 0, 0, 0, 0x80])
    );
}
