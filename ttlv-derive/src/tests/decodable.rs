//! Tests for `#[derive(Decodable)]`.

use proc_macro2::TokenStream as TokenStream2;
use syn::parse_quote;

use crate::derive_decodable_fn2;

// --- Struct ---

/// Basic struct with a tag: generates TagDecodable + flatten_decode + Decodable.
#[test]
fn test_struct_unit() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(tag = Tag::MyTag)]
        struct Toto;
    };
    let expected: TokenStream2 = parse_quote! {
        impl ::ttlv::TagDecodable for Toto {
            fn decode<D: ::ttlv::Decoder>(
                tag: impl ::ttlv::Tag,
                decoder: &mut D
            ) -> ::ttlv::Result<Self> {
                use ::ttlv::Decoder;
                decoder.read_struct(tag, |d| { Self::flatten_decode(d) })
            }
        }
        impl Toto {
            pub fn flatten_decode<D: ::ttlv::Decoder>(d: &mut D) -> ::ttlv::Result<Self> {
                let res = Self {};
                Ok(res)
            }
        }
        impl ::ttlv::Decodable for Toto {
            fn decode(decoder: &mut impl ::ttlv::Decoder) -> ::ttlv::Result<Self> {
                decoder.tag_decode(Tag::MyTag)
            }
        }
    };

    let output = derive_decodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// Named fields: each field decoded in order via `d.decode()` or `d.tag_decode()`.
fn test_struct_named() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(tag = Tag::MyTag)]
        struct Toto{
            field1: u32,
            #[ttlv(tag = 42)]
            field2: String,
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl ::ttlv::TagDecodable for Toto {
            fn decode<D: ::ttlv::Decoder>(
                tag: impl ::ttlv::Tag,
                decoder: &mut D
            ) -> ::ttlv::Result<Self> {
                use ::ttlv::Decoder;
                decoder.read_struct(tag, |d| { Self::flatten_decode(d) })
            }
        }
        impl Toto {
            pub fn flatten_decode<D: ::ttlv::Decoder>(d: &mut D) -> ::ttlv::Result<Self> {
                let _field1: u32 = d.decode()? ;
                let _field2: String = d.tag_decode(42)? ;
                let res = Self {
                    field1: _field1,
                    field2: _field2
                };
                Ok(res)
            }
        }
        impl ::ttlv::Decodable for Toto {
            fn decode(decoder: &mut impl ::ttlv::Decoder) -> ::ttlv::Result<Self> {
                decoder.tag_decode(Tag::MyTag)
            }
        }
    };

    let output = derive_decodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// Tuple struct: verifies index-based field names (_0, _1) in decode.
fn test_struct_unnamed() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(tag = Tag::MyTag)]
        struct Toto(u32, #[ttlv(tag = 42)] String);
    };
    let expected: TokenStream2 = parse_quote! {
        impl ::ttlv::TagDecodable for Toto {
            fn decode<D: ::ttlv::Decoder>(tag: impl ::ttlv::Tag, decoder: &mut D) -> ::ttlv::Result<Self> {
                use ::ttlv::Decoder;
                decoder.read_struct(tag, |d| { Self::flatten_decode(d) })
            }
        }
        impl Toto {
            pub fn flatten_decode<D: ::ttlv::Decoder>(d: &mut D) -> ::ttlv::Result<Self> {
                let _0: u32 = d.decode()? ;
                let _1: String = d.tag_decode(42)? ;
                let res = Self { 0: _0, 1: _1 };
                Ok(res)
            }
        }
        impl ::ttlv::Decodable for Toto {
            fn decode(decoder: &mut impl ::ttlv::Decoder) -> ::ttlv::Result<Self> {
                decoder.tag_decode(Tag::MyTag)
            }
        }
    };

    let output = derive_decodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// Flattened struct: generates only Decodable (no TagDecodable, no flatten_decode).
fn test_struct_flatten() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(flatten)]
        struct Toto {
            field1: u32,
            #[ttlv(tag = 42)]
            field2: String,
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl ::ttlv::Decodable for Toto {
            fn decode(d: &mut impl ::ttlv::Decoder) -> ::ttlv::Result<Self> {
                let _field1: u32 = d.decode()?;
                let _field2: String = d.tag_decode(42)?;
                let res = Self {
                    field1: _field1,
                    field2: _field2
                };
                Ok(res)
            }
        }
    };

    let output = derive_decodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// Skipped field: uses `Default::default()` in the constructor, no decode call.
fn test_struct_skip() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(tag = Tag::MyTag)]
        struct Toto {
            field1: u32,
            #[ttlv(skip)]
            field2: String,
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl ::ttlv::TagDecodable for Toto {
            fn decode<D: ::ttlv::Decoder>(tag: impl ::ttlv::Tag, decoder: &mut D) -> ::ttlv::Result<Self> {
                use ::ttlv::Decoder;
                decoder.read_struct(tag, |d| { Self::flatten_decode(d) })
            }
        }
        impl Toto {
            pub fn flatten_decode<D: ::ttlv::Decoder>(d: &mut D) -> ::ttlv::Result<Self> {
                let _field1: u32 = d.decode()?;
                let res = Self {
                    field1: _field1,
                    field2: Default::default()
                };
                Ok(res)
            }
        }
        impl ::ttlv::Decodable for Toto {
            fn decode(decoder: &mut impl ::ttlv::Decoder) -> ::ttlv::Result<Self> {
                decoder.tag_decode(Tag::MyTag)
            }
        }
    };

    let output = derive_decodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// Extensions integration: `set_ext` stores value *after* decoding (opposite of encode),
/// `if(expr)` wraps decode in if/else with `Default::default()` fallback.
fn test_struct_set_ext_and_if() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(tag = Tag::MyTag)]
        struct Toto {
            #[ttlv(set_ext)]
            field1: u32,
            #[ttlv(tag = 42, if(_ext.check()))]
            field2: String,
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl ::ttlv::TagDecodable for Toto {
            fn decode<D: ::ttlv::Decoder>(tag: impl ::ttlv::Tag, decoder: &mut D) -> ::ttlv::Result<Self> {
                use ::ttlv::Decoder;
                decoder.read_struct(tag, |d| { Self::flatten_decode(d) })
            }
        }
        impl Toto {
            pub fn flatten_decode<D: ::ttlv::Decoder>(d: &mut D) -> ::ttlv::Result<Self> {
                let _field1: u32 = d.decode()?;
                d.extensions().insert(_field1.clone());;
                let _field2 = {
                    use ::ttlv::ExtensionsExt;
                    let _ext = d.extensions();
                    if _ext.check() {
                        let _field2: String = d.tag_decode(42)?;
                        _field2
                    } else {
                        Default::default()
                    }
                };;
                let res = Self {
                    field1: _field1,
                    field2: _field2
                };
                Ok(res)
            }
        }
        impl ::ttlv::Decodable for Toto {
            fn decode(decoder: &mut impl ::ttlv::Decoder) -> ::ttlv::Result<Self> {
                decoder.tag_decode(Tag::MyTag)
            }
        }
    };

    let output = derive_decodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

// --- Enum ---

/// TTLV enum decode: matches on (numeric, name) pairs with rename support.
/// Without a default variant, unknown values produce `Error::InvalidEnum`.
#[test]
fn test_enum() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(enum, tag = Tag::MyTag)]
        enum Toto {
            Test1 = 1,
            #[ttlv(rename = "foo")]
            Test2= 12
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl ::ttlv::TagDecodable for Toto {
            fn decode<D: ::ttlv::Decoder>(tag: impl ::ttlv::Tag, decoder: &mut D) -> ::ttlv::Result<Self> {
                use ::ttlv::Tag;
                let val = decoder.read_enum(&tag)? ;
                match (val.numeric(), val.name()) {
                    (Some(1), None) => Ok(Self::Test1),
                    (None | Some(1), Some(::std::stringify!(Test1))) => Ok(Self::Test1),
                    (Some(12), None) => Ok(Self::Test2),
                    (None | Some(12), Some("foo")) => Ok(Self::Test2),
                    _ => Err(::ttlv::Error::InvalidEnum {
                        tag: tag.raw().to_owned(),
                        value: val.raw().to_owned()
                    })
                }
            }
        }
        impl ::ttlv::Decodable for Toto {
            fn decode(decoder: &mut impl ::ttlv::Decoder) -> ::ttlv::Result<Self> {
                decoder.tag_decode(Tag::MyTag)
            }
        }
    };

    let output = derive_decodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// TTLV enum with `#[ttlv(default)]`: unknown values are captured in the catch-all variant
/// instead of returning an error.
fn test_enum_with_default() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(enum, tag = Tag::MyTag)]
        enum Toto {
            Test1 = 1,
            #[ttlv(rename = "foo")]
            Test2= 12,
            #[ttlv(default)]
            Unknown(Foo)
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl ::ttlv::TagDecodable for Toto {
            fn decode<D: ::ttlv::Decoder>(tag: impl ::ttlv::Tag, decoder: &mut D) -> ::ttlv::Result<Self> {
                use ::ttlv::Tag;
                let val = decoder.read_enum(&tag)? ;
                match (val.numeric(), val.name()) {
                    (Some(1), None) => Ok(Self::Test1),
                    (None | Some(1), Some(::std::stringify!(Test1))) => Ok(Self::Test1),
                    (Some(12), None) => Ok(Self::Test2),
                    (None | Some(12), Some("foo")) => Ok(Self::Test2),
                    _ => Ok(Self::Unknown(val.raw().to_owned()))
                }
            }
        }
        impl ::ttlv::Decodable for Toto {
            fn decode(decoder: &mut impl ::ttlv::Decoder) -> ::ttlv::Result<Self> {
                decoder.tag_decode(Tag::MyTag)
            }
        }
    };

    let output = derive_decodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}
