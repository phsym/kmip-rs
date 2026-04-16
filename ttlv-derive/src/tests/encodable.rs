//! Tests for `#[derive(Encodable)]`.
//!
//! Each test provides a `parse_quote!` input and an expected `TokenStream` output,
//! verifying that the generated code matches exactly. This pins the output so that
//! any refactoring that accidentally changes generated code is caught.

use proc_macro2::TokenStream as TokenStream2;
use syn::parse_quote;

use crate::derive_encodable_fn2;

// --- Struct ---

/// Basic struct with a tag: generates inner_encode + TagEncodable + flatten_encode + Encodable.
#[test]
fn test_struct_unit() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(tag = Tag::MyTag)]
        struct Toto;
    };
    let expected: TokenStream2 = parse_quote! {
        impl Toto {
            fn inner_encode(&self, e: &mut impl ::ttlv::Encoder) {
                match self {
                    Self {} => {}
                }
            }
        }
        impl ::ttlv::TagEncodable for Toto {
            fn encode<E: ::ttlv::Encoder>(&self, tag: impl ::ttlv::Tag, encoder: &mut E) {
                use ::ttlv::Encoder;
                encoder.write_struct(tag, |e| {
                    self.flatten_encode(e);
                });
            }
        }
        impl Toto {
            pub fn flatten_encode<E: ::ttlv::Encoder>(&self, e: &mut E) {
                self.inner_encode(e)
            }
        }
        impl ::ttlv::Encodable for Toto {
            fn encode(&self, encoder: &mut impl ::ttlv::Encoder) {
                encoder.tag_encode(Tag::MyTag, self);
            }
        }
    };

    let output = derive_encodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// Named fields with per-field `tag` attribute: verifies field destructuring and tagged encoding.
fn test_struct_named() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(tag = Tag::MyTag)]
        struct Toto{
            field1: u32,
            #[ttlv(tag = 42)]
            field2: string,
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl Toto {
            fn inner_encode(&self, e: &mut impl ::ttlv::Encoder) {
                match self {
                    Self {
                        field1: _field1,
                        field2: _field2
                    } => {
                        e.encode(_field1);
                        e.tag_encode(42, _field2)
                    }
                }
            }
        }
        impl ::ttlv::TagEncodable for Toto {
            fn encode<E: ::ttlv::Encoder>(&self, tag: impl ::ttlv::Tag, encoder: &mut E) {
                use ::ttlv::Encoder;
                encoder.write_struct(tag, |e| {
                    self.flatten_encode(e);
                });
            }
        }
        impl Toto {
            pub fn flatten_encode<E: ::ttlv::Encoder>(&self, e: &mut E) {
                self.inner_encode(e)
            }
        }
        impl ::ttlv::Encodable for Toto {
            fn encode(&self, encoder: &mut impl ::ttlv::Encoder) {
                encoder.tag_encode(Tag::MyTag, self);
            }
        }
    };

    let output = derive_encodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// Tuple struct: verifies index-based field access (0, 1) instead of named fields.
fn test_struct_unnamed() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(tag = Tag::MyTag)]
        struct Toto(u32, #[ttlv(tag = 42)] string);
    };
    let expected: TokenStream2 = parse_quote! {
        impl Toto {
            fn inner_encode(&self, e: &mut impl ::ttlv::Encoder) {
                match self {
                    Self { 0: _0, 1: _1 } => {
                        e.encode(_0);
                        e.tag_encode(42, _1)
                    }
                }
            }
        }
        impl ::ttlv::TagEncodable for Toto {
            fn encode<E: ::ttlv::Encoder>(&self, tag: impl ::ttlv::Tag, encoder: &mut E) {
                use ::ttlv::Encoder;
                encoder.write_struct(tag, |e| {
                    self.flatten_encode(e);
                });
            }
        }
        impl Toto {
            pub fn flatten_encode<E: ::ttlv::Encoder>(&self, e: &mut E) {
                self.inner_encode(e)
            }
        }
        impl ::ttlv::Encodable for Toto {
            fn encode(&self, encoder: &mut impl ::ttlv::Encoder) {
                encoder.tag_encode(Tag::MyTag, self);
            }
        }
    };

    let output = derive_encodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// Flattened struct: generates Encodable (no TagEncodable, no flatten_encode).
/// Fields are encoded inline without a wrapping TTLV struct.
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
        impl Toto {
            fn inner_encode(&self, e: &mut impl ::ttlv::Encoder) {
                match self {
                    Self {
                        field1: _field1,
                        field2: _field2
                    } => {
                        e.encode(_field1);
                        e.tag_encode(42, _field2)
                    }
                }
            }
        }
        impl ::ttlv::Encodable for Toto {
            fn encode(&self, encoder: &mut impl ::ttlv::Encoder) {
                self.inner_encode(encoder);
            }
        }
    };

    let output = derive_encodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// Skipped field: still appears in destructuring pattern but produces no encode call.
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
        impl Toto {
            fn inner_encode(&self, e: &mut impl ::ttlv::Encoder) {
                match self {
                    Self {
                        field1: _field1,
                        field2: _field2
                    } => {
                        e.encode(_field1)
                    }
                }
            }
        }
        impl ::ttlv::TagEncodable for Toto {
            fn encode<E: ::ttlv::Encoder>(&self, tag: impl ::ttlv::Tag, encoder: &mut E) {
                use ::ttlv::Encoder;
                encoder.write_struct(tag, |e| {
                    self.flatten_encode(e);
                });
            }
        }
        impl Toto {
            pub fn flatten_encode<E: ::ttlv::Encoder>(&self, e: &mut E) {
                self.inner_encode(e)
            }
        }
        impl ::ttlv::Encodable for Toto {
            fn encode(&self, encoder: &mut impl ::ttlv::Encoder) {
                encoder.tag_encode(Tag::MyTag, self);
            }
        }
    };

    let output = derive_encodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// Extensions integration: `set_ext` stores value in extensions *before* encoding,
/// `if(expr)` conditionally encodes based on extension state.
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
        impl Toto {
            fn inner_encode(&self, e: &mut impl ::ttlv::Encoder) {
                match self {
                    Self {
                        field1: _field1,
                        field2: _field2
                    } => {
                        e.extensions().insert(_field1.clone());
                        e.encode(_field1);
                        {
                            use ::ttlv::ExtensionsExt;
                            let _ext = e.extensions();
                            if _ext.check() {
                                e.tag_encode(42, _field2);
                            }
                        }
                    }
                }
            }
        }
        impl ::ttlv::TagEncodable for Toto {
            fn encode<E: ::ttlv::Encoder>(&self, tag: impl ::ttlv::Tag, encoder: &mut E) {
                use ::ttlv::Encoder;
                encoder.write_struct(tag, |e| {
                    self.flatten_encode(e);
                });
            }
        }
        impl Toto {
            pub fn flatten_encode<E: ::ttlv::Encoder>(&self, e: &mut E) {
                self.inner_encode(e)
            }
        }
        impl ::ttlv::Encodable for Toto {
            fn encode(&self, encoder: &mut impl ::ttlv::Encoder) {
                encoder.tag_encode(Tag::MyTag, self);
            }
        }
    };

    let output = derive_encodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

// --- Enum (struct-like) ---
// These enums don't have `#[ttlv(enum)]` — they're treated as tagged unions where
// each variant is encoded like a struct.

/// Struct-like enum with a tag: each variant gets an inner_encode match arm.
#[test]
fn test_tagged_enum() {
    let source = parse_quote! {
        #[ttlv(tag = Tag::MyTag)]
        enum Toto {
            Test1 = 1,
            Test2= 12
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl Toto {
            fn inner_encode(&self, e: &mut impl ::ttlv::Encoder) {
                match self {
                    Self::Test1 {} => {},
                    Self::Test2 {} => {}
                };
            }
        }
        impl ::ttlv::TagEncodable for Toto {
            fn encode<E: ::ttlv::Encoder>(&self, tag: impl ::ttlv::Tag, encoder: &mut E) {
                use ::ttlv::Encoder;
                encoder.write_struct(tag, |e| {
                    self.flatten_encode(e);
                });
            }
        }
        impl Toto {
            pub fn flatten_encode<E: ::ttlv::Encoder>(&self, e: &mut E) {
                self.inner_encode(e)
            }
        }
        impl ::ttlv::Encodable for Toto {
            fn encode(&self, encoder: &mut impl ::ttlv::Encoder) {
                encoder.tag_encode(Tag::MyTag, self);
            }
        }
    };

    let output = derive_encodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// Struct-like enum without tag: generates TagEncodable but no Encodable.
fn test_untagged_enum() {
    let source: TokenStream2 = parse_quote! {
        enum Toto {
            Test1 = 1,
            Test2= 12
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl Toto {
            fn inner_encode(&self, e: &mut impl ::ttlv::Encoder) {
                match self {
                    Self::Test1 {} => {},
                    Self::Test2 {} => {}
                };
            }
        }
        impl ::ttlv::TagEncodable for Toto {
            fn encode<E: ::ttlv::Encoder>(&self, tag: impl ::ttlv::Tag, encoder: &mut E) {
                use ::ttlv::Encoder;
                encoder.write_struct(tag, |e| {
                    self.flatten_encode(e);
                });
            }
        }
        impl Toto {
            pub fn flatten_encode<E: ::ttlv::Encoder>(&self, e: &mut E) {
                self.inner_encode(e)
            }
        }
    };

    let output = derive_encodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// Flattened struct-like enum: generates Encodable (no TagEncodable).
/// Each variant's fields are encoded inline.
fn test_flatten_enum() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(flatten)]
        enum Toto {
            Test1(#[ttlv(tag = 1)] u32),
            Test2(#[ttlv(tag = 2)] String),
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl Toto {
            fn inner_encode(&self, e: &mut impl ::ttlv::Encoder) {
                match self {
                    Self::Test1 { 0: _0 } => {
                        e.tag_encode(1, _0)
                    },
                    Self::Test2 { 0: _0 } => {
                        e.tag_encode(2, _0)
                    }
                };
            }
        }
        impl ::ttlv::Encodable for Toto {
            fn encode(&self, encoder: &mut impl ::ttlv::Encoder) {
                self.inner_encode(encoder);
            }
        }
    };

    let output = derive_encodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

// --- Enum (TTLV) ---
// These enums have `#[ttlv(enum)]` — they represent TTLV Enumeration values,
// where each variant maps to a numeric discriminant written via `write_enum()`.

/// TTLV enum: variants map to (discriminant, name) tuples for write_enum().
#[test]
fn test_ttlv_enum() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(enum, tag = Tags::MyTag)]
        enum Toto {
            Test1 = 1,
            Test2 = 12,
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl ::ttlv::TagEncodable for Toto {
            fn encode<E: ::ttlv::Encoder>(&self, tag: impl ::ttlv::Tag, encoder: &mut E) {
                let value = match self {
                    Self::Test1 => (1, ::std::stringify!(Test1)),
                    Self::Test2 => (12, ::std::stringify!(Test2))
                };
                encoder.write_enum(tag, value);
            }
        }
        impl ::ttlv::Encodable for Toto {
            fn encode(&self, encoder: &mut impl ::ttlv::Encoder) {
                encoder.tag_encode(Tags::MyTag, self);
            }
        }
    };

    let output = derive_encodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// TTLV enum with `#[ttlv(default)]` catch-all and `#[ttlv(rename)]` override.
/// Default variant short-circuits with `return encoder.write_enum(tag, value)`.
fn test_ttlv_enum_with_default_and_rename() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(enum, tag = Tags::MyTag)]
        enum Toto {
            Test1 = 1,
            #[ttlv(rename = "foo")]
            Test2 = 12,
            #[ttlv(default)]
            Unknown(RawTag),
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl ::ttlv::TagEncodable for Toto {
            fn encode<E: ::ttlv::Encoder>(&self, tag: impl ::ttlv::Tag, encoder: &mut E) {
                let value = match self {
                    Self::Test1 => (1, ::std::stringify!(Test1)),
                    Self::Test2 => (12, "foo"),
                    Self::Unknown(value) => return encoder.write_enum(tag, value)
                };
                encoder.write_enum(tag, value);
            }
        }
        impl ::ttlv::Encodable for Toto {
            fn encode(&self, encoder: &mut impl ::ttlv::Encoder) {
                encoder.tag_encode(Tags::MyTag, self);
            }
        }
    };

    let output = derive_encodable_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}
