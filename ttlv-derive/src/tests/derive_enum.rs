//! Tests for `#[derive(Enum)]`.

use proc_macro2::TokenStream as TokenStream2;
use syn::parse_quote;

use crate::derive_enum_fn2;

/// Basic Enum derive with rename: generates name() and Display.
/// Renamed variant uses the literal string instead of stringify!().
#[test]
fn test_basic() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(enum)]
        enum Toto {
            Test1 = 1,
            #[ttlv(rename = "foo")]
            Test2 = 12,
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl Toto {
            pub fn name(&self) -> &str {
                match self {
                    Self::Test1 => ::std::stringify!(Test1),
                    Self::Test2 => "foo",
                }
            }
        }
        impl ::std::fmt::Display for Toto {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                self.name().fmt(f)
            }
        }
    };

    let output = derive_enum_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}

#[test]
/// Enum with `#[ttlv(default)]` catch-all: the default variant delegates to
/// `value.name().unwrap_or("Unknown")` since its inner value implements `Tag`.
fn test_with_default() {
    let source: TokenStream2 = parse_quote! {
        #[ttlv(enum)]
        enum Toto {
            Test1 = 1,
            #[ttlv(default)]
            Unknown(RawTag),
        }
    };
    let expected: TokenStream2 = parse_quote! {
        impl Toto {
            pub fn name(&self) -> &str {
                match self {
                    Self::Test1 => ::std::stringify!(Test1),
                    Self::Unknown(value) => value.name().unwrap_or("Unknown"),
                }
            }
        }
        impl ::std::fmt::Display for Toto {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                self.name().fmt(f)
            }
        }
    };

    let output = derive_enum_fn2(source).unwrap();
    assert_eq!(expected.to_string(), output.to_string())
}
