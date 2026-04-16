use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{DataEnum, Error, Fields, Ident, Result};

use crate::{AttrExt, EnumAttr, EnumEnumAttr};

pub fn derive_enum(en: DataEnum, ident: Ident, enum_attr: EnumAttr) -> Result<TokenStream2> {
    match enum_attr {
        EnumAttr::Enum(enum_attr) => derive_enum_enum(en, ident, enum_attr),
        EnumAttr::Struct(_) => Err(Error::new_spanned(&ident, "need the enum attribute")),
    }
}

fn derive_enum_enum(en: DataEnum, ident: Ident, enum_attr: EnumEnumAttr) -> Result<TokenStream2> {
    let mut branches = Vec::new();
    let mut default_branch = quote! {_ => Err(::ttlv::Error::InvalidEnum{tag: tag.raw().to_owned(), value: val.raw().to_owned()})};
    for var in en.variants {
        // Validate the attributes
        let attrs = var.attrs.get_attr()?.for_enum_variant()?;

        let vident = &var.ident;
        if attrs.default {
            default_branch = quote! { _ => Ok(Self::#vident(val.raw().to_owned()))}
        } else {
            if !matches!(var.fields, Fields::Unit) {
                return Err(Error::new_spanned(
                    &var.ident,
                    "Only unit fields are supported",
                ));
            }
            let disc = &var
                .discriminant
                .as_ref()
                .ok_or(Error::new_spanned(&var.ident, "Missing discriminant"))?
                .1;
            branches.push(quote! {(Some(#disc), None) => Ok(Self::#vident)});
            if let Some(rename) = attrs.rename {
                branches.push(quote! {(None|Some(#disc), Some(#rename)) => Ok(Self::#vident)});
            } else {
                branches
                    .push(quote! {(None|Some(#disc), Some(::std::stringify!(#vident))) => Ok(Self::#vident)});
            }
        }
    }

    let mut impls = vec![quote! {
        impl ::ttlv::TagDecodable for #ident {
            fn decode<D: ::ttlv::Decoder>(tag: impl ::ttlv::Tag, decoder: &mut D) -> ::ttlv::Result<Self> {
                use ::ttlv::Tag;
                let val = decoder.read_enum(&tag)?;
                match (val.numeric(), val.name()) {
                    #(#branches,) *
                    #default_branch
                }
            }
        }
    }];

    if let Some(tag) = enum_attr.tag {
        impls.push(quote! {
                impl ::ttlv::Decodable for #ident {
                    fn decode(decoder: &mut impl ::ttlv::Decoder) -> ::ttlv::Result<Self> {
                        decoder.tag_decode(#tag)
                    }
                }
        });
    }

    Ok(quote! {
        #(#impls) *
    })
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use crate::derive_decodable_fn2;

    use super::*;

    #[test]
    fn test_derive_enum() {
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
    fn test_derive_enum_with_default() {
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
}
