use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{DataEnum, Error, Fields, Ident, Result};

use crate::{AttrExt, CallMode, EnumAttr, EnumEnumAttr, StructAttr};

use super::{
    impl_encodable, impl_fields_encode, impl_flattened_encode, impl_inner_encode,
    impl_tag_encodable,
};

pub fn derive_enum(en: DataEnum, ident: Ident, enum_attr: EnumAttr) -> Result<TokenStream2> {
    match enum_attr {
        EnumAttr::Enum(enum_attr) => derive_enum_enum(en, ident, enum_attr),
        EnumAttr::Struct(enum_attr) => derive_enum_struct(en, ident, enum_attr),
    }
}

fn derive_enum_enum(en: DataEnum, ident: Ident, enum_attr: EnumEnumAttr) -> Result<TokenStream2> {
    let mut branches = Vec::new();
    let mut has_branches = false;
    for var in en.variants {
        // Validate the attributes
        let attrs = var.attrs.get_attr()?.for_enum_variant()?;
        let vident = &var.ident;
        if attrs.default {
            branches.push(quote! {Self::#vident(value) => return encoder.write_enum(tag, value)});
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
            if let Some(rename) = attrs.rename {
                branches.push(quote! {Self::#vident => (#disc, #rename)});
            } else {
                branches.push(quote! {Self::#vident => (#disc, ::std::stringify!(#vident))});
            }
            has_branches = true;
        }
    }

    let write_enum = has_branches.then_some(quote! {encoder.write_enum(tag, value);});

    let mut impls = vec![quote! {
            impl ::ttlv::TagEncodable for #ident {
                fn encode<E: ::ttlv::Encoder>(&self, tag: impl ::ttlv::Tag, encoder: &mut E) {
                    let value = match self {
                        #(#branches), *
                    };
                    #write_enum
                }
            }
    }];

    if let Some(tag) = enum_attr.tag {
        impls.push(quote! {
            impl ::ttlv::Encodable for #ident {
                fn encode(&self, encoder: &mut impl ::ttlv::Encoder) {
                    encoder.tag_encode(#tag, self);
                }
            }
        });
    }

    Ok(quote! {
        #(#impls) *
    })
}

fn derive_enum_struct(en: DataEnum, ident: Ident, enum_attr: StructAttr) -> Result<TokenStream2> {
    let mut branches = Vec::new();
    for var in en.variants {
        // Validate the attributes
        var.attrs.get_attr()?.for_enum_variant()?;

        branches.push(impl_fields_encode(var.fields, "e", Some(var.ident))?);
    }

    let mut impls = vec![impl_inner_encode(
        &ident,
        "e",
        quote! {
            match self {
                #(#branches), *
            };
        },
    )];

    if let CallMode::Flatten = enum_attr.call_mode {
        impls.push(impl_flattened_encode(&ident));
    } else {
        impls.push(impl_tag_encodable(&ident));
    };

    if let CallMode::Tag(tag) = enum_attr.call_mode {
        impls.push(impl_encodable(&ident, &tag));
    }

    Ok(quote! {
        #(#impls) *
    })
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use crate::derive_encodable_fn2;

    use super::*;

    #[test]
    fn test_derive_tagged_enum() {
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
    fn test_derive_untagged_enum() {
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
}
