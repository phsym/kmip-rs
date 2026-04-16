use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{DataStruct, Ident, Result};

use crate::{CallMode, StructAttr, encodable::impl_tag_encodable};

use super::{impl_encodable, impl_fields_encode, impl_flattened_encode, impl_inner_encode};

pub fn derive_struct(
    data: DataStruct,
    ident: Ident,
    struct_attr: StructAttr,
) -> Result<TokenStream2> {
    let branch = impl_fields_encode(data.fields, "e", None)?;

    let mut impls = vec![impl_inner_encode(
        &ident,
        "e",
        quote! {
            match self {
                #branch
            }
        },
    )];

    if let CallMode::Flatten = struct_attr.call_mode {
        impls.push(impl_flattened_encode(&ident));
    } else {
        impls.push(impl_tag_encodable(&ident));
    };

    if let CallMode::Tag(tag) = struct_attr.call_mode {
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
    fn test_derive_struct_unit() {
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
    fn test_derive_struct_named() {
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
    fn test_derive_struct_unnamed() {
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
}
