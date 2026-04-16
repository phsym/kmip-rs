use proc_macro2::TokenStream as TokenStream2;
use quote::{ToTokens, format_ident, quote, quote_spanned};
use syn::{DataStruct, Fields, Ident, Index, Result, spanned::Spanned};

use crate::{AttrExt, CallMode, StructAttr};

pub fn derive_struct(
    data: DataStruct,
    ident: Ident,
    struct_attr: StructAttr,
) -> Result<TokenStream2> {
    let fields = match data.fields {
        Fields::Named(fields) => fields.named,
        Fields::Unnamed(fields) => fields.unnamed,
        Fields::Unit => Default::default(),
    };

    let mut stmts = Vec::new();
    let mut idents = Vec::new();
    for (idx, field) in fields.into_iter().enumerate() {
        let attrs = field.attrs.get_attr()?.for_struct_field()?;
        let ident = field
            .ident
            .as_ref()
            .map(|id| id.to_token_stream())
            .unwrap_or(
                Index {
                    index: idx as u32,
                    span: field.span(),
                }
                .to_token_stream(),
            );

        if !attrs.skip {
            let var = format_ident!("_{}", ident.to_string());
            let ty = field.ty;

            let mut call = match attrs.call_mode {
                CallMode::None => quote_spanned! {ident.span() => let #var: #ty = d.decode()?},
                CallMode::Tag(tag) => {
                    quote_spanned! {ident.span() => let #var: #ty = d.tag_decode(#tag)?}
                }
                CallMode::Flatten => {
                    quote_spanned! {ident.span() => let #var: #ty = d.flatten_decode()?}
                }
            };

            if let Some(filter) = attrs.if_filter {
                call = quote! {
                    let #var = {
                        use ::ttlv::ExtensionsExt;
                        let _ext = d.extensions();
                        if #filter {
                            #call;
                            #var
                        } else {
                            Default::default()
                        }
                    };
                }
            }

            if attrs.set_ext {
                call = quote! {
                    #call;
                    d.extensions().insert(#var.clone());
                }
            }

            stmts.push(call);
            idents.push(quote_spanned! {ident.span() => #ident: #var});
        } else {
            idents.push(quote_spanned! {ident.span() => #ident: Default::default()});
        }
    }

    let mut impls = if let CallMode::Flatten = struct_attr.call_mode {
        vec![quote! {
            impl ::ttlv::Decodable for #ident {
                fn decode(d: &mut impl ::ttlv::Decoder) -> ::ttlv::Result<Self> {
                    #(#stmts;) *
                    let res = Self {
                        #(#idents), *
                    };
                    Ok(res)
                }
            }
        }]
    } else {
        vec![quote! {
            impl ::ttlv::TagDecodable for #ident {
                fn decode<D: ::ttlv::Decoder>(tag: impl ::ttlv::Tag, decoder: &mut D) -> ::ttlv::Result<Self> {
                    use ::ttlv::Decoder;
                    decoder.read_struct(tag, |d| {
                        Self::flatten_decode(d)
                    })
                }
            }

            impl #ident {
                pub fn flatten_decode<D: ::ttlv::Decoder>(d: &mut D) -> ::ttlv::Result<Self> {
                    #(#stmts;) *
                    let res = Self {
                        #(#idents), *
                    };
                    Ok(res)
                }
            }
        }]
    };

    if let CallMode::Tag(tag) = struct_attr.call_mode {
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
    fn test_derive_struct_unit() {
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
    fn test_derive_struct_named() {
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
    fn test_derive_struct_unnamed() {
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
}
