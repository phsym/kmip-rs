mod r#enum;
mod r#struct;
use r#enum::*;
use r#struct::*;

use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{ToTokens, format_ident, quote, quote_spanned};
use syn::{Data, DeriveInput, Error, Expr, Fields, Ident, Index, Result, spanned::Spanned};

use crate::{AttrExt, CallMode};

pub fn derive_encodable_fn2(item: TokenStream2) -> Result<TokenStream2> {
    let ast: DeriveInput = syn::parse2(item)?;
    let attr = ast.attrs.get_attr()?;

    match ast.data {
        Data::Enum(en) => derive_enum(en, ast.ident, attr.for_enum()?),
        Data::Struct(data) => derive_struct(data, ast.ident, attr.for_struct()?),
        _ => Err(Error::new_spanned(
            &ast,
            "Only enums and structs are supported",
        )),
    }
}

fn impl_fields_encode(
    fields: Fields,
    encoder_ident: &str,
    variant: Option<Ident>,
) -> Result<TokenStream2> {
    let encoder = Ident::new(encoder_ident, Span::call_site());

    let fields = match fields {
        Fields::Named(fields) => fields.named,
        Fields::Unnamed(fields) => fields.unnamed,
        Fields::Unit => Default::default(),
    };

    let mut stmts = Vec::new();
    let mut fields_idents = Vec::new();
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
        let field_var = format_ident!("_{}", ident.to_string());
        fields_idents.push(quote_spanned! {ident.span() => #ident: #field_var});

        if !attrs.skip {
            let mut call = match attrs.call_mode {
                CallMode::None => quote_spanned! {ident.span() => #encoder.encode(#field_var)},
                CallMode::Tag(tag) => {
                    quote_spanned! {ident.span() => #encoder.tag_encode(#tag, #field_var)}
                }
                CallMode::Flatten => {
                    quote_spanned! {ident.span() => #field_var.flatten_encode(#encoder)}
                }
            };
            if attrs.set_ext {
                call = quote! {
                    #encoder.extensions().insert(#field_var.clone());
                    #call
                };
            }
            if let Some(filter) = attrs.if_filter {
                call = quote! {
                    {
                        use ::ttlv::ExtensionsExt;
                        let _ext = #encoder.extensions();
                        if #filter {
                            #call;
                        }
                }
                };
            }
            stmts.push(call);
        }
    }
    if let Some(varname) = variant {
        return Ok(quote! {Self::#varname{#(#fields_idents), *} => {
            #(#stmts); *
        }});
    }
    Ok(quote! {Self{#(#fields_idents), *} => {
        #(#stmts); *
    }})
}

fn impl_inner_encode(ident: &Ident, encoder_ident: &str, body: TokenStream2) -> TokenStream2 {
    let encoder = Ident::new(encoder_ident, Span::call_site());
    quote! {
        impl #ident {
            fn inner_encode(&self, #encoder: &mut impl ::ttlv::Encoder) {
                #body
            }
        }
    }
}

fn impl_tag_encodable(ident: &Ident) -> TokenStream2 {
    quote! {
        impl ::ttlv::TagEncodable for #ident {
            fn encode<E: ::ttlv::Encoder>(&self, tag: impl ::ttlv::Tag, encoder: &mut E) {
                use ::ttlv::Encoder;
                encoder.write_struct(tag, |e| {
                    self.flatten_encode(e);
                });
            }
        }

        impl #ident {
            pub fn flatten_encode<E: ::ttlv::Encoder>(&self, e: &mut E) {
                self.inner_encode(e)
            }
        }
    }
}

fn impl_encodable(ident: &Ident, tag: &Expr) -> TokenStream2 {
    quote! {
        impl ::ttlv::Encodable for #ident {
            fn encode(&self, encoder: &mut impl ::ttlv::Encoder) {
                encoder.tag_encode(#tag, self);
            }
        }
    }
}

fn impl_flattened_encode(ident: &Ident) -> TokenStream2 {
    quote! {
        impl ::ttlv::Encodable for #ident {
            fn encode(&self, encoder: &mut impl ::ttlv::Encoder) {
                self.inner_encode(encoder);
            }
        }
    }
}
