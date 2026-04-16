use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DataEnum, DeriveInput, Error, Fields, Ident, Result};

use crate::{AttrExt, EnumAttr};

pub fn derive_enum_fn2(item: TokenStream2) -> Result<TokenStream2> {
    let ast: DeriveInput = syn::parse2(item)?;
    let attr = ast.attrs.get_attr()?;

    match ast.data {
        Data::Enum(en) => derive_enum(en, ast.ident, attr.for_enum()?),
        _ => Err(Error::new_spanned(&ast, "Only enums are supported")),
    }
}

pub fn derive_enum(en: DataEnum, ident: Ident, enum_attr: EnumAttr) -> Result<TokenStream2> {
    match enum_attr {
        EnumAttr::Enum(_) => derive_enum_enum(en, ident),
        _ => Err(Error::new_spanned(
            &ident,
            "Missing the ttlv 'enum' attribute",
        )),
    }
}

fn derive_enum_enum(en: DataEnum, ident: Ident) -> Result<TokenStream2> {
    let mut branches = Vec::new();
    for var in en.variants {
        // Validate the attributes
        let attrs = var.attrs.get_attr()?.for_enum_variant()?;
        let vident = &var.ident;
        if attrs.default {
            branches.push(quote! {Self::#vident(value) => value.name().unwrap_or("Unknown")});
        } else {
            if !matches!(var.fields, Fields::Unit) {
                return Err(Error::new_spanned(
                    &var.ident,
                    "Only unit fields are supported",
                ));
            }
            if let Some(rename) = attrs.rename {
                branches.push(quote! {Self::#vident =>  #rename});
            } else {
                branches.push(quote! {Self::#vident => ::std::stringify!(#vident)});
            }
        }
    }

    Ok(quote! {
        impl #ident {
            pub fn name(&self) -> &str {
                match self {
                    #(#branches,) *
                }
            }
        }

        impl ::std::fmt::Display for #ident {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                self.name().fmt(f)
            }
        }
    })
}
