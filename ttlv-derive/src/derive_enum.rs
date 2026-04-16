//! Code generation for `#[derive(Enum)]`.
//!
//! Generates a `name() -> &str` method and a `Display` impl for TTLV enums.
//! Each variant maps to its name string (or `#[ttlv(rename = "...")]` override),
//! and the `#[ttlv(default)]` catch-all variant delegates to the inner value's
//! `Tag::name()` method.

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DataEnum, DeriveInput, Error, Ident, Result};

use crate::ttlv_enum::parse_ttlv_variants;
use crate::{AttrExt, EnumAttr};

/// Entry point for `#[derive(Enum)]`. Only enums with `#[ttlv(enum)]` are accepted.
pub fn derive_enum_fn2(item: TokenStream2) -> Result<TokenStream2> {
    let ast: DeriveInput = syn::parse2(item)?;
    let attr = ast.attrs.get_attr()?;

    match ast.data {
        Data::Enum(en) => derive_enum(en, ast.ident, attr.for_enum()?),
        _ => Err(Error::new_spanned(&ast, "Only enums are supported")),
    }
}

fn derive_enum(en: DataEnum, ident: Ident, enum_attr: EnumAttr) -> Result<TokenStream2> {
    match enum_attr {
        EnumAttr::Enum(_) => {}
        _ => {
            return Err(Error::new_spanned(
                &ident,
                "Missing the ttlv 'enum' attribute",
            ));
        }
    }

    let variants = parse_ttlv_variants(&en)?;

    let mut branches = Vec::new();
    for var in &variants {
        let vident = &var.ident;
        if var.is_default {
            branches.push(quote! {Self::#vident(value) => value.name().unwrap_or("Unknown")});
        } else if let Some(ref rename) = var.rename {
            branches.push(quote! {Self::#vident => #rename});
        } else {
            branches.push(quote! {Self::#vident => ::std::stringify!(#vident)});
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
