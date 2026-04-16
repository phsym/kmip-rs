//! Shared TTLV enum variant parsing for `Encodable`, `Decodable`, and `Enum` derives.
//!
//! TTLV enums (marked with `#[ttlv(enum)]`) have unit variants with explicit discriminants
//! (e.g. `Create = 0x01`) and an optional catch-all `#[ttlv(default)]` variant.
//! All three derive macros need to iterate these variants and extract the same information,
//! so this module provides a shared `parse_ttlv_variants()` function.

use proc_macro2::Literal;
use syn::{DataEnum, Error, Expr, Fields, Ident, Lit, Result};

use crate::AttrExt;

/// A parsed TTLV enum variant. Regular variants have an `ident`, a numeric `discriminant`,
/// and an optional `rename`. The `#[ttlv(default)]` catch-all variant has `is_default = true`
/// and wraps a single unnamed field (e.g. `Unknown(RawTag)`).
pub struct TtlvVariant {
    pub ident: Ident,
    pub discriminant: Expr,
    pub rename: Option<Literal>,
    pub is_default: bool,
}

/// Parses all variants of a `#[ttlv(enum)]` enum, validating that non-default variants
/// are unit variants with explicit discriminants.
pub fn parse_ttlv_variants(en: &DataEnum) -> Result<Vec<TtlvVariant>> {
    let mut result = Vec::new();
    for var in &en.variants {
        let attrs = var.attrs.get_attr()?.for_enum_variant()?;
        let ident = var.ident.clone();

        if attrs.default {
            match &var.fields {
                Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {}
                _ => {
                    return Err(Error::new_spanned(
                        &var.ident,
                        "Default variant must have exactly one unnamed field",
                    ));
                }
            }
            result.push(TtlvVariant {
                ident,
                discriminant: syn::parse_quote!(0), // placeholder, not used for default
                rename: attrs.rename,
                is_default: true,
            });
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
            if !matches!(disc, Expr::Lit(lit) if matches!(lit.lit, Lit::Int(_))) {
                return Err(Error::new_spanned(
                    disc,
                    "Discriminant must be an integer literal",
                ));
            }
            result.push(TtlvVariant {
                ident,
                discriminant: disc.clone(),
                rename: attrs.rename,
                is_default: false,
            });
        }
    }
    Ok(result)
}
