//! Shared field extraction for both the encode and decode paths.
//!
//! Both `Encodable` and `Decodable` derives need to iterate struct fields, parse their
//! `#[ttlv(...)]` attributes, and compute identifiers and variable names. This module
//! extracts that common logic into `FieldInfo`, so each derive only handles its own
//! code generation (the `quote!` templates differ between encode and decode).

use proc_macro2::TokenStream as TokenStream2;
use quote::{ToTokens, format_ident, quote, quote_spanned};
use syn::{Expr, Fields, Ident, Index, Result, Type, spanned::Spanned};

use crate::{AttrExt, CallMode};

/// Parsed representation of a single struct/tuple field with its `#[ttlv(...)]` attributes.
///
/// For named fields, `ident` is the field name (e.g. `field1`).
/// For unnamed (tuple) fields, `ident` is the index (e.g. `0`, `1`).
/// `var` is the generated temporary variable name (e.g. `_field1`, `_0`).
pub struct FieldInfo {
    pub ident: TokenStream2,
    pub var: Ident,
    pub ty: Type,
    pub call_mode: CallMode,
    pub if_filter: Option<Expr>,
    pub set_ext: bool,
    pub skip: bool,
}

impl FieldInfo {
    /// Parses `syn::Fields` into a list of `FieldInfo`, extracting each field's
    /// identifier, type, and validated `#[ttlv(...)]` attributes.
    pub fn from_fields(fields: Fields) -> Result<Vec<Self>> {
        let fields = match fields {
            Fields::Named(fields) => fields.named,
            Fields::Unnamed(fields) => fields.unnamed,
            Fields::Unit => Default::default(),
        };

        let mut result = Vec::new();
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
            let var = format_ident!("_{}", ident.to_string());
            result.push(FieldInfo {
                ident,
                var,
                ty: field.ty,
                call_mode: attrs.call_mode,
                if_filter: attrs.if_filter,
                set_ext: attrs.set_ext,
                skip: attrs.skip,
            });
        }
        Ok(result)
    }

    /// Generates `field1: _field1` for destructuring patterns
    pub fn binding(&self) -> TokenStream2 {
        let ident = &self.ident;
        let var = &self.var;
        quote_spanned! {ident.span() => #ident: #var}
    }
}

/// Builds a `where <ty>: ::std::clone::Clone, ...` clause for fields that need `Clone`
/// (currently `#[ttlv(set_ext)]` fields, which are cloned before insertion into the
/// extensions context). Each predicate is spanned at the field type so a missing
/// `Clone` impl surfaces at the offending field rather than at the derive invocation.
/// Duplicate types (same struct used on multiple `set_ext` fields, or across enum
/// variants) are collapsed to a single predicate. Returns an empty token stream
/// when `types` is empty.
///
/// # Gotcha: `trivial_bounds`
///
/// The predicate uses concrete field types, which on stable Rust makes an
/// unsatisfied bound a hard `E0277` at the field type — exactly the error we
/// want. Under the unstable `#![feature(trivial_bounds)]`, however, rustc
/// accepts such bounds silently and the method merely becomes uncallable;
/// the error then surfaces at the caller (the derived trait impl) rather than
/// at the field. Stable Rust is unaffected; nightly users who opt into
/// `trivial_bounds` get a less precise span but still a compile error.
pub fn clone_bounds_where_clause(types: &[Type]) -> TokenStream2 {
    let mut seen = std::collections::HashSet::new();
    let preds: Vec<_> = types
        .iter()
        .filter(|ty| seen.insert(ty.to_token_stream().to_string()))
        .map(|ty| quote_spanned! {ty.span() => #ty: ::std::clone::Clone})
        .collect();
    if preds.is_empty() {
        return TokenStream2::new();
    }
    quote! { where #(#preds),* }
}
