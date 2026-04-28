//! Code generation for `#[derive(Encodable)]`.
//!
//! For each type, this generates up to three items:
//!
//! 1. **`inner_encode()`** — a private inherent method containing the actual encoding logic.
//!    For structs, it destructures `self` and encodes each field. For struct-like enums,
//!    it matches on `self` with one arm per variant.
//!
//! 2. **`TagEncodable` impl** (or `flatten_encode()`) — the public trait impl.
//!    With a tag: wraps `inner_encode` in `encoder.write_struct(tag, ...)`.
//!    With flatten: delegates directly to `inner_encode` via `Encodable`.
//!
//! 3. **`Encodable` impl** — only when a `tag` attribute is present. Delegates to `tag_encode`.
//!
//! TTLV enums (`#[ttlv(enum)]`) take a different path: they generate a `TagEncodable` impl
//! that maps each variant to a `(discriminant, name)` tuple and calls `encoder.write_enum()`.

use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    Data, DataEnum, DataStruct, DeriveInput, Error, Expr, Ident, Result, Type, spanned::Spanned,
};

use crate::fields::{FieldInfo, clone_bounds_where_clause};
use crate::path::ttlv_path;
use crate::ttlv_enum::parse_ttlv_variants;
use crate::{AttrExt, CallMode, EnumAttr, EnumEnumAttr, StructAttr};

/// Entry point for `#[derive(Encodable)]`. Dispatches to struct or enum handling.
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

// --- Struct encoding ---

fn derive_struct(data: DataStruct, ident: Ident, struct_attr: StructAttr) -> Result<TokenStream2> {
    let (branch, set_ext_types) = impl_fields_encode(data.fields, "e", None)?;

    let mut impls = vec![impl_inner_encode(
        &ident,
        "e",
        quote! {
            match self {
                #branch
            }
        },
        &set_ext_types,
    )];

    match struct_attr.call_mode {
        CallMode::Flatten => impls.push(impl_flattened_encode(&ident)),
        _ => impls.push(impl_tag_encodable(&ident)),
    }

    if let CallMode::Tag(tag) = struct_attr.call_mode {
        impls.push(impl_encodable(&ident, &tag));
    }

    Ok(quote! {
        #(#impls) *
    })
}

// --- Enum encoding ---

/// Dispatches between TTLV enum encoding and struct-like enum encoding.
fn derive_enum(en: DataEnum, ident: Ident, enum_attr: EnumAttr) -> Result<TokenStream2> {
    match enum_attr {
        EnumAttr::Enum(enum_attr) => derive_enum_enum(en, ident, enum_attr),
        EnumAttr::Struct(struct_attr) => derive_enum_struct(en, ident, struct_attr),
    }
}

/// Generates `TagEncodable` for TTLV enums (`#[ttlv(enum)]`).
///
/// Each variant maps to a `(discriminant, name)` tuple that gets passed to
/// `encoder.write_enum(tag, value)`. The `#[ttlv(default)]` variant short-circuits
/// with `return encoder.write_enum(tag, value)` since its inner value is already a tag.
fn derive_enum_enum(en: DataEnum, ident: Ident, enum_attr: EnumEnumAttr) -> Result<TokenStream2> {
    let ttlv = ttlv_path();
    let variants = parse_ttlv_variants(&en)?;

    let mut branches = Vec::new();
    let mut has_branches = false;
    for var in &variants {
        let vident = &var.ident;
        if var.is_default {
            branches.push(quote! {Self::#vident(value) => return encoder.write_enum(tag, value)});
        } else {
            let disc = &var.discriminant;
            if let Some(ref rename) = var.rename {
                branches.push(quote! {Self::#vident => (#disc, #rename)});
            } else {
                branches.push(quote! {Self::#vident => (#disc, ::std::stringify!(#vident))});
            }
            has_branches = true;
        }
    }

    let body = if has_branches {
        quote! {
            let value = match self {
                #(#branches), *
            };
            encoder.write_enum(tag, value)
        }
    } else {
        // No non-default branches: every arm diverges (or the match is empty).
        // The match itself produces `!`, which coerces to `Result<(), _>`.
        quote! {
            match self {
                #(#branches), *
            }
        }
    };

    let mut impls = vec![quote! {
        impl #ttlv::TagEncodable for #ident {
            fn encode<E: #ttlv::Encoder>(&self, tag: impl #ttlv::Tag, encoder: &mut E) -> #ttlv::Result<()> {
                #body
            }
        }
    }];

    if let Some(tag) = enum_attr.tag {
        impls.push(impl_encodable(&ident, &tag));
    }

    Ok(quote! {
        #(#impls) *
    })
}

/// Generates encoding for struct-like enums (no `#[ttlv(enum)]`).
/// Each variant's fields are encoded as if it were a struct, wrapped in a `match self` arm.
fn derive_enum_struct(en: DataEnum, ident: Ident, struct_attr: StructAttr) -> Result<TokenStream2> {
    let mut branches = Vec::new();
    let mut set_ext_types = Vec::new();
    for var in en.variants {
        var.attrs.get_attr()?.for_enum_variant()?;
        let (branch, mut types) = impl_fields_encode(var.fields, "e", Some(var.ident))?;
        branches.push(branch);
        set_ext_types.append(&mut types);
    }

    let mut impls = vec![impl_inner_encode(
        &ident,
        "e",
        quote! {
            match self {
                #(#branches), *
            }
        },
        &set_ext_types,
    )];

    match struct_attr.call_mode {
        CallMode::Flatten => impls.push(impl_flattened_encode(&ident)),
        _ => impls.push(impl_tag_encodable(&ident)),
    }

    if let CallMode::Tag(tag) = struct_attr.call_mode {
        impls.push(impl_encodable(&ident, &tag));
    }

    Ok(quote! {
        #(#impls) *
    })
}

// --- Field encoding ---

/// Generates a match arm that destructures a struct (or enum variant) and encodes each field.
///
/// For each non-skipped field, generates the appropriate encode call based on its `CallMode`,
/// optionally wrapping it with `set_ext` (inserts value into extensions *before* encoding)
/// and/or `if_filter` (conditionally encodes based on extension state).
///
/// Returns a token stream like:
/// ```ignore
/// Self { field1: _field1, field2: _field2 } => {
///     encoder.encode(_field1);
///     encoder.tag_encode(42, _field2)
/// }
/// ```
fn impl_fields_encode(
    fields: syn::Fields,
    encoder_ident: &str,
    variant: Option<Ident>,
) -> Result<(TokenStream2, Vec<Type>)> {
    let ttlv = ttlv_path();
    let encoder = Ident::new(encoder_ident, Span::call_site());
    let field_infos = FieldInfo::from_fields(fields)?;

    let bindings: Vec<_> = field_infos.iter().map(|f| f.binding()).collect();

    let mut stmts = Vec::new();
    let mut set_ext_types = Vec::new();
    for f in &field_infos {
        if f.skip {
            continue;
        }
        let var = &f.var;
        let ident = &f.ident;
        let mut call = match &f.call_mode {
            CallMode::None => quote::quote_spanned! {ident.span() => #encoder.encode(#var)},
            CallMode::Tag(tag) => {
                quote::quote_spanned! {ident.span() => #encoder.tag_encode(#tag, #var)}
            }
            CallMode::Flatten => {
                quote::quote_spanned! {ident.span() => #var.flatten_encode(#encoder)}
            }
        };
        if f.set_ext {
            call = quote! {
                #encoder.extensions().insert(#var.clone());
                #call
            };
            set_ext_types.push(f.ty.clone());
        }
        if let Some(ref filter) = f.if_filter {
            call = quote! {
                {
                    use #ttlv::ExtensionsExt;
                    let _ext = #encoder.extensions();
                    if #filter {
                        #call
                    } else {
                        #ttlv::Result::Ok(())
                    }
                }
            };
        }
        stmts.push(call);
    }

    let branch = if let Some(varname) = variant {
        quote! {Self::#varname{#(#bindings), *} => {
            #(#stmts ?;)*
            #ttlv::Result::Ok(())
        }}
    } else {
        quote! {Self{#(#bindings), *} => {
            #(#stmts ?;)*
            #ttlv::Result::Ok(())
        }}
    };
    Ok((branch, set_ext_types))
}

// --- Code generation helpers ---
// These functions generate the boilerplate trait impls and inherent methods that
// wrap the actual encoding logic (produced by `impl_fields_encode`).

/// Generates the private `inner_encode()` inherent method that contains the body of the encoding logic.
///
/// Fields marked `#[ttlv(set_ext)]` require `Clone`, so each set_ext field type
/// contributes a `where <ty>: Clone` bound on this method's signature. The bound
/// is spanned at the field type so a missing `Clone` impl surfaces at the field.
fn impl_inner_encode(
    ident: &Ident,
    encoder_ident: &str,
    body: TokenStream2,
    set_ext_types: &[Type],
) -> TokenStream2 {
    let ttlv = ttlv_path();
    let encoder = Ident::new(encoder_ident, Span::call_site());
    let where_clause = clone_bounds_where_clause(set_ext_types);
    quote! {
        impl #ident {
            fn inner_encode(&self, #encoder: &mut impl #ttlv::Encoder) -> #ttlv::Result<()> #where_clause {
                #body
            }
        }
    }
}

/// Generates `TagEncodable` impl (wraps `inner_encode` in `write_struct`) and
/// the public `flatten_encode()` method (used by parent types with `#[ttlv(flatten)]` fields).
fn impl_tag_encodable(ident: &Ident) -> TokenStream2 {
    let ttlv = ttlv_path();
    quote! {
        impl #ttlv::TagEncodable for #ident {
            fn encode<E: #ttlv::Encoder>(&self, tag: impl #ttlv::Tag, encoder: &mut E) -> #ttlv::Result<()> {
                use #ttlv::Encoder;
                encoder.write_struct(tag, |e| {
                    self.flatten_encode(e)
                })
            }
        }

        impl #ident {
            pub fn flatten_encode<E: #ttlv::Encoder>(&self, e: &mut E) -> #ttlv::Result<()> {
                self.inner_encode(e)
            }
        }
    }
}

/// Generates `Encodable` impl that delegates to `tag_encode` with the given tag.
fn impl_encodable(ident: &Ident, tag: &Expr) -> TokenStream2 {
    let ttlv = ttlv_path();
    quote! {
        impl #ttlv::Encodable for #ident {
            fn encode(&self, encoder: &mut impl #ttlv::Encoder) -> #ttlv::Result<()> {
                encoder.tag_encode(#tag, self)
            }
        }
    }
}

/// Generates `Encodable` impl for flattened types (delegates directly to `inner_encode`,
/// without wrapping in `write_struct`).
fn impl_flattened_encode(ident: &Ident) -> TokenStream2 {
    let ttlv = ttlv_path();
    quote! {
        impl #ttlv::Encodable for #ident {
            fn encode(&self, encoder: &mut impl #ttlv::Encoder) -> #ttlv::Result<()> {
                self.inner_encode(encoder)
            }
        }
    }
}
