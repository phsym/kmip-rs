//! Code generation for `#[derive(Decodable)]`.
//!
//! For structs, generates up to three items:
//!
//! 1. **`TagDecodable` impl** — wraps decoding in `decoder.read_struct(tag, ...)`.
//! 2. **`flatten_decode()`** — public inherent method containing the actual decoding logic
//!    (called by parent types that have `#[ttlv(flatten)]` on this field).
//! 3. **`Decodable` impl** — only when a `tag` attribute is present. Delegates to `tag_decode`.
//!
//! For flattened structs (`#[ttlv(flatten)]`), only a `Decodable` impl is generated
//! (no `TagDecodable`, no `flatten_decode`).
//!
//! For TTLV enums (`#[ttlv(enum)]`), generates a `TagDecodable` impl that reads the enum
//! value and matches it against variant discriminants (by number) and names (by string).
//!
//! ## Key differences from the encode path
//!
//! - `set_ext` inserts into extensions *after* decoding (encode does it *before*)
//! - `if_filter` wraps the decode in an `if/else` with `Default::default()` fallback
//!   (encode just wraps in an `if` with no else)
//! - `skip` generates `field: Default::default()` in the constructor (encode just omits the call)

use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, quote_spanned};
use syn::{Data, DataEnum, DataStruct, DeriveInput, Error, Ident, Result, spanned::Spanned};

use crate::fields::FieldInfo;
use crate::ttlv_enum::parse_ttlv_variants;
use crate::{AttrExt, CallMode, EnumAttr, EnumEnumAttr, StructAttr};

/// Entry point for `#[derive(Decodable)]`. Dispatches to struct or enum handling.
pub fn derive_decodable_fn2(item: TokenStream2) -> Result<TokenStream2> {
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

// --- Struct decoding ---

fn derive_struct(data: DataStruct, ident: Ident, struct_attr: StructAttr) -> Result<TokenStream2> {
    let field_infos = FieldInfo::from_fields(data.fields)?;

    let mut stmts = Vec::new();
    let mut idents = Vec::new();
    for f in &field_infos {
        let field_ident = &f.ident;
        if !f.skip {
            let var = &f.var;
            let ty = &f.ty;

            let mut call = match &f.call_mode {
                CallMode::None => {
                    quote_spanned! {field_ident.span() => let #var: #ty = d.decode()?}
                }
                CallMode::Tag(tag) => {
                    quote_spanned! {field_ident.span() => let #var: #ty = d.tag_decode(#tag)?}
                }
                CallMode::Flatten => {
                    quote_spanned! {field_ident.span() => let #var: #ty = d.flatten_decode()?}
                }
            };

            if let Some(ref filter) = f.if_filter {
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
                    }
                }
            }

            if f.set_ext {
                call = quote! {
                    #call;
                    d.extensions().insert(#var.clone())
                }
            }

            stmts.push(call);
            idents.push(quote_spanned! {field_ident.span() => #field_ident: #var});
        } else {
            idents.push(quote_spanned! {field_ident.span() => #field_ident: Default::default()});
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

// --- Enum decoding ---

/// Only TTLV enums (`#[ttlv(enum)]`) support `Decodable`. Struct-like enums are rejected.
fn derive_enum(en: DataEnum, ident: Ident, enum_attr: EnumAttr) -> Result<TokenStream2> {
    match enum_attr {
        EnumAttr::Enum(enum_attr) => derive_enum_enum(en, ident, enum_attr),
        EnumAttr::Struct(_) => Err(Error::new_spanned(&ident, "need the enum attribute")),
    }
}

/// Generates `TagDecodable` for TTLV enums.
///
/// Reads the raw enum value via `decoder.read_enum()`, then matches on `(numeric, name)`:
/// - Each variant produces two match arms: one for numeric-only, one for name (with or without rename)
/// - The `#[ttlv(default)]` variant becomes the catch-all `_ =>` arm
/// - If no default variant exists, the catch-all returns `Error::InvalidEnum`
fn derive_enum_enum(en: DataEnum, ident: Ident, enum_attr: EnumEnumAttr) -> Result<TokenStream2> {
    let variants = parse_ttlv_variants(&en)?;

    let mut branches = Vec::new();
    let mut default_branch = quote! {_ => Err(::ttlv::Error::InvalidEnum{tag: tag.raw().to_owned(), value: val.raw().to_owned()})};
    for var in &variants {
        let vident = &var.ident;
        if var.is_default {
            default_branch = quote! { _ => Ok(Self::#vident(val.raw().to_owned()))};
        } else {
            let disc = &var.discriminant;
            branches.push(quote! {(Some(#disc), None) => Ok(Self::#vident)});
            if let Some(ref rename) = var.rename {
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
