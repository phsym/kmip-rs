//! Proc-macro crate for deriving TTLV serialization/deserialization traits.
//!
//! Provides three derive macros that generate implementations for the traits
//! defined in the `ttlv` crate:
//!
//! - `#[derive(Encodable)]` — generates `Encodable` and `TagEncodable` impls for serialization
//! - `#[derive(Decodable)]` — generates `Decodable` and `TagDecodable` impls for deserialization
//! - `#[derive(Enum)]` — generates `name() -> &str` and `Display` for TTLV enumeration types
//!
//! All three macros share the `#[ttlv(...)]` attribute namespace. See `attrs.rs` for the full
//! list of supported attributes.

mod attrs;
mod decodable;
mod derive_enum;
mod encodable;
mod fields;
mod ttlv_enum;

#[cfg(test)]
mod tests;

use attrs::*;
use decodable::*;
use derive_enum::*;
use encodable::*;

use proc_macro::TokenStream;

/// Derives `Encodable` and `TagEncodable` for structs and enums.
///
/// Each `_fn` entry point converts from `proc_macro::TokenStream` to `proc_macro2::TokenStream`,
/// delegates to the `_fn2` implementation (which returns `Result`), and converts errors into
/// compile-time diagnostics.
#[proc_macro_derive(Encodable, attributes(ttlv))]
pub fn derive_encodable_fn(item: TokenStream) -> TokenStream {
    match derive_encodable_fn2(item.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.into_compile_error().into(),
    }
}

/// Derives `Decodable` and `TagDecodable` for structs and enums.
#[proc_macro_derive(Decodable, attributes(ttlv))]
pub fn derive_decodable_fn(item: TokenStream) -> TokenStream {
    match derive_decodable_fn2(item.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.into_compile_error().into(),
    }
}

/// Derives `name() -> &str` and `Display` for TTLV enumeration types.
///
/// Requires `#[ttlv(enum)]` on the enum. Each variant must have an explicit
/// discriminant (e.g. `Variant = 0x01`), except `#[ttlv(default)]` catch-all variants.
#[proc_macro_derive(Enum, attributes(ttlv))]
pub fn derive_enum_fn(item: TokenStream) -> TokenStream {
    match derive_enum_fn2(item.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.into_compile_error().into(),
    }
}
