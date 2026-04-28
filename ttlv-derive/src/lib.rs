#![doc = include_str!("../README.md")]

mod attrs;
mod decodable;
mod derive_enum;
mod encodable;
mod fields;
mod path;
mod ttlv_enum;

#[cfg(test)]
mod tests;

use attrs::*;
use decodable::*;
use derive_enum::*;
use encodable::*;

use proc_macro::TokenStream;

/// Derives [`Encodable`] and [`TagEncodable`] for structs and enums.
///
/// Accepts every `#[ttlv(...)]` attribute listed in the [crate-level
/// reference](crate#attribute-reference) that applies to a struct, enum, or
/// field. See the [examples](crate#examples) for the full feature set.
///
/// Each `_fn` entry point converts from `proc_macro::TokenStream` to
/// `proc_macro2::TokenStream`, delegates to the `_fn2` implementation (which
/// returns `Result`), and converts errors into compile-time diagnostics.
///
/// [`Encodable`]: https://docs.rs/ttlv/latest/ttlv/trait.Encodable.html
/// [`TagEncodable`]: https://docs.rs/ttlv/latest/ttlv/trait.TagEncodable.html
#[proc_macro_derive(Encodable, attributes(ttlv))]
pub fn derive_encodable_fn(item: TokenStream) -> TokenStream {
    match derive_encodable_fn2(item.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.into_compile_error().into(),
    }
}

/// Derives [`Decodable`] and [`TagDecodable`] for structs and TTLV enums.
///
/// Struct-like enums (enums without `#[ttlv(enum)]`) are not supported —
/// the TTLV wire format does not carry a variant discriminator at this layer,
/// so the macro cannot generate a decoder for them. Use [`Encodable`] alone
/// for those types and model the decode side with a concrete struct.
///
/// [`Decodable`]: https://docs.rs/ttlv/latest/ttlv/trait.Decodable.html
/// [`TagDecodable`]: https://docs.rs/ttlv/latest/ttlv/trait.TagDecodable.html
/// [`Encodable`]: macro@Encodable
#[proc_macro_derive(Decodable, attributes(ttlv))]
pub fn derive_decodable_fn(item: TokenStream) -> TokenStream {
    match derive_decodable_fn2(item.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.into_compile_error().into(),
    }
}

/// Derives inherent `name() -> &str` and [`Display`](std::fmt::Display) for
/// TTLV Enumeration types.
///
/// Requires `#[ttlv(enum)]` on the enum. Each variant must be a unit variant
/// with an explicit integer discriminant (e.g. `Variant = 0x01`), except
/// `#[ttlv(default)]` catch-all variants, which must wrap exactly one unnamed
/// field. `#[ttlv(rename = "...")]` overrides the string returned by
/// `name()` / `Display` for that variant.
#[proc_macro_derive(Enum, attributes(ttlv))]
pub fn derive_enum_fn(item: TokenStream) -> TokenStream {
    match derive_enum_fn2(item.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.into_compile_error().into(),
    }
}
