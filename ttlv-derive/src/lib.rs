//! Proc-macro crate for deriving TTLV serialization/deserialization traits.
//!
//! This crate provides derive macros that plug into the traits defined in the
//! [`ttlv`](https://docs.rs/ttlv) crate. You normally pull them in via the
//! `ttlv` crate's `derive` feature (enabled by default) rather than depending
//! on `ttlv-derive` directly:
//!
//! ```toml
//! [dependencies]
//! ttlv = "*"
//! ```
//!
//! Then bring the derives into scope:
//!
//! ```ignore
//! use ttlv::{Encodable, Decodable, Enum};
//! ```
//!
//! # Macros
//!
//! | Derive                  | Generates                                                     |
//! |-------------------------|---------------------------------------------------------------|
//! | `#[derive(Encodable)]`  | `Encodable` and/or `TagEncodable` impls (+ `flatten_encode`)  |
//! | `#[derive(Decodable)]`  | `Decodable` and/or `TagDecodable` impls (+ `flatten_decode`)  |
//! | `#[derive(Enum)]`       | Inherent `name() -> &str` and [`Display`](std::fmt::Display)  |
//!
//! All three share the `#[ttlv(...)]` attribute namespace.
//!
//! # Attribute reference
//!
//! | Attribute              | Applies to          | Description                                                                  |
//! |------------------------|---------------------|------------------------------------------------------------------------------|
//! | `tag = <expr>`         | struct, field, enum | TTLV tag used for the tagged method (`tag_encode` / `tag_decode`)            |
//! | `flatten`              | struct, field, enum | Encode/decode fields inline, without a wrapping TTLV struct                  |
//! | `enum`                 | enum                | Selects the [TTLV Enumeration](#enums-the-two-shapes) wire format (unit variants + discriminants); without it the enum is a [struct-like sum](#enums-the-two-shapes) of payloads |
//! | `set_ext`              | field               | Store the field value in the extensions context (requires `Clone`)           |
//! | `if(<expr>)`           | field               | Conditionally encode/decode the field based on the extensions context        |
//! | `skip`                 | field               | Skip this field entirely; use `Default::default()` when decoding             |
//! | `default`              | enum variant        | Catch-all variant for unknown discriminants (wraps a single unnamed field)   |
//! | `rename = "..."`       | enum variant        | Override the string name of a variant                                        |
//!
//! `tag` and `flatten` are mutually exclusive on the same item.
//!
//! # What gets generated
//!
//! The encode and decode traits come in two flavors:
//!
//! - [`Encodable`] / [`Decodable`] — carry their own tag (top-level entry
//!   points for a type).
//! - [`TagEncodable`] / [`TagDecodable`] — receive a tag from the caller
//!   (used for fields, where the parent decides the tag).
//!
//! The macros pick which impls to emit based on the `#[ttlv(...)]` attribute
//! on the type:
//!
//! | Form                    | `TagEncodable` / `TagDecodable` | `Encodable` / `Decodable` | `flatten_encode` / `flatten_decode` |
//! |-------------------------|:-------------------------------:|:-------------------------:|:-----------------------------------:|
//! | no attribute            | ✔                               |                           | ✔                                   |
//! | `#[ttlv(tag = ...)]`    | ✔                               | ✔ (delegates to tagged)   | ✔                                   |
//! | `#[ttlv(flatten)]`      |                                 | ✔ (inlines fields)        | ✔                                   |
//!
//! [`Encodable`]: https://docs.rs/ttlv/latest/ttlv/trait.Encodable.html
//! [`Decodable`]: https://docs.rs/ttlv/latest/ttlv/trait.Decodable.html
//! [`TagEncodable`]: https://docs.rs/ttlv/latest/ttlv/trait.TagEncodable.html
//! [`TagDecodable`]: https://docs.rs/ttlv/latest/ttlv/trait.TagDecodable.html
//!
//! # Examples
//!
//! All snippets below have a counterpart fixture in
//! `ttlv-derive/tests/fixtures/pass/`, which is compiled by the `trybuild`
//! test suite. If you want to run them, look there.
//!
//! ## Tagged struct
//!
//! A struct with its own `#[ttlv(tag = ...)]` gets both the tagged and
//! untagged impls, so it can be used as a top-level message or as a field.
//!
//! ```ignore
//! use ttlv::{Encodable, Decodable};
//!
//! #[derive(Encodable, Decodable)]
//! #[ttlv(tag = 0x42_00_01u32)]
//! pub struct Message {
//!     #[ttlv(tag = 0x42_00_02u32)]
//!     pub id: i32,
//!     #[ttlv(tag = 0x42_00_03u32)]
//!     pub name: String,
//!     #[ttlv(tag = 0x42_00_04u32)]
//!     pub optional: Option<i64>,
//! }
//! ```
//!
//! `Option<T>` fields are encoded only when `Some`, and decode to `None` when
//! absent — this behavior comes from `ttlv`'s blanket impls, not the derive.
//!
//! ## Untagged struct
//!
//! Omit the struct-level `tag` to only generate the tagged impls. The caller
//! must supply a tag at each use site via `tag_encode` / `tag_decode`.
//!
//! ```ignore
//! # use ttlv::{Encodable, Decodable};
//! #[derive(Encodable, Decodable)]
//! pub struct Untagged {
//!     #[ttlv(tag = 0x42_00_30u32)]
//!     pub a: i32,
//!     #[ttlv(tag = 0x42_00_31u32)]
//!     pub b: i32,
//! }
//! ```
//!
//! ## Flattened struct (struct-level)
//!
//! `#[ttlv(flatten)]` on the struct emits its fields inline at the parent's
//! level — no wrapping TTLV struct is written. Useful for splitting a flat
//! message across multiple Rust types.
//!
//! ```ignore
//! # use ttlv::{Encodable, Decodable};
//! #[derive(Encodable, Decodable)]
//! #[ttlv(flatten)]
//! pub struct Flat {
//!     #[ttlv(tag = 0x42_00_11u32)]
//!     pub a: i32,
//!     #[ttlv(tag = 0x42_00_12u32)]
//!     pub b: String,
//! }
//! ```
//!
//! ## Flattened field (field-level)
//!
//! `#[ttlv(flatten)]` on a field inlines the inner type's fields into the
//! outer struct body. The inner type must also derive `Encodable`/`Decodable`
//! so that its `flatten_encode` / `flatten_decode` inherent methods exist.
//!
//! ```ignore
//! # use ttlv::{Encodable, Decodable};
//! #[derive(Encodable, Decodable)]
//! #[ttlv(tag = 0x42_00_20u32)]
//! pub struct Inner {
//!     #[ttlv(tag = 0x42_00_21u32)]
//!     pub a: i32,
//!     #[ttlv(tag = 0x42_00_22u32)]
//!     pub b: String,
//! }
//!
//! #[derive(Encodable, Decodable)]
//! #[ttlv(tag = 0x42_00_10u32)]
//! pub struct Outer {
//!     #[ttlv(flatten)]
//!     pub inner: Inner,
//!     #[ttlv(tag = 0x42_00_13u32)]
//!     pub extra: i32,
//! }
//! ```
//!
//! ## Conditional fields: `set_ext` + `if`
//!
//! `set_ext` stores a field's value in the encoder/decoder's extensions
//! context. Later fields can then gate themselves on that state via `if(...)`.
//! The `if` expression has a local binding named `_ext` of type
//! `&mut Extensions`.
//! This is how version-dependent fields are expressed without creating a new
//! type per protocol version.
//!
//! ```ignore
//! # use ttlv::{Encodable, Decodable};
//! #[derive(Encodable, Decodable)]
//! #[ttlv(tag = 0x42_00_40u32)]
//! pub struct WithAttrs {
//!     #[ttlv(tag = 0x42_00_41u32, set_ext)]
//!     pub version: i32,
//!
//!     // Only encoded/decoded when the previously decoded `version >= 2`.
//!     #[ttlv(tag = 0x42_00_42u32, if(_ext.get::<i32>().is_some_and(|v| *v >= 2)))]
//!     pub conditional: Option<i32>,
//!
//!     // Never touched by the derive; gets `Default::default()` on decode.
//!     #[ttlv(skip)]
//!     pub computed: i32,
//! }
//! ```
//!
//! `set_ext` requires the field type to implement `Clone` (the value is
//! cloned into the extensions before encoding / after decoding). The macro
//! adds a targeted `where <field_ty>: Clone` bound so a missing `Clone` impl
//! is reported at the field, not at the derive call site.
//!
//! ## Named tags via a user-defined enum
//!
//! `#[ttlv(tag = <expr>)]` accepts any expression that evaluates to a type
//! implementing [`ttlv::Tag`], so raw `u32` literals are not the only option.
//! Real protocols typically define one big enum of named tags and use
//! `Tags::Foo` wherever a tag is needed — this is the pattern the `kmip`
//! crate uses for its [`Tags`](https://docs.rs/kmip/latest/kmip/enum.Tags.html)
//! enum.
//!
//! The enum just needs a `Tag` impl (`numeric()` + `name()`); `ttlv-derive`
//! doesn't provide one for you here, because the KMIP-style use case benefits
//! from reusing something like `strum` for the name mapping. A minimal
//! hand-rolled version:
//!
//! ```ignore
//! use ttlv::{Encodable, Decodable, Tag};
//!
//! #[derive(Clone, Copy)]
//! #[repr(u32)]
//! pub enum Tags {
//!     Message = 0x42_00_A0,
//!     Id = 0x42_00_A1,
//!     Name = 0x42_00_A2,
//!     Nested = 0x42_00_A3,
//!     Value = 0x42_00_A4,
//! }
//!
//! impl Tag for Tags {
//!     fn numeric(&self) -> Option<u32> { Some(*self as u32) }
//!     fn name(&self) -> Option<&str> {
//!         Some(match self {
//!             Self::Message => "Message",
//!             Self::Id => "Id",
//!             Self::Name => "Name",
//!             Self::Nested => "Nested",
//!             Self::Value => "Value",
//!         })
//!     }
//! }
//!
//! #[derive(Encodable, Decodable)]
//! #[ttlv(tag = Tags::Nested)]
//! pub struct Nested {
//!     #[ttlv(tag = Tags::Value)]
//!     pub value: i32,
//! }
//!
//! #[derive(Encodable, Decodable)]
//! #[ttlv(tag = Tags::Message)]
//! pub struct Message {
//!     #[ttlv(tag = Tags::Id)]
//!     pub id: i32,
//!     #[ttlv(tag = Tags::Name)]
//!     pub name: String,
//!     #[ttlv(tag = Tags::Nested)]
//!     pub nested: Nested,
//! }
//! ```
//!
//! The `kmip` crate follows the same shape but pulls in `strum_macros`
//! (`IntoStaticStr`, `EnumString`, `FromRepr`) to auto-generate the name
//! mapping and the inverse `RawTag -> Tags` lookup used during decoding.
//! Pair the tag enum with [`#[ttlv(if(_ext.is_in(ProtocolVersion::V1_4..)))]`](#conditional-fields-set_ext--if)
//! and you get the KMIP-style version-gated schema straight from the struct
//! definition.
//!
//! [`ttlv::Tag`]: https://docs.rs/ttlv/latest/ttlv/trait.Tag.html
//!
//! ## Generic containers
//!
//! `Vec<T>`, `Option<T>`, `Struct<T>`, and `Value<T>` all implement the ttlv
//! traits (blanket impls in the `ttlv` crate), so they can appear as field
//! types without any extra attributes:
//!
//! ```ignore
//! # use ttlv::{Encodable, Decodable, RawTag, Struct, Value};
//! #[derive(Encodable, Decodable)]
//! #[ttlv(tag = 0x42_00_90u32)]
//! pub struct Leaf {
//!     #[ttlv(tag = 0x42_00_91u32)]
//!     pub value: i32,
//! }
//!
//! #[derive(Encodable, Decodable)]
//! #[ttlv(tag = 0x42_00_92u32)]
//! pub struct Container {
//!     #[ttlv(tag = 0x42_00_93u32)]
//!     pub leaves: Vec<Leaf>,
//!     #[ttlv(tag = 0x42_00_94u32)]
//!     pub maybe: Option<Leaf>,
//!     #[ttlv(tag = 0x42_00_95u32)]
//!     pub raw_struct: Struct<RawTag>,
//!     #[ttlv(tag = 0x42_00_96u32)]
//!     pub raw_value: Value<RawTag>,
//! }
//! ```
//!
//! ## Enums: the two shapes
//!
//! A Rust `enum` can map to two very different TTLV wire formats, and the
//! macros can't tell them apart from the variant shapes alone. The
//! `#[ttlv(enum)]` attribute is the explicit switch:
//!
//! | Attribute                    | Wire representation                                             | Variant shape                               | `Decodable` | `#[derive(Enum)]` |
//! |------------------------------|-----------------------------------------------------------------|---------------------------------------------|:-----------:|:-----------------:|
//! | `#[ttlv(enum)]`              | TTLV **Enumeration** — a single 32-bit integer value            | Unit only, explicit integer discriminants   | ✔           | ✔                 |
//! | *(no attribute)*             | The selected variant's payload, inlined or wrapped in a struct  | Each variant carries a payload              |             |                   |
//!
//! In the first case the wire carries a discriminant number (optionally with
//! its name); in the second there is no discriminator on the wire — the
//! enum is just a Rust-side choice between different payload types, and
//! encoding defers to whichever variant is active. That's why `Decodable`
//! is only supported for the first shape: without a wire discriminator, the
//! decoder has nothing to dispatch on.
//!
//! ### TTLV enums (`#[ttlv(enum)]`)
//!
//! Unit variants with explicit integer discriminants, serialized as a TTLV
//! Enumeration value. Use `#[derive(Enum)]` alongside to also get `name()`
//! and `Display`.
//!
//! ```ignore
//! # use ttlv::{Encodable, Decodable, Enum, RawTag};
//! #[derive(Clone, Enum, Encodable, Decodable)]
//! #[ttlv(enum, tag = 0x42_00_50u32)]
//! #[repr(u32)]
//! pub enum Operation {
//!     Create = 0x01,
//!     Destroy = 0x02,
//!
//!     // Override the variant's string name (shown by Display / emitted in
//!     // textual TTLV encodings).
//!     #[ttlv(rename = "Archive (legacy)")]
//!     Archive = 0x03,
//!
//!     // Catch-all for unknown discriminants during decoding. Must wrap
//!     // exactly one unnamed field (typically `RawTag`).
//!     #[ttlv(default)]
//!     Unknown(RawTag),
//! }
//! ```
//!
//! Dropping the `tag = ...` gives you a TTLV enum that always receives a tag
//! from its caller — appropriate when the same enum is reused under multiple
//! tags:
//!
//! ```ignore
//! # use ttlv::{Encodable, Decodable, Enum};
//! #[derive(Enum, Encodable, Decodable)]
//! #[ttlv(enum)]
//! #[repr(u32)]
//! pub enum Status {
//!     Ok = 1,
//!     Failed = 2,
//! }
//! ```
//!
//! ## Struct-like enums
//!
//! An enum *without* `#[ttlv(enum)]` is a sum over payload-carrying variants.
//! Only `Encodable` is supported for this shape (decoding would require a
//! discriminator the TTLV wire format doesn't provide at this layer).
//!
//! A tagged struct-like enum wraps each variant's payload in its own TTLV
//! struct:
//!
//! ```ignore
//! # use ttlv::Encodable;
//! #[derive(Encodable)]
//! #[ttlv(tag = 0x42_00_70u32)]
//! pub struct LoginDetails {
//!     #[ttlv(tag = 0x42_00_71u32)]
//!     pub user: String,
//! }
//!
//! #[derive(Encodable)]
//! #[ttlv(tag = 0x42_00_72u32)]
//! pub struct TokenDetails {
//!     #[ttlv(tag = 0x42_00_73u32)]
//!     pub token: String,
//! }
//!
//! #[derive(Encodable)]
//! #[ttlv(tag = 0x42_00_74u32)]
//! pub enum AuthKind {
//!     Login(LoginDetails),
//!     Token(TokenDetails),
//! }
//! ```
//!
//! A flattened struct-like enum emits the selected variant's payload inline —
//! the canonical KMIP "Credential" pattern, where the payload shape changes
//! but the tag comes from the inner struct itself:
//!
//! ```ignore
//! # use ttlv::Encodable;
//! # #[derive(Encodable)]
//! # #[ttlv(tag = 0x42_00_60u32)]
//! # pub struct UserPassword { #[ttlv(tag = 0x42_00_61u32)] pub username: String }
//! # #[derive(Encodable)]
//! # #[ttlv(tag = 0x42_00_62u32)]
//! # pub struct Token { #[ttlv(tag = 0x42_00_63u32)] pub value: String }
//! #[derive(Encodable)]
//! #[ttlv(flatten)]
//! pub enum Credential {
//!     UserPassword(UserPassword),
//!     Token(Token),
//! }
//! ```
//!
//! An untagged struct-like enum produces a `TagEncodable` impl only — the
//! caller passes the tag in at every use site:
//!
//! ```ignore
//! # use ttlv::Encodable;
//! # #[derive(Encodable)]
//! # #[ttlv(tag = 0x42_00_80u32)]
//! # pub struct Leaf { #[ttlv(tag = 0x42_00_81u32)] pub value: i32 }
//! #[derive(Encodable)]
//! pub enum Either {
//!     Left(Leaf),
//!     Right(Leaf),
//! }
//! ```

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
