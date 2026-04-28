# ttlv

[![Test](https://github.com/phsym/kmip-rs/actions/workflows/test.yaml/badge.svg)](https://github.com/phsym/kmip-rs/actions/workflows/test.yaml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Tag-Type-Length-Value (TTLV) encoder/decoder.

TTLV is the binary wire format defined by the OASIS Key Management
Interoperability Protocol (KMIP). Each item is a 3-byte tag, a 1-byte type,
a 4-byte big-endian length, and a value padded to a multiple of 8 bytes.
This crate is a self-contained implementation that can be used outside of
KMIP — application code defines its own tags and types.

## What it provides

- [`TtlvEncoder`] / [`TtlvDecoder`] for the canonical KMIP binary form.
- [`XmlEncoder`] / [`XmlDecoder`] for the XML representation defined in
  _KMIP Additional Message Encodings_ (feature `xml`).
- [`TextEncoder`] for a human-readable, debug-oriented form (feature `text`).
- [`Encodable`] / [`Decodable`] traits, plus `#[derive(Encodable, Decodable, Enum)]`
  procedural macros (feature `derive`) for mapping Rust structs and enums
  to TTLV.
- [`Stream`] — a length-prefixed framing adapter over any `Read + Write`.

## Example

Encode a struct to bytes and decode it back:

```rust
use ttlv::{Decodable, Encodable, TtlvDecoder, TtlvEncoder};

#[derive(Debug, PartialEq, Encodable, Decodable)]
#[ttlv(tag = 0x420001)]
struct Greeting {
    #[ttlv(tag = 0x420002)]
    code: i32,
    #[ttlv(tag = 0x420003)]
    message: String,
}

let original = Greeting { code: 42, message: "hello".into() };

let mut enc = TtlvEncoder::new();
original.encode(&mut enc).unwrap();

let mut dec = TtlvDecoder::new(enc.bytes());
let decoded = Greeting::decode(&mut dec).unwrap();

assert_eq!(original, decoded);
```

Working with the encoder directly is also possible — the [`Encoder`] and
[`Decoder`] traits expose one method per TTLV primitive type:

```rust
use ttlv::{Encoder, TtlvEncoder};

let mut enc = TtlvEncoder::new();
enc.write_struct(0x420020u32, |s| {
    s.write_integer(0x420004u32, 254)?;
    s.write_string(0x420005u32, "hi")?;
    Ok(())
}).unwrap();
```

## Cargo features

All features are opt-in — the default set is empty, so consumers pull in
only the encoders, derives, and integrations they actually use. Enable
what you need via `features = [...]`:

```toml
[dependencies]
ttlv = { version = "*", features = ["derive", "xml", "chrono"] }
```

| Feature     | Default | Effect                                                     |
| ----------- | ------- | ---------------------------------------------------------- |
| `derive`    | no      | Re-exports [`Encodable`], [`Decodable`], [`Enum`] derives. |
| `xml`       | no      | Enables [`XmlEncoder`] / [`XmlDecoder`] (implies `chrono`).|
| `text`      | no      | Enables [`TextEncoder`] (implies `chrono`).                |
| `chrono`    | no      | `TagEncodable`/`TagDecodable` impls for `chrono` types.    |
| `bitflags`  | no      | [`Bitmask`] integration with the `bitflags` crate.         |
| `serde`     | no      | Derives `serde::Serialize` on TTLV value types.            |
| `arbitrary` | no      | Derives `arbitrary::Arbitrary` for fuzzing.                |
