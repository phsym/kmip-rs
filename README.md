# kmip-rs

> This project is a **WORK IN PROGRESS**

[![Test](https://github.com/phsym/kmip-rs/actions/workflows/test.yaml/badge.svg)](https://github.com/phsym/kmip-rs/actions/workflows/test.yaml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

A pure-Rust implementation of the [OASIS Key Management Interoperability
Protocol (KMIP)](https://www.oasis-open.org/committees/kmip/), targeting
KMIP 1.0–1.4. The workspace provides a typed synchronous client, server-side
primitives for building a KMIP service, and the underlying TTLV
(Tag-Type-Length-Value) codec as a standalone crate that can be reused in
isolation.

## Workspace layout

| Crate         | Description                                                                                          |
| ------------- | ---------------------------------------------------------------------------------------------------- |
| `kmip`        | KMIP protocol types, request/response payloads, attributes, and a synchronous TLS client and server. |
| `ttlv`        | Standalone KMIP TTLV (binary and XML) encoder/decoder, with a `Stream` adapter for I/O.              |
| `ttlv-derive` | Proc-macro crate providing `#[derive(Encodable, Decodable, Enum)]`.                                  |

## Installation

The crates are not yet published to crates.io. Add as git dependencies:

```toml
[dependencies]
kmip = { git = "https://github.com/phsym/kmip-rs" }
```

## Quick start

Connect to a KMIP server with rustls (the default TLS backend) and create an
AES-256 symmetric key:

```rust,no_run
# use kmip::{
#     CryptographicUsageMask,
#     attributes::{Attribute, CryptographicLength},
#     client::ClientBuilder,
#     enums::{CryptographicAlgorithm, ObjectType},
#     payloads::CreateRequestPayload,
#     types::TemplateAttribute,
# };
#
# fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ClientBuilder::new()
        .add_root_certificate_file("ca.pem")?
        .identity_file("client.pem", "client.key")?
        .connect_rustls("kmip.example.com:5696", "kmip.example.com")?;

    let response = client.request(CreateRequestPayload {
        object_type: ObjectType::SymmetricKey,
        attributes: TemplateAttribute::new(vec![
            Attribute::new(CryptographicAlgorithm::AES),
            Attribute::new(CryptographicLength(256)),
            Attribute::new(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt,
            ),
        ]),
    })?;

    println!("created key: {:?}", response);
#     Ok(())
# }
```

The same operation written with the fluent helpers on `Client`:

```rust,no_run
# use kmip::{CryptographicUsageMask, client::ClientBuilder};
#
# fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = ClientBuilder::new()
        .add_root_certificate_file("ca.pem")?
        .identity_file("client.pem", "client.key")?
        .connect_rustls("kmip.example.com:5696", "kmip.example.com")?;

    let response = client
        .create()
        .aes(256, CryptographicUsageMask::Encrypt | CryptographicUsageMask::Decrypt)
        .exec()?;

    println!("created key: {:?}", response);
#     Ok(())
# }
```

Each operation has a dedicated builder under [`client::exec`](kmip/src/client/exec)
(`create`, `create_keypair`, `register`, `rekey`, `locate`, `get`, `encrypt`,
`decrypt`, `sign`, `add_attribute`, …). For batched requests use
`client.batch(...)`, and for raw `RequestMessage` exchange use
`client.roundtrip(&msg)`. Protocol version is auto-negotiated against the
server's `Discover Versions` response.

## TLS backends

The `kmip` crate compiles against several TLS implementations, selected via
mutually-exclusive Cargo features. Each backend exposes its own builder method:

| Feature       | Backend       | Builder method         | Notes                                                       |
| ------------- | ------------- | ---------------------- | ----------------------------------------------------------- |
| `tls-rustls`  | rustls        | `connect_rustls(...)`  | **Default.** Pure Rust, uses the platform trust store.      |
| `tls-native`  | native-tls    | `connect_native(...)`  | Delegates to the OS (SChannel / SecureTransport / OpenSSL). |
| `tls-openssl` | openssl crate | `connect_openssl(...)` | Requires a system OpenSSL.                                  |
| `tls-boring`  | BoringSSL     | `connect_boring(...)`  | Useful when matching a BoringSSL-based server stack.        |

## Optional features

| Feature               | Default | Effect                                                                        |
| --------------------- | ------- | ----------------------------------------------------------------------------- |
| `tls-rustls`          | yes     | Enables the rustls client backend (see above).                                |
| `uuid`                | yes     | Implements unique-identifier helpers using the `uuid` crate.                  |
| `serde`               | no      | Derives `serde::Serialize` on protocol types for logging/inspection.          |
| `arbitrary`           | no      | Derives `arbitrary::Arbitrary` for fuzzing.                                   |
| `interop-rust-crypto` | no      | Cryptographic interop using pure-Rust crates (`rsa`, `p256`, `p384`, `p521`). |
| `interop-openssl`     | no      | Cryptographic interop using OpenSSL.                                          |
| `interop-boring`      | no      | Cryptographic interop using BoringSSL.                                        |

The `ttlv` crate has its own feature flags (`xml`, `text`, `derive`, `chrono`,
`serde`, `arbitrary`, `bitflags`) — see [`ttlv/Cargo.toml`](ttlv/Cargo.toml).

## Minimum supported Rust version

**Rust 1.88.0**, edition 2024. The MSRV is checked in CI; bumping it is
considered a non-breaking change.

## Implementation status

> **Legend:**
>
> - N/A : Not Applicable
> - ✅ : Fully compatible
> - ❌ : Not implemented or reviewed
> - 🚧 : Work in progress / Partially compatible
> - 💀 : Deprecated

### Messages

|                  | v1.0 | v1.1 | v1.2 | v1.3 | v1.4 |
| ---------------- | ---- | ---- | ---- | ---- | ---- |
| Request Message  | ✅   | ✅   | ✅   | ✅   | ✅   |
| Response Message | ✅   | ✅   | ✅   | ✅   | ✅   |

### Operations

| Operation            | v1.0 | v1.1 | v1.2 | v1.3 | v1.4 |
| -------------------- | ---- | ---- | ---- | ---- | ---- |
| Create               | ✅   | ✅   | ✅   | ✅   | ✅   |
| Create Key Pair      | ✅   | ✅   | ✅   | ✅   | ✅   |
| Register             | ✅   | ✅   | ✅   | ✅   | ✅   |
| Re-key               | ✅   | ✅   | ✅   | ✅   | ✅   |
| DeriveKey            | ❌   | ❌   | ❌   | ❌   | ❌   |
| Certify              | ❌   | ❌   | ❌   | ❌   | ❌   |
| Re-certify           | ❌   | ❌   | ❌   | ❌   | ❌   |
| Locate               | ✅   | ✅   | ✅   | ✅   | ✅   |
| Check                | ❌   | ❌   | ❌   | ❌   | ❌   |
| Get                  | ✅   | ✅   | ✅   | ✅   | ✅   |
| Get Attributes       | ✅   | ✅   | ✅   | ✅   | ✅   |
| Get Attribute List   | ✅   | ✅   | ✅   | ✅   | ✅   |
| Add Attribute        | ✅   | ✅   | ✅   | ✅   | ✅   |
| Modify Attribute     | ✅   | ✅   | ✅   | ✅   | ✅   |
| Delete Attribute     | ✅   | ✅   | ✅   | ✅   | ✅   |
| Obtain Lease         | ✅   | ✅   | ✅   | ✅   | ✅   |
| Get Usage Allocation | ✅   | ✅   | ✅   | ✅   | ✅   |
| Activate             | ✅   | ✅   | ✅   | ✅   | ✅   |
| Revoke               | ✅   | ✅   | ✅   | ✅   | ✅   |
| Destroy              | ✅   | ✅   | ✅   | ✅   | ✅   |
| Archive              | ✅   | ✅   | ✅   | ✅   | ✅   |
| Recover              | ✅   | ✅   | ✅   | ✅   | ✅   |
| Validate             | ❌   | ❌   | ❌   | ❌   | ❌   |
| Query                | ✅   | ✅   | ✅   | ✅   | ✅   |
| Cancel               | ❌   | ❌   | ❌   | ❌   | ❌   |
| Poll                 | ❌   | ❌   | ❌   | ❌   | ❌   |
| Notify               | ❌   | ❌   | ❌   | ❌   | ❌   |
| Put                  | ❌   | ❌   | ❌   | ❌   | ❌   |
| Discover             | N/A  | ✅   | ✅   | ✅   | ✅   |
| Re-key Key Pair      | N/A  | ✅   | ✅   | ✅   | ✅   |
| Encrypt              | N/A  | N/A  | ✅   | ✅   | ✅   |
| Decrypt              | N/A  | N/A  | ✅   | ✅   | ✅   |
| Sign                 | N/A  | N/A  | ✅   | ✅   | ✅   |
| Signature Verify     | N/A  | N/A  | ✅   | ✅   | ✅   |
| MAC                  | N/A  | N/A  | ❌   | ❌   | ❌   |
| MAC Verify           | N/A  | N/A  | ❌   | ❌   | ❌   |
| RNG Retrieve         | N/A  | N/A  | ❌   | ❌   | ❌   |
| RNG Seed             | N/A  | N/A  | ❌   | ❌   | ❌   |
| Hash                 | N/A  | N/A  | ❌   | ❌   | ❌   |
| Create Split Key     | N/A  | N/A  | ❌   | ❌   | ❌   |
| Join Split Key       | N/A  | N/A  | ❌   | ❌   | ❌   |
| Export               | N/A  | N/A  | N/A  | N/A  | ✅   |
| Import               | N/A  | N/A  | N/A  | N/A  | ✅   |

### Managed Objects

| Object        | v1.0 | v1.1 | v1.2 | v1.3 | v1.4 |
| ------------- | ---- | ---- | ---- | ---- | ---- |
| Certificate   | ✅   | ✅   | ✅   | ✅   | ✅   |
| Symmetric Key | ✅   | ✅   | ✅   | ✅   | ✅   |
| Public Key    | ✅   | ✅   | ✅   | ✅   | ✅   |
| Private Key   | ✅   | ✅   | ✅   | ✅   | ✅   |
| Split Key     | ✅   | ✅   | ✅   | ✅   | ✅   |
| Template      | ✅   | ✅   | ✅   | 💀   | 💀   |
| Secret Data   | ✅   | ✅   | ✅   | ✅   | ✅   |
| Opaque Object | ✅   | ✅   | ✅   | ✅   | ✅   |
| PGP Key       | N/A  | N/A  | ✅   | ✅   | ✅   |

### Base Objects

| Object                                   | v1.0 | v1.1 | v1.2 | v1.3 | v1.4 |
| ---------------------------------------- | ---- | ---- | ---- | ---- | ---- |
| Attribute                                | ✅   | ✅   | ✅   | ✅   | ✅   |
|  Credential                              | ✅   | ✅   | ✅   | ✅   | ✅   |
|  Key Block                               | ✅   | ✅   | ✅   | ✅   | ✅   |
| Key Value                                | ✅   | ✅   | ✅   | ✅   | ✅   |
| Key Wrapping Data                        | ✅   | ✅   | ✅   | ✅   | ✅   |
| Key Wrapping Specification               | ✅   | ✅   | ✅   | ✅   | ✅   |
| Transparent Key Structures               | 🚧   | 🚧   | 🚧   | 🚧   | 🚧   |
| Template-Attribute Structures            | ✅   | ✅   | ✅   | ✅   | ✅   |
| Extension Information                    | N/A  | ✅   | ✅   | ✅   | ✅   |
| Data                                     | N/A  | N/A  | ✅   | ✅   | ✅   |
| Data Length                              | N/A  | N/A  | ❌   | ❌   | ❌   |
| Signature Data                           | N/A  | N/A  | ✅   | ✅   | ✅   |
| MAC Data                                 | N/A  | N/A  | ❌   | ❌   | ❌   |
| Nonce                                    | N/A  | N/A  | ✅   | ✅   | ✅   |
| Correlation Value                        | N/A  | N/A  | N/A  | ✅   | ✅   |
| Init Indicator                           | N/A  | N/A  | N/A  | ✅   | ✅   |
| Final Indicator                          | N/A  | N/A  | N/A  | ✅   | ✅   |
| RNG Parameter                            | N/A  | N/A  | N/A  | ✅   | ✅   |
| Profile Information                      | N/A  | N/A  | N/A  | ✅   | ✅   |
| Validation Information                   | N/A  | N/A  | N/A  | ✅   | ✅   |
| Capability Information                   | N/A  | N/A  | N/A  | ✅   | ✅   |
| Authenticated Encryption Additional Data | N/A  | N/A  | N/A  | N/A  | ✅   |
| Authenticated Encryption Tag             | N/A  | N/A  | N/A  | N/A  | ✅   |

#### Transparent Key Structures

| Object                   | v1.0 | v1.1 | v1.2 | v1.3 | v1.4 |
| ------------------------ | ---- | ---- | ---- | ---- | ---- |
| Symmetric Key            | ✅   | ✅   | ✅   | ✅   | ✅   |
| DSA Private/Public Key   | ❌   | ❌   | ❌   | ❌   | ❌   |
| RSA Private/Public Key   | ✅   | ✅   | ✅   | ✅   | ✅   |
| DH Private/Public Key    | ❌   | ❌   | ❌   | ❌   | ❌   |
| ECDSA Private/Public Key | ✅   | ✅   | ✅   | 💀   | 💀   |
| ECDH Private/Public Key  | ❌   | ❌   | ❌   | 💀   | 💀   |
| ECMQV Private/Public     | ❌   | ❌   | ❌   | 💀   | 💀   |
| EC Private/Public        | N/A  | N/A  | N/A  | ✅   | ✅   |

### Attributes

| Attribute                        | v1.0 | v1.1 | v1.2 | v1.3 | v1.4 |
| -------------------------------- | ---- | ---- | ---- | ---- | ---- |
| Unique Identifier                | ✅   | ✅   | ✅   | ✅   | ✅   |
| Name                             | ✅   | ✅   | ✅   | ✅   | ✅   |
| Object Type                      | ✅   | ✅   | ✅   | ✅   | ✅   |
| Cryptographic Algorithm          | ✅   | ✅   | ✅   | ✅   | ✅   |
| Cryptographic Length             | ✅   | ✅   | ✅   | ✅   | ✅   |
| Cryptographic Parameters         | ✅   | ✅   | ✅   | ✅   | ✅   |
| Cryptographic Domain Parameters  | ✅   | ✅   | ✅   | ✅   | ✅   |
| Certificate Type                 | ✅   | ✅   | ✅   | ✅   | ✅   |
| Certificate Identifier           | ✅   | 💀   | 💀   | 💀   | 💀   |
| Certificate Subject              | ✅   | 💀   | 💀   | 💀   | 💀   |
| Certificate Issuer               | ✅   | 💀   | 💀   | 💀   | 💀   |
| Digest                           | ✅   | ✅   | ✅   | ✅   | ✅   |
| Operation Policy Name            | ✅   | ✅   | ✅   | 💀   | 💀   |
| Cryptographic Usage Mask         | ✅   | ✅   | ✅   | ✅   | ✅   |
| Lease Time                       | ✅   | ✅   | ✅   | ✅   | ✅   |
| Usage Limits                     | ✅   | ✅   | ✅   | ✅   | ✅   |
| State                            | ✅   | ✅   | ✅   | ✅   | ✅   |
| Initial Date                     | ✅   | ✅   | ✅   | ✅   | ✅   |
| Activation Date                  | ✅   | ✅   | ✅   | ✅   | ✅   |
| Process Start Date               | ✅   | ✅   | ✅   | ✅   | ✅   |
| Protect Stop Date                | ✅   | ✅   | ✅   | ✅   | ✅   |
| Deactivation Date                | ✅   | ✅   | ✅   | ✅   | ✅   |
| Destroy Date                     | ✅   | ✅   | ✅   | ✅   | ✅   |
| Compromise Occurrence Date       | ✅   | ✅   | ✅   | ✅   | ✅   |
| Compromise Date                  | ✅   | ✅   | ✅   | ✅   | ✅   |
| Revocation Reason                | ✅   | ✅   | ✅   | ✅   | ✅   |
| Archive Date                     | ✅   | ✅   | ✅   | ✅   | ✅   |
| Object Group                     | ✅   | ✅   | ✅   | ✅   | ✅   |
| Link                             | ✅   | ✅   | ✅   | ✅   | ✅   |
| Application Specific Information | ✅   | ✅   | ✅   | ✅   | ✅   |
| Contact Information              | ✅   | ✅   | ✅   | ✅   | ✅   |
| Last Change Date                 | ✅   | ✅   | ✅   | ✅   | ✅   |
| Custom Attribute                 | ✅   | ✅   | ✅   | ✅   | ✅   |
| Certificate Length               | N/A  | ✅   | ✅   | ✅   | ✅   |
| X.509 Certificate Identifier     | N/A  | ✅   | ✅   | ✅   | ✅   |
| X.509 Certificate Subject        | N/A  | ✅   | ✅   | ✅   | ✅   |
| X.509 Certificate Issuer         | N/A  | ✅   | ✅   | ✅   | ✅   |
| Digital Signature Algorithm      | N/A  | ✅   | ✅   | ✅   | ✅   |
| Fresh                            | N/A  | ✅   | ✅   | ✅   | ✅   |
| Alternative Name                 | N/A  | N/A  | ✅   | ✅   | ✅   |
| Key Value Present                | N/A  | N/A  | ✅   | ✅   | ✅   |
| Key Value Location               | N/A  | N/A  | ✅   | ✅   | ✅   |
| Original Creation Date           | N/A  | N/A  | ✅   | ✅   | ✅   |
| Random Number Generator          | N/A  | N/A  | N/A  | ✅   | ✅   |
| PKCS#12 Friendly Name            | N/A  | N/A  | N/A  | N/A  | ✅   |
| Description                      | N/A  | N/A  | N/A  | N/A  | ✅   |
| Comment                          | N/A  | N/A  | N/A  | N/A  | ✅   |
| Sensitive                        | N/A  | N/A  | N/A  | N/A  | ✅   |
| Always Sensitive                 | N/A  | N/A  | N/A  | N/A  | ✅   |
| Extractable                      | N/A  | N/A  | N/A  | N/A  | ✅   |
| Never Extractable                | N/A  | N/A  | N/A  | N/A  | ✅   |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
