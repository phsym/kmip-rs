# pkcs11-kmip

> This crate is a **WORK IN PROGRESS** and is not published to crates.io.

A PKCS#11 v2.40 provider that translates Cryptoki calls into KMIP requests
issued against a remote KMIP server. The crate is built as a C dynamic
library (`cdylib`) and is loaded by any PKCS#11-aware application
(e.g. `pkcs11-tool`, `softhsm2-util`, OpenSSL `pkcs11` engine/provider,
Java's SunPKCS11, Mozilla NSS, the `cryptoki` Rust crate, …).

Internally the provider opens one TLS connection to the KMIP endpoint per
PKCS#11 session and uses the [`kmip`](../kmip) workspace client to drive
key management and cryptographic operations.

## Building

The crate is a member of the `kmip-rs` workspace. From the workspace root:

```sh
# Debug build (loaded by the integration tests and examples)
cargo build -p pkcs11-kmip

# Release build
cargo build -p pkcs11-kmip --release
```

The build produces a shared library under `target/<profile>/`:

| Platform | Output                                          |
| -------- | ----------------------------------------------- |
| Linux    | `target/<profile>/libpkcs11_kmip.so`            |
| macOS    | `target/<profile>/libpkcs11_kmip.dylib`         |
| Windows  | `target/<profile>/pkcs11_kmip.dll`              |

Point your PKCS#11 host application at that path to load the provider.

Minimum supported Rust version: **1.88.0** (edition 2024), as set at the
[workspace level](../Cargo.toml).

## Configuration

The provider is configured exclusively through environment variables, read
once during `C_Initialize`. The host application's environment must therefore
contain these variables before it loads the module.

| Variable             | Required | Description                                                                                  |
| -------------------- | -------- | -------------------------------------------------------------------------------------------- |
| `PKCS11_KMIP_ENDPOINT` | yes    | `host:port` of the KMIP server (e.g. `kmip.example.com:5696`). The hostname is also used as the TLS SNI / server name. |
| `PKCS11_KMIP_CERT`     | yes    | Path to the PEM-encoded client certificate used for mTLS.                                    |
| `PKCS11_KMIP_KEY`      | yes    | Path to the PEM-encoded client private key matching `PKCS11_KMIP_CERT`.                      |
| `PKCS11_KMIP_CA`       | no     | Path to a PEM bundle of additional root certificates to trust. When unset, only the platform trust store is used. |
| `PKCS11_LOG_LEVEL`     | no     | `tracing` level filter for logs written to stderr: `off`, `error`, `warn`, `info`, `debug`, `trace`. Defaults to `off`. |

Example:

```sh
export PKCS11_KMIP_ENDPOINT=kmip.example.com:5696
export PKCS11_KMIP_CERT=/etc/kmip/client.pem
export PKCS11_KMIP_KEY=/etc/kmip/client.key
export PKCS11_KMIP_CA=/etc/kmip/ca.pem
export PKCS11_LOG_LEVEL=debug
```

If any required variable is missing or unreadable, `C_Initialize` returns
`CKR_ARGUMENTS_BAD`.

## Running the tests

The integration tests (`pkcs11-kmip/tests/*.rs`) `dlopen` the built shared
library from `target/<profile>/`, so the crate **must be built first** —
`cargo test` does not (re)build `cdylib` artifacts in a way the tests can
find them. They also require a reachable KMIP server, since each test opens a
real session and exercises operations end-to-end.

```sh
# 1. Build the cdylib so the tests can load it
cargo build -p pkcs11-kmip

# 2. Export the configuration (see above)
export PKCS11_KMIP_ENDPOINT=...
export PKCS11_KMIP_CERT=...
export PKCS11_KMIP_KEY=...
# export PKCS11_KMIP_CA=...        # optional
# export PKCS11_LOG_LEVEL=debug    # optional

# 3. Run the tests
cargo test -p pkcs11-kmip
```

For a release-mode test run, build and test with `--release`:

```sh
cargo build -p pkcs11-kmip --release
cargo test  -p pkcs11-kmip --release
```

The test suite currently covers:

- [`listing.rs`](tests/listing.rs) — slot, token, and mechanism enumeration.
- [`aes_encryption.rs`](tests/aes_encryption.rs) — AES key generation and
  ECB / CBC / CBC-PAD / GCM encrypt-decrypt roundtrips.
- [`rsa_signing.rs`](tests/rsa_signing.rs) — RSA key pair generation,
  `RSA_PKCS` / `RSA_PKCS_PSS` (with SHA-256/384/512) signing and verification.
- [`ecdsa_signing.rs`](tests/ecdsa_signing.rs) — EC key pair generation on
  P-256/P-384/P-521 and `ECDSA` / `ECDSA_SHAxxx` signing and verification.

## Running the example

[`examples/quickstart.rs`](examples/quickstart.rs) exercises the full provider
surface (generate AES, RSA, ECDSA keys; encrypt / decrypt; sign / verify) and
prints the intermediate values. Like the tests, it loads the shared library
from `target/<profile>/`, so the crate must be built first and the
`PKCS11_KMIP_*` environment variables must be set.

```sh
# 1. Build the cdylib
cargo build -p pkcs11-kmip

# 2. Configure (see above)
export PKCS11_KMIP_ENDPOINT=...
export PKCS11_KMIP_CERT=...
export PKCS11_KMIP_KEY=...

# 3. Run the example
cargo run -p pkcs11-kmip --example quickstart
```

For a release build, pass `--release` to both `cargo build` and
`cargo run`.

## What is implemented

### PKCS#11 functions

The provider exposes Cryptoki v2.40 (`CK_VERSION { major: 2, minor: 4 }`).
The complete list of supported and unsupported entry points is defined in
[`src/lib.rs`](src/lib.rs) (`FUNCLIST`).

| Category               | Implemented                                                                                                                 | Not supported                                                                                                  |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| General                | `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetFunctionList`                                                              | —                                                                                                              |
| Slot & token           | `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo`                              | `C_InitToken`, `C_InitPIN`, `C_SetPIN`, `C_WaitForSlotEvent`                                                   |
| Session                | `C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo`, `C_Login`, `C_Logout`                          | `C_GetOperationState`, `C_SetOperationState`                                                                   |
| Object management      | `C_DestroyObject`, `C_GetObjectSize`, `C_GetAttributeValue`, `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal`     | `C_CreateObject`, `C_CopyObject`, `C_SetAttributeValue`                                                        |
| Encryption / Decryption | `C_EncryptInit`, `C_Encrypt`, `C_DecryptInit`, `C_Decrypt`                                                                  | `C_EncryptUpdate`, `C_EncryptFinal`, `C_DecryptUpdate`, `C_DecryptFinal` (multi-part streaming)                |
| Sign / Verify          | `C_SignInit`, `C_Sign`, `C_VerifyInit`, `C_Verify`                                                                          | `C_SignUpdate`, `C_SignFinal`, `C_SignRecover*`, `C_VerifyUpdate`, `C_VerifyFinal`, `C_VerifyRecover*`         |
| Key management         | `C_GenerateKey`, `C_GenerateKeyPair`                                                                                        | `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`                                                                      |
| Random                 | `C_SeedRandom`, `C_GenerateRandom`                                                                                          | —                                                                                                              |
| Digest                 | —                                                                                                                           | `C_Digest*` (all digest functions)                                                                             |
| Dual-function          | —                                                                                                                           | `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate`               |
| Legacy / parallel      | `C_GetFunctionStatus`, `C_CancelFunction`                                                                                   | —                                                                                                              |

Unsupported entries return `CKR_FUNCTION_NOT_SUPPORTED`.

### Mechanisms

Mechanisms are declared in [`src/slot.rs`](src/slot.rs).

| Mechanism                                                                                  | Flags                  | Key size range (bits) |
| ------------------------------------------------------------------------------------------ | ---------------------- | --------------------- |
| `CKM_AES_KEY_GEN`                                                                          | `GENERATE`             | 128 – 256             |
| `CKM_AES_ECB`, `CKM_AES_CBC`, `CKM_AES_CBC_PAD`, `CKM_AES_GCM`                             | `ENCRYPT` \| `DECRYPT` | 128 – 256             |
| `CKM_RSA_PKCS_KEY_PAIR_GEN`                                                                | `GENERATE_KEY_PAIR`    | 1024 – 4096           |
| `CKM_RSA_PKCS`, `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`, `CKM_SHA512_RSA_PKCS`        | `SIGN` \| `VERIFY`     | 1024 – 4096           |
| `CKM_RSA_PKCS_PSS`, `CKM_SHA256_RSA_PKCS_PSS`, `CKM_SHA384_RSA_PKCS_PSS`, `CKM_SHA512_RSA_PKCS_PSS` | `SIGN` \| `VERIFY` | 1024 – 4096           |
| `CKM_EC_KEY_PAIR_GEN`                                                                      | `GENERATE_KEY_PAIR`    | 256 – 521             |
| `CKM_ECDSA`, `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384`, `CKM_ECDSA_SHA512`                    | `SIGN` \| `VERIFY`     | 256 – 521             |

Supported EC curves: `secp256r1` (P-256), `secp384r1` (P-384),
`secp521r1` (P-521).

### Object classes

- `CKO_SECRET_KEY` — AES symmetric keys (`CKK_AES`).
- `CKO_PUBLIC_KEY` / `CKO_PRIVATE_KEY` — RSA (`CKK_RSA`) and EC (`CKK_EC`)
  key pairs.

### Key attributes accepted at generation time

- `CKA_LABEL`, `CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_TOKEN`
- `CKA_ENCRYPT`, `CKA_DECRYPT`, `CKA_SIGN`, `CKA_VERIFY`, `CKA_WRAP`, `CKA_UNWRAP`
- `CKA_VALUE_LEN`, `CKA_MODULUS_BITS`, `CKA_EC_PARAMS` (named-curve OID encoded in DER)
- `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_PRIVATE`
- `CKA_PUBLIC_EXPONENT` is parsed but ignored — the server selects the
  RSA public exponent.

### Notable limitations

- No multi-part `*Update` / `*Final` operations — all crypto operations
  are single-shot `C_Encrypt` / `C_Decrypt` / `C_Sign` / `C_Verify`.
- No digest, MAC, key wrapping, key derivation, key import (`C_CreateObject`),
  or attribute modification (`C_SetAttributeValue`).
- A single slot (slot id `0`) is exposed; PIN management is not implemented
  (`CKF_PROTECTED_AUTHENTICATION_PATH` is reported).
- `C_Login` is a local toggle that gates visibility of private objects in
  `C_FindObjects`; authentication to the KMIP server is performed via mTLS
  at connection time, not via PKCS#11 PIN.

## License

Licensed under either of Apache-2.0 or MIT, at your option, the same as the
rest of the [`kmip-rs`](../README.md) workspace.
