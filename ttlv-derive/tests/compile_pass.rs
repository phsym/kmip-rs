//! Compile-pass tests for the `ttlv-derive` macros.
//!
//! Each `tests/fixtures/pass/*.rs` fixture exercises a valid derive input shape
//! and must compile cleanly (no errors, no warnings — fixtures deny warnings
//! at the crate level).

#[test]
fn compile_pass() {
    let t = trybuild::TestCases::new();
    t.pass("tests/fixtures/pass/*.rs");
}
