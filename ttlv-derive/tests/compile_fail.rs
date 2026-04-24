//! Compile-fail snapshot tests for the `ttlv-derive` macros.
//!
//! Each `tests/fixtures/fail/*.rs` fixture is compiled, and its stderr is matched
//! against the sibling `.stderr` snapshot. Do not hand-edit the `.stderr` files —
//! they're machine-generated and pin exact span rendering (arrow widths, fence
//! drawings). A rustc upgrade that tweaks diagnostic formatting will break all
//! snapshots at once; regenerate with:
//!
//!     TRYBUILD=overwrite cargo test -p ttlv-derive --test compile_fail

#[test]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/fixtures/fail/*.rs");
}
