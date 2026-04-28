//! Resolves the path under which the `ttlv` crate is reachable from the
//! consumer's crate, so generated code keeps working when `ttlv` is renamed
//! via `[dependencies]` (e.g. `tlv = { package = "ttlv", ... }`).

use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::Ident;

pub(crate) fn ttlv_path() -> TokenStream {
    match crate_name("ttlv") {
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name, Span::call_site());
            quote!(::#ident)
        }
        // Fallback covers two cases that resolve to the same path:
        // - `Itself`: `ttlv`'s own README doctests, where rustdoc passes
        //   `--extern ttlv`. (Genuine in-lib use of these derives from
        //   inside `ttlv` would also need `extern crate self as ttlv;`.)
        // - `Err`: `ttlv` is not in `[dependencies]` (e.g. ttlv-derive's
        //   own unit tests, where `ttlv` is only a dev-dep).
        Ok(FoundCrate::Itself) | Err(_) => quote!(::ttlv),
    }
}
