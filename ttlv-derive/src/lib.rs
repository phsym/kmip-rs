mod attributes;
mod decodable;
mod derive_enum;
mod encodable;

use attributes::*;
use decodable::*;
use derive_enum::*;
use encodable::*;

use proc_macro::TokenStream;

#[proc_macro_derive(Encodable, attributes(ttlv))]
pub fn derive_encodable_fn(item: TokenStream) -> TokenStream {
    match derive_encodable_fn2(item.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.into_compile_error().into(),
    }
}

#[proc_macro_derive(Decodable, attributes(ttlv))]
pub fn derive_decodable_fn(item: TokenStream) -> TokenStream {
    match derive_decodable_fn2(item.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.into_compile_error().into(),
    }
}

#[proc_macro_derive(Enum, attributes(ttlv))]
pub fn derive_enum_fn(item: TokenStream) -> TokenStream {
    match derive_enum_fn2(item.into()) {
        Ok(ts) => ts.into(),
        Err(e) => e.into_compile_error().into(),
    }
}
