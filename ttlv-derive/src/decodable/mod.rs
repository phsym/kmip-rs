mod r#enum;
mod r#struct;
use r#enum::*;
use r#struct::*;

use proc_macro2::TokenStream as TokenStream2;
use syn::{Data, DeriveInput, Error, Result};

use crate::AttrExt;

pub fn derive_decodable_fn2(item: TokenStream2) -> Result<TokenStream2> {
    let ast: DeriveInput = syn::parse2(item)?;
    let attr = ast.attrs.get_attr()?;

    match ast.data {
        Data::Enum(en) => derive_enum(en, ast.ident, attr.for_enum()?),
        Data::Struct(data) => derive_struct(data, ast.ident, attr.for_struct()?),
        _ => Err(Error::new_spanned(
            &ast,
            "Only enums and structs are supported",
        )),
    }
}
