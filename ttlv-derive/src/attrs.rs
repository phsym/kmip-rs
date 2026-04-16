//! Parsing and validation of `#[ttlv(...)]` attributes.
//!
//! The raw `Attr` struct collects all possible attribute fields from `#[ttlv(...)]`.
//! It is then validated and narrowed into context-specific types via `for_struct()`,
//! `for_enum()`, `for_struct_field()`, or `for_enum_variant()`, each of which rejects
//! attributes that don't apply in that context.
//!
//! ## Supported attributes
//!
//! | Attribute              | Applies to          | Description                                              |
//! |------------------------|---------------------|----------------------------------------------------------|
//! | `tag = <expr>`         | struct, field        | TTLV tag for encoding/decoding                           |
//! | `flatten`              | struct, field, enum  | Encode/decode fields inline (no struct wrapper)           |
//! | `enum`                 | enum                 | Marks enum as a TTLV Enumeration (vs struct-like enum)    |
//! | `set_ext`              | field                | Store decoded value in the extensions context             |
//! | `if(<expr>)`           | field                | Conditional encoding/decoding based on extensions context |
//! | `skip`                 | field                | Skip this field; use `Default::default()` on decode       |
//! | `default`              | enum variant         | Catch-all variant for unknown discriminants               |
//! | `rename = "..."`       | enum variant         | Override the variant's string name                        |

use proc_macro2::{Literal, Span};
use syn::{Attribute, Expr, Result, parenthesized, spanned::Spanned};

/// Extension trait to extract `#[ttlv(...)]` attributes from a list of `syn::Attribute`.
pub trait AttrExt {
    fn get_attr(&self) -> Result<Attr>;
}

impl AttrExt for Vec<Attribute> {
    /// Parses all `#[ttlv(...)]` attributes on an item into a single `Attr` struct.
    fn get_attr(&self) -> Result<Attr> {
        let mut attrs = Attr::default();
        for attr in self {
            if attr.path().is_ident("ttlv") {
                attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("tag") {
                        if attrs.tag.is_some() {
                            return Err(meta.error("tag defined more than once"));
                        }
                        attrs.tag = Some(WithSpan::new(meta.path.span(), meta.value()?.parse()?));
                        Ok(())
                    } else if meta.path.is_ident("flatten") {
                        attrs.flatten = Some(WithSpan::new(meta.path.span(), ()));
                        Ok(())
                    } else if meta.path.is_ident("enum") {
                        attrs.is_enum = Some(WithSpan::new(meta.path.span(), ()));
                        Ok(())
                    } else if meta.path.is_ident("set_ext") {
                        attrs.set_ext = Some(WithSpan::new(meta.path.span(), ()));
                        Ok(())
                    } else if meta.path.is_ident("if") {
                        let content;
                        parenthesized!(content in meta.input);
                        attrs.if_filter = Some(WithSpan::new(meta.path.span(), content.parse()?));
                        Ok(())
                    } else if meta.path.is_ident("default") {
                        if attrs.default.is_some() {
                            return Err(meta.error("default defined more than once"));
                        }
                        attrs.default = Some(WithSpan::new(meta.path.span(), ()));
                        Ok(())
                    } else if meta.path.is_ident("skip") {
                        attrs.skip = Some(WithSpan::new(meta.path.span(), ()));
                        Ok(())
                    } else if meta.path.is_ident("rename") {
                        attrs.rename =
                            Some(WithSpan::new(meta.path.span(), meta.value()?.parse()?));
                        Ok(())
                    } else {
                        Err(meta.error("Unknown attribute"))
                    }
                })?;
            }
        }
        Ok(attrs)
    }
}

/// Wraps a parsed value with the span of the attribute key that produced it,
/// so we can emit targeted compile errors pointing at the right `#[ttlv(...)]` token.
struct WithSpan<T> {
    value: T,
    span: Span,
}

impl<T> WithSpan<T> {
    fn new(span: Span, value: T) -> Self {
        Self { value, span }
    }

    fn error(self, msg: &str) -> syn::Error {
        syn::Error::new(self.span, msg)
    }
}

/// Rejects attributes that are not valid in a given context.
/// Each field-message pair is checked: if the field is `Some`, a compile error is emitted.
macro_rules! reject {
    ($($field:expr => $msg:expr),+ $(,)?) => {
        $(if let Some(v) = $field { return Err(v.error($msg)); })+
    };
}

/// Raw parsed `#[ttlv(...)]` attributes before context-specific validation.
/// Call `for_struct()`, `for_enum()`, `for_struct_field()`, or `for_enum_variant()`
/// to validate and narrow into the appropriate context type.
#[derive(Default)]
pub struct Attr {
    tag: Option<WithSpan<Expr>>,
    flatten: Option<WithSpan<()>>,
    is_enum: Option<WithSpan<()>>,
    set_ext: Option<WithSpan<()>>,
    if_filter: Option<WithSpan<Expr>>,
    default: Option<WithSpan<()>>,
    skip: Option<WithSpan<()>>,
    rename: Option<WithSpan<Literal>>,
}

impl Attr {
    pub fn for_struct(self) -> Result<StructAttr> {
        reject!(
            self.is_enum => "enum is not supported on structs",
            self.set_ext => "set_ext is not supported on structs",
            self.if_filter => "if filter is not supported on structs",
            self.default => "default is not supported on structs",
            self.skip => "skip is not supported on structs",
            self.rename => "rename is not supported on structs",
        );
        Ok(StructAttr {
            call_mode: CallMode::from_attr(self.tag, self.flatten)?,
        })
    }

    pub fn for_enum(self) -> Result<EnumAttr> {
        if self.is_enum.is_some() {
            reject!(
                self.flatten => "flatten is not supported on enums",
                self.set_ext => "set_ext is not supported on enums",
                self.if_filter => "if filter is not supported on enums",
                self.default => "default is not supported on enums",
                self.skip => "skip is not supported on enums",
                self.rename => "rename is not supported on enums",
            );
            Ok(EnumAttr::Enum(EnumEnumAttr {
                tag: self.tag.map(|t| t.value),
            }))
        } else {
            Ok(EnumAttr::Struct(self.for_struct()?))
        }
    }

    pub fn for_struct_field(self) -> Result<StructFieldAttr> {
        reject!(
            self.is_enum => "enum is not supported on struct fields",
            self.default => "default is not supported on struct fields",
            self.rename => "rename is not supported on struct fields",
        );
        Ok(StructFieldAttr {
            call_mode: CallMode::from_attr(self.tag, self.flatten)?,
            if_filter: self.if_filter.map(|a| a.value),
            set_ext: self.set_ext.is_some(),
            skip: self.skip.is_some(),
        })
    }

    pub fn for_enum_variant(self) -> Result<EnumVariantAttr> {
        reject!(
            self.flatten => "flatten is not supported on enum variants",
            self.tag => "tag is not supported on enum variants",
            self.is_enum => "enum is not supported on enum variants",
            self.set_ext => "set_ext is not supported on enum variants",
            self.if_filter => "if filter is not supported on enum variants",
            self.skip => "skip is not supported on enum variants",
        );
        Ok(EnumVariantAttr {
            default: self.default.is_some(),
            rename: self.rename.map(|r| r.value),
        })
    }
}

pub struct StructAttr {
    pub call_mode: CallMode,
}

pub struct StructFieldAttr {
    pub call_mode: CallMode,
    pub if_filter: Option<Expr>,
    pub set_ext: bool,
    pub skip: bool,
}

pub enum EnumAttr {
    Enum(EnumEnumAttr),
    Struct(StructAttr),
}

pub struct EnumEnumAttr {
    pub tag: Option<Expr>,
}

pub struct EnumVariantAttr {
    pub default: bool,
    pub rename: Option<Literal>,
}

/// Determines how a struct or field is encoded/decoded:
/// - `None`: delegate to the trait's untagged method (`encode`/`decode`)
/// - `Tag(expr)`: use the tagged method (`tag_encode`/`tag_decode`) with the given tag expression
/// - `Flatten`: encode/decode fields inline without a wrapping struct
pub enum CallMode {
    None,
    Tag(Expr),
    Flatten,
}

impl CallMode {
    fn from_attr(tag: Option<WithSpan<Expr>>, flatten: Option<WithSpan<()>>) -> Result<Self> {
        Ok(match (tag, flatten) {
            (None, None) => Self::None,
            (Some(tag), None) => Self::Tag(tag.value),
            (None, Some(_)) => Self::Flatten,
            (Some(tag), Some(flatten)) => {
                let mut e = tag.error("tag and flatten attribute are mutually exclusive");
                e.combine(flatten.error("tag and flatten attribute are mutually exclusive"));
                return Err(e);
            }
        })
    }
}
