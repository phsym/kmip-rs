use proc_macro2::{Literal, Span};
use syn::{Attribute, Expr, Result, parenthesized, spanned::Spanned};

pub trait AttrExt {
    fn get_attr(&self) -> Result<Attr>;
}

impl AttrExt for Vec<Attribute> {
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
        if let Some(is_enum) = self.is_enum {
            return Err(is_enum.error("enum is not supported on structs"));
        }
        if let Some(set_ext) = self.set_ext {
            return Err(set_ext.error("set_ext is not supported on structs"));
        }
        if let Some(if_filter) = self.if_filter {
            return Err(if_filter.error("if filter is not supported on structs"));
        }
        if let Some(def) = self.default {
            return Err(def.error("default is not supported on structs"));
        }
        if let Some(skip) = self.skip {
            return Err(skip.error("skip is not supported on structs"));
        }
        if let Some(rn) = self.rename {
            return Err(rn.error("rename is not supported on structs"));
        }
        Ok(StructAttr {
            call_mode: CallMode::from_attr(self.tag, self.flatten)?, // tag: self.tag.map(|t| t.value),
        })
    }

    pub fn for_enum(self) -> Result<EnumAttr> {
        if self.is_enum.is_some() {
            if let Some(flatten) = self.flatten {
                return Err(flatten.error("flatten is not supported on enums"));
            }
            if let Some(set_ext) = self.set_ext {
                return Err(set_ext.error("set_ext is not supported on enums"));
            }
            if let Some(if_filter) = self.if_filter {
                return Err(if_filter.error("if filter is not supported on enums"));
            }
            if let Some(def) = self.default {
                return Err(def.error("default is not supported on enums"));
            }
            if let Some(skip) = self.skip {
                return Err(skip.error("skip is not supported on enums"));
            }
            if let Some(rn) = self.rename {
                return Err(rn.error("rename is not supported on enums"));
            }
            Ok(EnumAttr::Enum(EnumEnumAttr {
                tag: self.tag.map(|t| t.value),
            }))
        } else {
            Ok(EnumAttr::Struct(self.for_struct()?))
        }
    }

    pub fn for_struct_field(self) -> Result<StructFieldAttr> {
        if let Some(is_enum) = self.is_enum {
            return Err(is_enum.error("enum is not supported on struct fields"));
        }
        if let Some(def) = self.default {
            return Err(def.error("default is not supported on struct fields"));
        }
        if let Some(rn) = self.rename {
            return Err(rn.error("rename is not supported on struct fields"));
        }
        Ok(StructFieldAttr {
            call_mode: CallMode::from_attr(self.tag, self.flatten)?,
            if_filter: self.if_filter.map(|a| a.value),
            set_ext: self.set_ext.is_some(),
            skip: self.skip.is_some(),
        })
    }

    pub fn for_enum_variant(self) -> Result<EnumVariantAttr> {
        if let Some(flatten) = self.flatten {
            return Err(flatten.error("flatten is not supported on enum variants"));
        }
        if let Some(tag) = self.tag {
            return Err(tag.error("tag is not supported on enum variants"));
        }
        if let Some(is_enum) = self.is_enum {
            return Err(is_enum.error("enum is not supported on enum variants"));
        }
        if let Some(set_ext) = self.set_ext {
            return Err(set_ext.error("set_ext is not supported on enum variants"));
        }
        if let Some(if_filter) = self.if_filter {
            return Err(if_filter.error("if filter is not supported on enum variants"));
        }
        if let Some(skip) = self.skip {
            return Err(skip.error("skip is not supported on enum variants"));
        }
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
