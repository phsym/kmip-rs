use crate::{
    attributes::Attribute,
    client::{
        BatchClient, Client,
        exec::{Attributed, Exec},
    },
    enums::{KeyCompressionType, KeyFormatType, KeyWrapType},
    objects::{KeyWrappingSpecification, Object},
    payloads::{ExportRequestPayload, ImportRequestPayload},
};

pub type ImportExec<'a> = Exec<'a, ImportRequestPayload>;
pub type ExportExec<'a> = Exec<'a, ExportRequestPayload>;

impl Client {
    pub fn import(&mut self, id: impl Into<String>, object: Object) -> ImportExec<'_> {
        ImportExec::new(
            self,
            ImportRequestPayload {
                unique_identifier: id.into(),
                key_wrap_type: None,
                replace_existing: None,
                attribute: Vec::new(),
                object,
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn import(self, id: String, object: Object) -> ImportExec<'a> {
        ImportExec::new(
            self.0,
            ImportRequestPayload {
                unique_identifier: id,
                key_wrap_type: None,
                replace_existing: None,
                attribute: Vec::new(),
                object,
            },
        )
    }
}

impl Client {
    pub fn export(&mut self, id: impl Into<String>) -> ExportExec<'_> {
        ExportExec::new(
            self,
            ExportRequestPayload {
                unique_identifier: Some(id.into()),
                key_format_type: None,
                key_wrap_type: None,
                key_compression_type: None,
                key_wrapping_specification: None,
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn export(self, id: Option<String>) -> ExportExec<'a> {
        ExportExec::new(
            self.0,
            ExportRequestPayload {
                unique_identifier: id,
                key_format_type: None,
                key_wrap_type: None,
                key_compression_type: None,
                key_wrapping_specification: None,
            },
        )
    }
}

impl ImportExec<'_> {
    pub fn with_replace_existing(mut self, replace: bool) -> Self {
        self.req.replace_existing = Some(replace);
        self
    }

    pub fn with_key_wrap_type(mut self, key_wrap_type: KeyWrapType) -> Self {
        self.req.key_wrap_type = Some(key_wrap_type);
        self
    }
}

impl Attributed for ImportExec<'_> {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute> {
        &mut self.req.attribute
    }
}

impl ExportExec<'_> {
    pub fn with_key_format_type(mut self, key_format_type: KeyFormatType) -> Self {
        self.req.key_format_type = Some(key_format_type);
        self
    }

    pub fn with_key_wrap_type(mut self, key_wrap_type: KeyWrapType) -> Self {
        self.req.key_wrap_type = Some(key_wrap_type);
        self
    }

    pub fn with_key_compression_type(mut self, key_compression_type: KeyCompressionType) -> Self {
        self.req.key_compression_type = Some(key_compression_type);
        self
    }

    pub fn with_key_wrapping_specification(mut self, spec: KeyWrappingSpecification) -> Self {
        self.req.key_wrapping_specification = Some(spec);
        self
    }
}
