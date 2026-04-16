use crate::{
    BatchClient, Client, GetRequestPayload, KeyCompressionType, KeyFormatType, KeyWrapType,
    KeyWrappingSpecification,
};

use super::Exec;

pub type GetExec<'a> = Exec<'a, GetRequestPayload>;

impl Client {
    pub fn get(&mut self, id: impl Into<String>) -> GetExec<'_> {
        GetExec::new(
            self,
            GetRequestPayload {
                unique_identifier: Some(id.into()),
                key_compression_type: None,
                key_format_type: None,
                key_wrap_type: None,
                key_wrapping_specification: None,
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn get(self, id: Option<String>) -> GetExec<'a> {
        GetExec::new(
            self.0,
            GetRequestPayload {
                unique_identifier: id,
                key_compression_type: None,
                key_format_type: None,
                key_wrap_type: None,
                key_wrapping_specification: None,
            },
        )
    }
}

impl GetExec<'_> {
    pub fn with_key_format(mut self, format: KeyFormatType) -> Self {
        self.req.key_format_type = Some(format);
        self
    }

    pub fn with_key_compression(mut self, compression: KeyCompressionType) -> Self {
        self.req.key_compression_type = Some(compression);
        self
    }

    pub fn with_key_wrapping(mut self, spec: KeyWrappingSpecification) -> Self {
        self.req.key_wrapping_specification = Some(spec);
        self
    }

    pub fn with_key_wrap_type(mut self, key_wrap_type: KeyWrapType) -> Self {
        self.req.key_wrap_type = Some(key_wrap_type);
        self
    }
}
