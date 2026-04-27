use chrono::Duration;

use crate::{
    attributes::Attribute,
    client::{BatchClient, Client},
    payloads::ReKeyRequestPayload,
    types::{Name, TemplateAttribute},
};

use super::{Attributed, Exec};

pub type ReKeyExec<'a> = Exec<'a, ReKeyRequestPayload>;

impl Client {
    pub fn rekey(&mut self, id: impl Into<String>) -> ReKeyExec<'_> {
        ReKeyExec::new(
            self,
            ReKeyRequestPayload {
                unique_identifier: Some(id.into()),
                offset: None,
                template_attribute: None,
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn rekey(self, id: Option<String>) -> ReKeyExec<'a> {
        ReKeyExec::new(
            self.0,
            ReKeyRequestPayload {
                unique_identifier: id,
                offset: None,
                template_attribute: None,
            },
        )
    }
}

impl ReKeyExec<'_> {
    fn get_template_attributes(&mut self) -> &mut TemplateAttribute {
        self.req
            .template_attribute
            .get_or_insert_with(Default::default)
    }

    pub fn with_offset(mut self, offset: Duration) -> Self {
        self.req.offset = Some(offset);
        self
    }

    #[deprecated = "Templates have been deprecated in KMIP v1.3"]
    pub fn with_template(mut self, name: Name) -> Self {
        #[allow(deprecated)]
        self.get_template_attributes().name.push(name);
        self
    }
}

impl Attributed for ReKeyExec<'_> {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute> {
        &mut self.get_template_attributes().attribute
    }
}
