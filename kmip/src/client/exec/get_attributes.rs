use crate::{AttributeName, BatchClient, Client, GetAttributesRequestPayload};

use super::Exec;

pub type GetAttributesExec<'a> = Exec<'a, GetAttributesRequestPayload>;

impl Client {
    pub fn get_attributes(&mut self, id: impl Into<String>) -> GetAttributesExec<'_> {
        GetAttributesExec::new(
            self,
            GetAttributesRequestPayload {
                unique_identifier: Some(id.into()),
                attribute_name: Vec::new(),
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn get_attributes(self, id: Option<String>) -> GetAttributesExec<'a> {
        GetAttributesExec::new(
            self.0,
            GetAttributesRequestPayload {
                unique_identifier: id,
                attribute_name: Vec::new(),
            },
        )
    }
}

impl GetAttributesExec<'_> {
    pub fn with_attribute(mut self, name: AttributeName) -> Self {
        self.req.attribute_name.push(name.into());
        self
    }

    pub fn with_attributes<A: IntoIterator<Item = AttributeName>>(mut self, names: A) -> Self {
        self.req
            .attribute_name
            .extend(names.into_iter().map(Into::into));
        self
    }
}
