use crate::{
    attributes::AttributeName,
    client::{BatchClient, Client},
    payloads::DeleteAttributeRequestPayload,
};

use super::Exec;

pub type DeleteAttributeExec<'a> = Exec<'a, DeleteAttributeRequestPayload>;

impl Client {
    pub fn delete_attribute(
        &mut self,
        id: impl Into<String>,
        attribute_name: AttributeName,
    ) -> DeleteAttributeExec<'_> {
        DeleteAttributeExec::new(
            self,
            DeleteAttributeRequestPayload {
                unique_identifier: Some(id.into()),
                attribute_name: attribute_name.into(),
                attribute_index: None,
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn delete_attribute(
        self,
        id: Option<String>,
        attribute_name: AttributeName,
    ) -> DeleteAttributeExec<'a> {
        DeleteAttributeExec::new(
            self.0,
            DeleteAttributeRequestPayload {
                unique_identifier: id,
                attribute_name: attribute_name.into(),
                attribute_index: None,
            },
        )
    }
}

impl DeleteAttributeExec<'_> {
    pub fn with_index(mut self, idx: i32) -> Self {
        self.req.attribute_index = Some(idx);
        self
    }
}
