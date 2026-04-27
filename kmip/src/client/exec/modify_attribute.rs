use crate::{
    attributes::AttributeValue,
    client::{BatchClient, Client},
    payloads::ModifyAttributeRequestPayload,
};

use super::Exec;

pub type ModifyAttributeExec<'a> = Exec<'a, ModifyAttributeRequestPayload>;

impl Client {
    pub fn modify_attribute(
        &mut self,
        id: impl Into<String>,
        attribute: impl Into<AttributeValue>,
    ) -> ModifyAttributeExec<'_> {
        let attribute = attribute.into();
        ModifyAttributeExec::new(
            self,
            ModifyAttributeRequestPayload {
                unique_identifier: Some(id.into()),
                attribute: attribute.into(),
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn modify_attribute(
        self,
        id: Option<String>,
        attribute: impl Into<AttributeValue>,
    ) -> ModifyAttributeExec<'a> {
        let attribute = attribute.into();
        ModifyAttributeExec::new(
            self.0,
            ModifyAttributeRequestPayload {
                unique_identifier: id,
                attribute: attribute.into(),
            },
        )
    }
}

impl ModifyAttributeExec<'_> {
    pub fn with_index(mut self, idx: i32) -> Self {
        self.req.attribute.index = Some(idx);
        self
    }
}
