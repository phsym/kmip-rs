use crate::{AddAttributeRequestPayload, AttributeValue, BatchClient, Client};

use super::Exec;

pub type AddAttributeExec<'a> = Exec<'a, AddAttributeRequestPayload>;

impl Client {
    pub fn add_attribute(
        &mut self,
        id: impl Into<String>,
        attr: impl Into<AttributeValue>,
    ) -> AddAttributeExec<'_> {
        let attr = attr.into();
        AddAttributeExec::new(
            self,
            AddAttributeRequestPayload {
                unique_identifier: Some(id.into()),
                attribute: attr.into(),
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn add_attribute(
        self,
        id: Option<String>,
        attr: impl Into<AttributeValue>,
    ) -> AddAttributeExec<'a> {
        let attr = attr.into();
        AddAttributeExec::new(
            self.0,
            AddAttributeRequestPayload {
                unique_identifier: id,
                attribute: attr.into(),
            },
        )
    }
}

impl AddAttributeExec<'_> {
    pub fn with_index(mut self, index: i32) -> Self {
        self.req.attribute.index = Some(index);
        self
    }
}
