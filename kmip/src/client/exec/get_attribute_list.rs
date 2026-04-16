use crate::{BatchClient, Client, GetAttributeListRequestPayload};

use super::Exec;

pub type GetAttributeListExec<'a> = Exec<'a, GetAttributeListRequestPayload>;

impl Client {
    pub fn get_attribute_list(&mut self, id: impl Into<String>) -> GetAttributeListExec<'_> {
        GetAttributeListExec::new(
            self,
            GetAttributeListRequestPayload {
                unique_identifier: Some(id.into()),
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn get_attribute_list(self, id: Option<String>) -> GetAttributeListExec<'a> {
        GetAttributeListExec::new(
            self.0,
            GetAttributeListRequestPayload {
                unique_identifier: id,
            },
        )
    }
}
