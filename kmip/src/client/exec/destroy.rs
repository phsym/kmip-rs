use crate::{BatchClient, Client, DestroyRequestPayload};

use super::Exec;

pub type DestroyExec<'a> = Exec<'a, DestroyRequestPayload>;

impl Client {
    pub fn destroy(&mut self, id: impl Into<String>) -> DestroyExec<'_> {
        DestroyExec::new(
            self,
            DestroyRequestPayload {
                unique_identifier: Some(id.into()),
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn destroy(self, id: Option<String>) -> DestroyExec<'a> {
        DestroyExec::new(
            self.0,
            DestroyRequestPayload {
                unique_identifier: id,
            },
        )
    }
}
