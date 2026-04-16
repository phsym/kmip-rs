use crate::{ActivateRequestPayload, BatchClient, Client};

use super::Exec;

pub type ActivateExec<'a> = Exec<'a, ActivateRequestPayload>;

impl Client {
    pub fn activate(&mut self, id: impl Into<String>) -> ActivateExec<'_> {
        ActivateExec::new(
            self,
            ActivateRequestPayload {
                unique_identifier: Some(id.into()),
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn activate(self, id: Option<String>) -> ActivateExec<'a> {
        ActivateExec::new(
            self.0,
            ActivateRequestPayload {
                unique_identifier: id,
            },
        )
    }
}
