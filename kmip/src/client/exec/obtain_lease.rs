use crate::{BatchClient, Client, ObtainLeaseRequestPayload};

use super::Exec;

pub type ObtainLeaseExec<'a> = Exec<'a, ObtainLeaseRequestPayload>;

impl Client {
    pub fn obtain_lease(&mut self, id: impl Into<String>) -> ObtainLeaseExec<'_> {
        ObtainLeaseExec::new(
            self,
            ObtainLeaseRequestPayload {
                unique_identifier: Some(id.into()),
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn obtain_lease(self, id: Option<String>) -> ObtainLeaseExec<'a> {
        ObtainLeaseExec::new(
            self.0,
            ObtainLeaseRequestPayload {
                unique_identifier: id,
            },
        )
    }
}
