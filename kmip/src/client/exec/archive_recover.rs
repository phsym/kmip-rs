use crate::{ArchiveRequestPayload, BatchClient, Client, RecoverRequestPayload};

use super::Exec;

pub type ArchiveExec<'a> = Exec<'a, ArchiveRequestPayload>;

impl Client {
    pub fn archive(&mut self, id: impl Into<String>) -> ArchiveExec<'_> {
        ArchiveExec::new(
            self,
            ArchiveRequestPayload {
                unique_identifier: Some(id.into()),
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn archive(self, id: Option<String>) -> ArchiveExec<'a> {
        ArchiveExec::new(
            self.0,
            ArchiveRequestPayload {
                unique_identifier: id,
            },
        )
    }
}

pub type RecoverExec<'a> = Exec<'a, RecoverRequestPayload>;

impl Client {
    pub fn recover(&mut self, id: impl Into<String>) -> RecoverExec<'_> {
        RecoverExec::new(
            self,
            RecoverRequestPayload {
                unique_identifier: Some(id.into()),
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn recover(self, id: Option<String>) -> RecoverExec<'a> {
        RecoverExec::new(
            self.0,
            RecoverRequestPayload {
                unique_identifier: id,
            },
        )
    }
}
