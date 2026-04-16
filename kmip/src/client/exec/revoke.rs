use chrono::Local;

use crate::{BatchClient, Client, RevocationReason, RevocationReasonCode, RevokeRequestPayload};

use super::Exec;

pub type RevokeExec<'a> = Exec<'a, RevokeRequestPayload>;

impl Client {
    pub fn revoke(&mut self, id: impl Into<String>) -> RevokeExec<'_> {
        RevokeExec::new(
            self,
            RevokeRequestPayload {
                unique_identifier: Some(id.into()),
                revocation_reason: RevocationReason {
                    revocation_reason_code: RevocationReasonCode::Unspecified,
                    revocation_message: None,
                },
                compromise_occurrence_date: None,
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn revoke(self, id: Option<String>) -> RevokeExec<'a> {
        RevokeExec::new(
            self.0,
            RevokeRequestPayload {
                unique_identifier: id,
                revocation_reason: RevocationReason {
                    revocation_reason_code: RevocationReasonCode::Unspecified,
                    revocation_message: None,
                },
                compromise_occurrence_date: None,
            },
        )
    }
}

impl RevokeExec<'_> {
    pub fn with_revocation_reason_code(mut self, code: RevocationReasonCode) -> Self {
        self.req.revocation_reason.revocation_reason_code = code;
        self
    }

    pub fn with_revocation_message(mut self, msg: String) -> Self {
        self.req.revocation_reason.revocation_message = Some(msg);
        self
    }

    pub fn with_compromise_occurrence_date(mut self, date: chrono::DateTime<Local>) -> Self {
        self.req.compromise_occurrence_date = Some(date);
        self
    }
}
