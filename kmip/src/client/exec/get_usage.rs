use crate::{BatchClient, Client, GetUsageAllocationRequestPayload};

use super::Exec;

pub type GetUsageAllocationExec<'a> = Exec<'a, GetUsageAllocationRequestPayload>;

impl Client {
    pub fn get_usage_allocation(
        &mut self,
        id: impl Into<String>,
        usage_limits_count: i64,
    ) -> GetUsageAllocationExec<'_> {
        GetUsageAllocationExec::new(
            self,
            GetUsageAllocationRequestPayload {
                unique_identifier: Some(id.into()),
                usage_limits_count,
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn get_usage_allocation(
        self,
        id: Option<String>,
        usage_limits_count: i64,
    ) -> GetUsageAllocationExec<'a> {
        GetUsageAllocationExec::new(
            self.0,
            GetUsageAllocationRequestPayload {
                unique_identifier: id,
                usage_limits_count,
            },
        )
    }
}
