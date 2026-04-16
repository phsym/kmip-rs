use crate::{
    Attribute, BatchClient, Client, LocateRequestPayload, ObjectGroupMember, StorageStatusMask,
};

use super::{Attributed, Exec};

pub type LocateExec<'a> = Exec<'a, LocateRequestPayload>;

impl Client {
    pub fn locate(&mut self) -> LocateExec<'_> {
        LocateExec::new(
            self,
            LocateRequestPayload {
                maximum_items: None,
                storage_status_mask: None,
                attributes: Vec::new(),
                object_group_member: None,
                offset_items: None,
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn locate(self) -> LocateExec<'a> {
        self.0.locate()
    }
}

impl Attributed for LocateExec<'_> {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute> {
        &mut self.req.attributes
    }
}

impl LocateExec<'_> {
    pub fn with_storage_status_mask(mut self, mask: StorageStatusMask) -> Self {
        self.req.storage_status_mask = Some(mask);
        self
    }

    pub fn with_max_items(mut self, max: i32) -> Self {
        self.req.maximum_items = Some(max);
        self
    }

    pub fn with_offset(mut self, offset: i32) -> Self {
        self.req.offset_items = Some(offset);
        self
    }

    pub fn with_object_group_member(mut self, group_member: ObjectGroupMember) -> Self {
        self.req.object_group_member = Some(group_member);
        self
    }
}
