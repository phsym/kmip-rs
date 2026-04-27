use chrono::Duration;

use crate::{
    attributes::Attribute,
    client::{
        BatchClient, Client,
        exec::{
            Attributed, Exec, WantExec,
            create_keypair::{WantCommonAttributes, WantPrivateAttributes, WantPublicAttributes},
        },
    },
    payloads::ReKeyKeyPairRequestPayload,
    types::Name,
};

pub type ReKeyKeyPairExec<'a, S> = Exec<'a, ReKeyKeyPairRequestPayload, S>;

impl Client {
    pub fn rekey_keypair(
        &mut self,
        private_key_id: impl Into<String>,
    ) -> ReKeyKeyPairExec<'_, WantExec> {
        ReKeyKeyPairExec::new(
            self,
            ReKeyKeyPairRequestPayload {
                private_key_unique_identifier: Some(private_key_id.into()),
                offset: None,
                common_template_attribute: None,
                private_key_template_attribute: None,
                public_key_template_attribute: None,
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn rekey_keypair(self, private_key_id: Option<String>) -> ReKeyKeyPairExec<'a, WantExec> {
        ReKeyKeyPairExec::new(
            self.0,
            ReKeyKeyPairRequestPayload {
                private_key_unique_identifier: private_key_id,
                offset: None,
                common_template_attribute: None,
                private_key_template_attribute: None,
                public_key_template_attribute: None,
            },
        )
    }
}

impl<'a, A> ReKeyKeyPairExec<'a, A> {
    fn transition<B>(self) -> ReKeyKeyPairExec<'a, B> {
        ReKeyKeyPairExec::new(self.client, self.req)
    }
}

impl ReKeyKeyPairExec<'_, WantExec> {
    pub fn with_offset(mut self, offset: Duration) -> Self {
        self.req.offset = Some(offset);
        self
    }
}

impl Attributed for ReKeyKeyPairExec<'_, WantExec> {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute> {
        &mut self
            .req
            .common_template_attribute
            .get_or_insert_with(Default::default)
            .attribute
    }
}

impl Attributed for ReKeyKeyPairExec<'_, WantCommonAttributes> {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute> {
        &mut self
            .req
            .common_template_attribute
            .get_or_insert_with(Default::default)
            .attribute
    }
}

impl Attributed for ReKeyKeyPairExec<'_, WantPrivateAttributes> {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute> {
        &mut self
            .req
            .private_key_template_attribute
            .get_or_insert_with(Default::default)
            .attribute
    }
}

impl Attributed for ReKeyKeyPairExec<'_, WantPublicAttributes> {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute> {
        &mut self
            .req
            .public_key_template_attribute
            .get_or_insert_with(Default::default)
            .attribute
    }
}

impl ReKeyKeyPairExec<'_, WantExec> {
    pub fn common(
        self,
        f: impl FnOnce(ReKeyKeyPairExec<WantCommonAttributes>) -> ReKeyKeyPairExec<WantCommonAttributes>,
    ) -> Self {
        f(self.transition()).transition()
    }

    pub fn private(
        self,
        f: impl FnOnce(
            ReKeyKeyPairExec<WantPrivateAttributes>,
        ) -> ReKeyKeyPairExec<WantPrivateAttributes>,
    ) -> Self {
        f(self.transition()).transition()
    }

    pub fn public(
        self,
        f: impl FnOnce(ReKeyKeyPairExec<WantPublicAttributes>) -> ReKeyKeyPairExec<WantPublicAttributes>,
    ) -> Self {
        f(self.transition()).transition()
    }

    #[deprecated = "deprecated as of kmip 1.3"]
    pub fn with_common_template(mut self, name: Name) -> Self {
        #[allow(deprecated)]
        self.req
            .common_template_attribute
            .get_or_insert_default()
            .name
            .push(name);
        self
    }

    #[deprecated = "deprecated as of kmip 1.3"]
    pub fn with_private_key_template(mut self, name: Name) -> Self {
        #[allow(deprecated)]
        self.req
            .private_key_template_attribute
            .get_or_insert_default()
            .name
            .push(name);
        self
    }

    #[deprecated = "deprecated as of kmip 1.3"]
    pub fn with_public_key_template(mut self, name: Name) -> Self {
        #[allow(deprecated)]
        self.req
            .public_key_template_attribute
            .get_or_insert_default()
            .name
            .push(name);
        self
    }
}
