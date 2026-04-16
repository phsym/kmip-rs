use crate::{
    Attribute, AttributeValue, BatchClient, Client, CreateKeyPairRequestPayload,
    CryptographicAlgorithm, CryptographicDomainParameters, CryptographicLength,
    CryptographicUsageMask, Name, RecommendedCurve,
};

use super::{Attributed, Exec, WantExec};

pub type CreateKeyPairExec<'a, S> = Exec<'a, CreateKeyPairRequestPayload, S>;

pub struct WantCommonAttributes;
pub struct WantPrivateAttributes;
pub struct WantPublicAttributes;

impl Client {
    pub fn create_keypair(&mut self) -> CreateKeyPairExec<'_, WantExec> {
        CreateKeyPairExec::new(
            self,
            CreateKeyPairRequestPayload {
                common_template_attribute: None,
                private_key_template_attribute: None,
                public_key_template_attribute: None,
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn create_keypair(self) -> CreateKeyPairExec<'a, WantExec> {
        self.0.create_keypair()
    }
}

impl<'a, A> CreateKeyPairExec<'a, A> {
    fn transition<B>(self) -> CreateKeyPairExec<'a, B> {
        CreateKeyPairExec::new(self.client, self.req)
    }
}

impl Attributed for CreateKeyPairExec<'_, WantExec> {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute> {
        &mut self
            .req
            .common_template_attribute
            .get_or_insert_with(Default::default)
            .attribute
    }
}

impl Attributed for CreateKeyPairExec<'_, WantCommonAttributes> {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute> {
        &mut self
            .req
            .common_template_attribute
            .get_or_insert_with(Default::default)
            .attribute
    }
}

impl Attributed for CreateKeyPairExec<'_, WantPrivateAttributes> {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute> {
        &mut self
            .req
            .private_key_template_attribute
            .get_or_insert_with(Default::default)
            .attribute
    }
}

impl Attributed for CreateKeyPairExec<'_, WantPublicAttributes> {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute> {
        &mut self
            .req
            .public_key_template_attribute
            .get_or_insert_with(Default::default)
            .attribute
    }
}

impl CreateKeyPairExec<'_, WantExec> {
    pub fn common(
        self,
        f: impl FnOnce(
            CreateKeyPairExec<WantCommonAttributes>,
        ) -> CreateKeyPairExec<WantCommonAttributes>,
    ) -> Self {
        f(self.transition()).transition()
    }

    pub fn private(
        self,
        f: impl FnOnce(
            CreateKeyPairExec<WantPrivateAttributes>,
        ) -> CreateKeyPairExec<WantPrivateAttributes>,
    ) -> Self {
        f(self.transition()).transition()
    }

    pub fn public(
        self,
        f: impl FnOnce(
            CreateKeyPairExec<WantPublicAttributes>,
        ) -> CreateKeyPairExec<WantPublicAttributes>,
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

    pub fn rsa(
        self,
        bitlen: i32,
        private_usage: CryptographicUsageMask,
        public_usage: CryptographicUsageMask,
    ) -> Self {
        self.common(|attr| {
            attr.with_attributes([
                AttributeValue::from(CryptographicAlgorithm::RSA),
                AttributeValue::from(CryptographicLength(bitlen)),
            ])
        })
        .public(|attr| attr.with_attribute(public_usage))
        .private(|attr| attr.with_attribute(private_usage))
    }

    pub fn ecdsa(
        self,
        curve: RecommendedCurve,
        private_usage: CryptographicUsageMask,
        public_usage: CryptographicUsageMask,
    ) -> Self {
        self.common(|attr| {
            attr.with_attributes([
                AttributeValue::from(CryptographicAlgorithm::ECDSA),
                AttributeValue::from(CryptographicLength(curve.bitlen())),
                AttributeValue::from(CryptographicDomainParameters {
                    qlength: None,
                    recommended_curve: Some(curve),
                }),
            ])
        })
        .public(|attr| attr.with_attribute(public_usage))
        .private(|attr| attr.with_attribute(private_usage))
    }
}
