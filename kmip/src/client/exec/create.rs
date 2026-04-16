use crate::{
    Attribute, BatchClient, Client, CreateRequestPayload, CryptographicAlgorithm,
    CryptographicLength, CryptographicUsageMask, Name, ObjectType, TemplateAttribute,
};

use super::{Attributed, Exec};

pub type CreateExec<'a> = Exec<'a, CreateRequestPayload>;
pub struct CreateExecWantType<'a>(&'a mut Client);

impl Client {
    pub fn create(&mut self) -> CreateExecWantType<'_> {
        CreateExecWantType(self)
    }
}

impl<'a> BatchClient<'a> {
    pub fn create(self) -> CreateExecWantType<'a> {
        self.0.create()
    }
}

impl Attributed for CreateExec<'_> {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute> {
        &mut self.req.attributes.attribute
    }
}

impl<'a> CreateExecWantType<'a> {
    pub fn object(self, object_type: ObjectType) -> CreateExec<'a> {
        CreateExec::new(
            self.0,
            CreateRequestPayload {
                object_type,
                attributes: TemplateAttribute::default(),
            },
        )
    }

    pub fn symmetric_key(
        self,
        alg: CryptographicAlgorithm,
        length: i32,
        usage: CryptographicUsageMask,
    ) -> CreateExec<'a> {
        //TODO: Cryptographic length to become usize
        self.object(ObjectType::SymmetricKey)
            .with_attribute(alg)
            .with_attribute(CryptographicLength(length))
            .with_attribute(usage)
    }

    pub fn aes(self, length: i32, usage: CryptographicUsageMask) -> CreateExec<'a> {
        //TODO: Cryptographic length to become usize
        self.symmetric_key(CryptographicAlgorithm::AES, length, usage)
    }

    pub fn tdes(self, length: i32, usage: CryptographicUsageMask) -> CreateExec<'a> {
        //TODO: Cryptographic length to become usize
        self.symmetric_key(CryptographicAlgorithm::DES3, length, usage)
    }

    pub fn skipjack(self, usage: CryptographicUsageMask) -> CreateExec<'a> {
        self.symmetric_key(CryptographicAlgorithm::SKIPJACK, 80, usage)
    }
}

impl CreateExec<'_> {
    #[deprecated = "deprecated as of kmip 1.3"]
    pub fn with_template(mut self, name: Name) -> Self {
        #[allow(deprecated)]
        self.req.attributes.name.push(name);
        self
    }
}
