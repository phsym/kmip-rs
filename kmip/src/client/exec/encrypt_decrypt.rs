use super::{Exec, WantExec};
use crate::{
    BatchClient, Client, CryptographicParameters, DecryptRequestPayload, EncryptRequestPayload,
};

pub type EncryptExec<'a, S> = Exec<'a, EncryptRequestPayload, S>;
pub type DecryptExec<'a, S> = Exec<'a, DecryptRequestPayload, S>;

pub struct WantsData;

impl Client {
    pub fn encrypt(&mut self, id: impl Into<String>) -> EncryptExec<'_, WantsData> {
        EncryptExec::new(
            self,
            EncryptRequestPayload {
                unique_identifier: Some(id.into()),
                cryptographic_parameters: None,
                data: None,
                iv_counter_nonce: None,
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
                authenticated_encryption_additional_data: None,
            },
        )
    }

    pub fn decrypt(&mut self, id: impl Into<String>) -> DecryptExec<'_, WantsData> {
        DecryptExec::new(
            self,
            DecryptRequestPayload {
                unique_identifier: Some(id.into()),
                cryptographic_parameters: None,
                data: None,
                iv_counter_nonce: None,
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
                authenticated_encryption_additional_data: None,
                authenticated_encryption_tag: None,
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn encrypt(self, id: Option<String>) -> EncryptExec<'a, WantsData> {
        EncryptExec::new(
            self.0,
            EncryptRequestPayload {
                unique_identifier: id,
                cryptographic_parameters: None,
                data: None,
                iv_counter_nonce: None,
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
                authenticated_encryption_additional_data: None,
            },
        )
    }

    pub fn decrypt(self, id: Option<String>) -> DecryptExec<'a, WantsData> {
        DecryptExec::new(
            self.0,
            DecryptRequestPayload {
                unique_identifier: id,
                cryptographic_parameters: None,
                data: None,
                iv_counter_nonce: None,
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
                authenticated_encryption_additional_data: None,
                authenticated_encryption_tag: None,
            },
        )
    }
}

impl<'a> EncryptExec<'a, WantsData> {
    pub fn data(mut self, data: impl Into<Vec<u8>>) -> EncryptExec<'a, WantExec> {
        self.req.data = Some(data.into());
        EncryptExec::new(self.client, self.req)
    }
}

impl<S> EncryptExec<'_, S> {
    pub fn with_cryptographic_parameters(mut self, params: CryptographicParameters) -> Self {
        self.req.cryptographic_parameters = Some(params);
        self
    }

    pub fn with_iv_counter_nonce(mut self, iv: impl Into<Vec<u8>>) -> Self {
        self.req.iv_counter_nonce = Some(iv.into());
        self
    }

    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.req.authenticated_encryption_additional_data = Some(aad.into());
        self
    }
}

impl<'a> DecryptExec<'a, WantsData> {
    pub fn data(mut self, data: impl Into<Vec<u8>>) -> DecryptExec<'a, WantExec> {
        self.req.data = Some(data.into());
        DecryptExec::new(self.client, self.req)
    }
}

impl<S> DecryptExec<'_, S> {
    pub fn with_cryptographic_parameters(mut self, params: CryptographicParameters) -> Self {
        self.req.cryptographic_parameters = Some(params);
        self
    }

    pub fn with_iv_counter_nonce(mut self, iv: impl Into<Vec<u8>>) -> Self {
        self.req.iv_counter_nonce = Some(iv.into());
        self
    }

    pub fn with_aad(mut self, aad: impl Into<Vec<u8>>) -> Self {
        self.req.authenticated_encryption_additional_data = Some(aad.into());
        self
    }

    pub fn with_tag(mut self, tag: impl Into<Vec<u8>>) -> Self {
        self.req.authenticated_encryption_tag = Some(tag.into());
        self
    }
}
