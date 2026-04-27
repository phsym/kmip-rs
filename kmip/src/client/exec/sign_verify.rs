use super::{Exec, WantExec};
use crate::{
    client::{BatchClient, Client},
    payloads::{SignRequestPayload, SignatureVerifyRequestPayload},
    types::CryptographicParameters,
};

pub type SignExec<'a, S> = Exec<'a, SignRequestPayload, S>;
pub type SignatureVerifyExec<'a, S> = Exec<'a, SignatureVerifyRequestPayload, S>;

pub struct WantsData;
pub struct WantsSignature;

impl Client {
    pub fn sign(&mut self, id: impl Into<String>) -> SignExec<'_, WantsData> {
        SignExec::new(
            self,
            SignRequestPayload {
                unique_identifier: Some(id.into()),
                cryptographic_parameters: None,
                data: None,
                digested_data: None,
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            },
        )
    }

    pub fn signature_verify(
        &mut self,
        id: impl Into<String>,
    ) -> SignatureVerifyExec<'_, WantsSignature> {
        SignatureVerifyExec::new(
            self,
            SignatureVerifyRequestPayload {
                unique_identifier: Some(id.into()),
                cryptographic_parameters: None,
                data: None,
                digested_data: None,
                signature_data: None,
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn sign(self, id: Option<String>) -> SignExec<'a, WantsData> {
        SignExec::new(
            self.0,
            SignRequestPayload {
                unique_identifier: id,
                cryptographic_parameters: None,
                data: None,
                digested_data: None,
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            },
        )
    }

    pub fn signature_verify(self, id: Option<String>) -> SignatureVerifyExec<'a, WantsSignature> {
        SignatureVerifyExec::new(
            self.0,
            SignatureVerifyRequestPayload {
                unique_identifier: id,
                cryptographic_parameters: None,
                data: None,
                digested_data: None,
                signature_data: None,
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            },
        )
    }
}

impl<'a> SignExec<'a, WantsData> {
    pub fn data(mut self, data: impl Into<Vec<u8>>) -> SignExec<'a, WantExec> {
        self.req.data = Some(data.into());
        SignExec::new(self.client, self.req)
    }

    pub fn digested_data(mut self, data: impl Into<Vec<u8>>) -> SignExec<'a, WantExec> {
        self.req.digested_data = Some(data.into());
        SignExec::new(self.client, self.req)
    }
}

impl<S> SignExec<'_, S> {
    pub fn with_cryptographic_parameters(mut self, params: CryptographicParameters) -> Self {
        self.req.cryptographic_parameters = Some(params);
        self
    }
}

impl<'a> SignatureVerifyExec<'a, WantsSignature> {
    pub fn signature(mut self, sig: impl Into<Vec<u8>>) -> SignatureVerifyExec<'a, WantsData> {
        self.req.signature_data = Some(sig.into());
        SignatureVerifyExec::new(self.client, self.req)
    }
}

impl<'a> SignatureVerifyExec<'a, WantsData> {
    pub fn data(mut self, data: impl Into<Vec<u8>>) -> SignatureVerifyExec<'a, WantExec> {
        self.req.data = Some(data.into());
        SignatureVerifyExec::new(self.client, self.req)
    }

    pub fn digested_data(mut self, data: impl Into<Vec<u8>>) -> SignatureVerifyExec<'a, WantExec> {
        self.req.digested_data = Some(data.into());
        SignatureVerifyExec::new(self.client, self.req)
    }
}

impl<S> SignatureVerifyExec<'_, S> {
    pub fn with_cryptographic_parameters(mut self, params: CryptographicParameters) -> Self {
        self.req.cryptographic_parameters = Some(params);
        self
    }
}
