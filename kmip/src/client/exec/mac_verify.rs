use super::{Exec};
use crate::{
    client::{BatchClient, Client},
    payloads::{MacRequestPayload, MacVerifyRequestPayload},
    types::CryptographicParameters,
};

pub type MacExec<'a, S> = Exec<'a, MacRequestPayload, S>;
pub type MacVerifyExec<'a, S> = Exec<'a, MacVerifyRequestPayload, S>;

pub struct WantsData;
pub struct WantsMac;

impl Client {
    pub fn mac(&mut self, id: impl Into<String>) -> MacExec<'_, WantsData> {
        MacExec::new(
            self,
            MacRequestPayload {
                unique_identifier: Some(id.into()),
                cryptographic_parameters: None,
                
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            },
        )
    }

    pub fn mac_verify(&mut self, id: impl Into<String>) -> MacVerifyExec<'_, WantsMac> {
        MacVerifyExec::new(
            self,
            MacVerifyRequestPayload {
                unique_identifier: Some(id.into()),
                cryptographic_parameters: None,
                
                mac_data: None,
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn mac(self, id: Option<String>) -> MacExec<'a, WantsData> {
        MacExec::new(
            self.0,
            MacRequestPayload {
                unique_identifier: id,
                cryptographic_parameters: None,
                
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            },
        )
    }

    pub fn mac_verify(self, id: Option<String>) -> MacVerifyExec<'a, WantsMac> {
        MacVerifyExec::new(
            self.0,
            MacVerifyRequestPayload {
                unique_identifier: id,
                cryptographic_parameters: None,
                
                mac_data: None,
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
            },
        )
    }
}

impl<S> MacExec<'_, S> {
    pub fn with_cryptographic_parameters(mut self, params: CryptographicParameters) -> Self {
        self.req.cryptographic_parameters = Some(params);
        self
    }
}

impl<'a> MacVerifyExec<'a, WantsMac> {
    pub fn mac_data(mut self, mac: impl Into<Vec<u8>>) -> MacVerifyExec<'a, WantsData> {
        self.req.mac_data = Some(mac.into());
        MacVerifyExec::new(self.client, self.req)
    }
}

impl<S> MacVerifyExec<'_, S> {
    pub fn with_cryptographic_parameters(mut self, params: CryptographicParameters) -> Self {
        self.req.cryptographic_parameters = Some(params);
        self
    }
}
