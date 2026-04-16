use crate::{BatchClient, Client, QueryFunction, QueryRequestPayload};

use super::Exec;

pub type QueryExec<'a> = Exec<'a, QueryRequestPayload>;

impl Client {
    pub fn query(&mut self) -> QueryExec<'_> {
        QueryExec::new(
            self,
            QueryRequestPayload {
                query_function: Vec::new(),
            },
        )
    }
}

impl<'a> BatchClient<'a> {
    pub fn query(self) -> QueryExec<'a> {
        self.0.query()
    }
}

impl QueryExec<'_> {
    pub fn operations(mut self) -> Self {
        self.req.query_function.push(QueryFunction::QueryOperations);
        self
    }

    pub fn objects(mut self) -> Self {
        self.req.query_function.push(QueryFunction::QueryObjects);
        self
    }

    pub fn server_information(mut self) -> Self {
        self.req
            .query_function
            .push(QueryFunction::QueryServerInformation);
        self
    }

    pub fn application_namespaces(mut self) -> Self {
        self.req
            .query_function
            .push(QueryFunction::QueryApplicationNamespaces);
        self
    }

    // KMIP 1.1

    pub fn extension_list(mut self) -> Self {
        //TODO: Check client version first
        self.req
            .query_function
            .push(QueryFunction::QueryExtensionList);
        self
    }

    pub fn extension_map(mut self) -> Self {
        //TODO: Check client version first
        self.req
            .query_function
            .push(QueryFunction::QueryExtensionMap);
        self
    }

    // KMIP 1.2

    pub fn attestation_types(mut self) -> Self {
        //TODO: Check client version first
        self.req
            .query_function
            .push(QueryFunction::QueryAttestationTypes);
        self
    }

    // KMIP 1.3

    pub fn rngs(mut self) -> Self {
        //TODO: Check client version first
        self.req.query_function.push(QueryFunction::QueryRNGs);
        self
    }

    pub fn validations(mut self) -> Self {
        //TODO: Check client version first
        self.req
            .query_function
            .push(QueryFunction::QueryValidations);
        self
    }

    pub fn profiles(mut self) -> Self {
        //TODO: Check client version first
        self.req.query_function.push(QueryFunction::QueryProfiles);
        self
    }

    pub fn capabilities(mut self) -> Self {
        //TODO: Check client version first
        self.req
            .query_function
            .push(QueryFunction::QueryCapabilities);
        self
    }

    pub fn client_registration_methods(mut self) -> Self {
        //TODO: Check client version first
        self.req
            .query_function
            .push(QueryFunction::QueryClientRegistrationMethods);
        self
    }

    pub fn all(self) -> Self {
        self.operations()
            .objects()
            .server_information()
            .application_namespaces()
            .extension_list()
            .extension_map()
            .attestation_types()
            .rngs()
            .validations()
            .profiles()
            .capabilities()
            .client_registration_methods()
    }
}
