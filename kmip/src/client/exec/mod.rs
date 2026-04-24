use std::marker::PhantomData;

use crate::{
    Attribute, BatchClient, Link, LinkType, Name, ObjectType, Request, Result, UniqueIdentifier,
    UsageLimits, UsageLimitsUnit,
};

use super::{BatchExec, Client};

mod add_attribute;
mod create;
mod create_keypair;
mod delete_attribute;
mod encrypt_decrypt;
mod get;
mod get_attributes;
mod get_usage;
mod import_export;
mod locate;
mod modify_attribute;
mod query;
mod register;
mod rekey;
mod rekey_keypair;
mod revoke;
mod sign_verify;

macro_rules! impl_unique_identifier_op {
    ($method:ident, $payload:ident) => {
        impl $crate::Client {
            pub fn $method(
                &mut self,
                id: impl Into<String>,
            ) -> $crate::client::exec::Exec<'_, $crate::$payload> {
                $crate::client::exec::Exec::new(
                    self,
                    $crate::$payload {
                        unique_identifier: Some(id.into()),
                    },
                )
            }
        }

        impl<'a> $crate::BatchClient<'a> {
            pub fn $method(
                self,
                id: Option<String>,
            ) -> $crate::client::exec::Exec<'a, $crate::$payload> {
                $crate::client::exec::Exec::new(
                    self.0,
                    $crate::$payload {
                        unique_identifier: id,
                    },
                )
            }
        }
    };
}

impl_unique_identifier_op!(activate, ActivateRequestPayload);
impl_unique_identifier_op!(destroy, DestroyRequestPayload);
impl_unique_identifier_op!(obtain_lease, ObtainLeaseRequestPayload);
impl_unique_identifier_op!(get_attribute_list, GetAttributeListRequestPayload);
impl_unique_identifier_op!(archive, ArchiveRequestPayload);
impl_unique_identifier_op!(recover, RecoverRequestPayload);

pub struct WantExec;

#[must_use = "exec() must be called"]
pub struct Exec<'a, R: Request, S = WantExec> {
    client: &'a mut Client,
    req: R,
    _ph: PhantomData<S>,
}

impl<'a, R: Request, S> Exec<'a, R, S> {
    fn new(client: &'a mut Client, req: R) -> Self {
        Self {
            client,
            req,
            _ph: PhantomData,
        }
    }

    pub fn into_inner(self) -> R {
        self.req
    }

    pub(crate) fn unpack(self) -> (&'a mut Client, R) {
        (self.client, self.req)
    }

    pub fn inner(&self) -> &R {
        &self.req
    }

    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.req
    }
}

impl<'a, R: Request> Exec<'a, R, WantExec> {
    pub fn exec(self) -> Result<R::Response> {
        self.client.request(self.req)
    }
}

impl<'a, R: Request + 'static> Exec<'a, R, WantExec> {
    pub fn then<N: Request>(self, next: N) -> BatchExec<'a, (R, N)> {
        BatchExec::new(self.client, (self.req, next))
    }

    pub fn and_then<N, F>(self, f: F) -> BatchExec<'a, (R, N)>
    where
        N: Request + 'static,
        F: Fn(BatchClient<'a>) -> Exec<'a, N, WantExec>,
    {
        let bc = BatchExec::new(self.client, (self.req,));
        bc.and_then(f)
    }

    pub fn and_then_try<N, F, E>(self, f: F) -> std::result::Result<BatchExec<'a, (R, N)>, E>
    where
        N: Request + 'static,
        F: Fn(BatchClient<'a>) -> std::result::Result<Exec<'a, N, WantExec>, E>,
    {
        let bc = BatchExec::new(self.client, (self.req,));
        bc.and_then_try(f)
    }
}

trait Attributed {
    fn attributes_mut(&mut self) -> &mut Vec<Attribute>;
}

#[allow(private_bounds)]
impl<'a, R: Request, S> Exec<'a, R, S>
where
    Exec<'a, R, S>: Attributed,
{
    pub fn with_attributes(
        mut self,
        attrs: impl IntoIterator<Item = impl Into<Attribute>>,
    ) -> Self {
        self.attributes_mut()
            .extend(attrs.into_iter().map(Into::into));
        self
    }

    pub fn with_attribute(mut self, attr: impl Into<Attribute>) -> Self {
        self.attributes_mut().push(attr.into());
        self
    }

    pub fn with_name(self, name: impl Into<String>) -> Self {
        self.with_attribute(Name::new_string(name))
    }

    pub fn with_uri(self, uri: impl Into<String>) -> Self {
        self.with_attribute(Name::new_uri(uri))
    }

    pub fn with_unique_id(self, id: impl Into<String>) -> Self {
        self.with_attribute(UniqueIdentifier::from(id.into()))
    }

    pub fn with_link(self, link_type: LinkType, linked_id: impl Into<String>) -> Self {
        self.with_attribute(Link {
            link_type,
            linked_object_identifier: linked_id.into(),
        })
    }

    pub fn with_object_type(self, object_type: ObjectType) -> Self {
        self.with_attribute(object_type)
    }

    pub fn with_usage_limit(self, total: i64, unit: UsageLimitsUnit) -> Self {
        self.with_attribute(UsageLimits {
            usage_limits_count: Some(total),
            usage_limits_total: total,
            usage_limits_unit: unit,
        })
    }
}
