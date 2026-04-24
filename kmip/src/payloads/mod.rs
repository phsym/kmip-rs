mod add_attribute;
mod create;
mod create_keypair;
mod delete_attribute;
mod discover;
mod encrypt_decrypt;
mod get;
mod get_attribute_list;
mod get_attributes;
mod get_usage;
mod import_export;
mod locate;
mod modify_attribute;
mod obtain_lease;
mod query;
mod register;
mod rekey;
mod rekey_keypair;
mod revoke;
mod sign_verify;

pub use {
    add_attribute::*, create::*, create_keypair::*, delete_attribute::*, discover::*,
    encrypt_decrypt::*, get::*, get_attribute_list::*, get_attributes::*, get_usage::*,
    import_export::*, locate::*, modify_attribute::*, obtain_lease::*, query::*, register::*,
    rekey::*, rekey_keypair::*, revoke::*, sign_verify::*,
};

use strum_macros::{EnumIs, EnumTryAs};
use ttlv::{Decoder, Encodable, MaybeKnownTag, RawTag};

use crate::{Operations, Tags};

macro_rules! unique_identifier_request_payload {
    ($name:ident) => {
        #[cfg_attr(feature = "arbitrary", derive(::arbitrary::Arbitrary))]
        #[cfg_attr(feature = "serde", derive(::serde::Serialize))]
        #[derive(Debug, Clone, PartialEq, ::ttlv::Encodable, ::ttlv::Decodable)]
        #[ttlv(tag = $crate::Tags::RequestPayload)]
        pub struct $name {
            #[ttlv(tag = $crate::Tags::UniqueIdentifier)]
            pub unique_identifier: Option<String>,
        }
    };
}

macro_rules! unique_identifier_response_payload {
    ($name:ident) => {
        #[cfg_attr(feature = "arbitrary", derive(::arbitrary::Arbitrary))]
        #[cfg_attr(feature = "serde", derive(::serde::Serialize))]
        #[derive(Debug, Clone, PartialEq, ::ttlv::Encodable, ::ttlv::Decodable)]
        #[ttlv(tag = $crate::Tags::ResponsePayload)]
        pub struct $name {
            #[ttlv(tag = $crate::Tags::UniqueIdentifier)]
            pub unique_identifier: String,
        }
    };
}

pub(crate) use unique_identifier_request_payload;

// Ops whose request AND response are id-only are declared here. Ops whose response
// carries extra fields (GetAttributeList, ObtainLease) keep their own module and
// invoke `unique_identifier_request_payload!` locally.
unique_identifier_request_payload!(ActivateRequestPayload);
unique_identifier_response_payload!(ActivateResponsePayload);
unique_identifier_request_payload!(ArchiveRequestPayload);
unique_identifier_response_payload!(ArchiveResponsePayload);
unique_identifier_request_payload!(RecoverRequestPayload);
unique_identifier_response_payload!(RecoverResponsePayload);
unique_identifier_request_payload!(DestroyRequestPayload);
unique_identifier_response_payload!(DestroyResponsePayload);

pub trait Request: Into<RequestPayload> + TryFrom<RequestPayload, Error = crate::Error> {
    const OPERATION: Operations;
    type Response: Response<Request = Self>;
}

pub trait Response: Into<ResponsePayload> + TryFrom<ResponsePayload, Error = crate::Error> {
    type Request: Request<Response = Self>;
}

macro_rules! impl_payload {
    ($($name:ident => $req:ident, $resp:ident;)*) => {
        #[cfg_attr(feature = "arbitrary", derive(::arbitrary::Arbitrary))]
        #[cfg_attr(feature = "serde", derive(serde::Serialize), serde(untagged))]
        #[derive(Debug, Clone, PartialEq, Encodable, EnumIs, EnumTryAs)]
        #[ttlv(flatten)]
        #[allow(clippy::large_enum_variant)] // TODO: Remove this
        pub enum RequestPayload {
            $($name($req),) *
            Unknown(
                #[ttlv(skip)] RawTag,
                #[ttlv(tag = Tags::RequestPayload)] ttlv::Struct<MaybeKnownTag<Tags>>,
            ),
        }

        impl RequestPayload {
            pub fn decode_with(op: Operations, d: &mut impl Decoder) -> ttlv::Result<Self> {
                Ok(match op {
                    $(Operations::$name => Self::$name(d.decode()?),)*
                    Operations::Unknown(id) => Self::Unknown(id, d.tag_decode(Tags::RequestPayload)?),
                })
            }

            pub fn operation(&self) -> Operations {
                match self {
                    $(Self::$name(..) => Operations::$name,)*
                    Self::Unknown(op, ..) => Operations::Unknown(op.clone()),
                }
            }
        }

        #[cfg_attr(feature = "arbitrary", derive(::arbitrary::Arbitrary))]
        #[cfg_attr(feature = "serde", derive(serde::Serialize), serde(untagged))]
        #[derive(Debug, Clone, PartialEq, Encodable, EnumIs, EnumTryAs)]
        #[ttlv(flatten)]
        #[allow(clippy::large_enum_variant)] // TODO: Remove this
        pub enum ResponsePayload {
            $($name($resp),) *
            Unknown(
                #[ttlv(skip)] RawTag,
                #[ttlv(tag = Tags::ResponsePayload)] ttlv::Struct<MaybeKnownTag<Tags>>,
            ),
        }

        impl ResponsePayload {
            pub fn decode_with_opt(op: Operations, d: &mut impl Decoder) -> ttlv::Result<Option<Self>> {
                Ok(match op {
                    $(Operations::$name => d.decode::<Option<_>>()?.map(Self::$name),) *
                    Operations::Unknown(id) => d
                        .tag_decode::<Option<_>>(Tags::ResponsePayload)?
                        .map(|pl| ResponsePayload::Unknown(id, pl)),
                })
            }

            pub fn operation(&self) -> Operations {
                match self {
                    $(Self::$name(..) => Operations::$name,) *
                    Self::Unknown(op, ..) => Operations::Unknown(op.clone()),
                }
            }
        }

        $(
            impl From<$req> for RequestPayload {
                fn from(value: $req) -> Self {
                    Self::$name(value)
                }
            }

            impl From<$resp> for ResponsePayload {
                fn from(value: $resp) -> Self {
                    Self::$name(value)
                }
            }

            impl TryFrom<RequestPayload> for $req {
                type Error = crate::Error;

                fn try_from(value: RequestPayload) -> Result<Self, Self::Error> {
                    match value {
                        RequestPayload::$name(pl) => Ok(pl),
                        _ => Err(crate::Error::UnexpectedRequestPayload { want: std::stringify!($name) })
                    }
                }
            }

            impl TryFrom<ResponsePayload> for $resp {
                type Error = crate::Error;

                fn try_from(value: ResponsePayload) -> Result<Self, Self::Error> {
                    match value {
                        ResponsePayload::$name(pl) => Ok(pl),
                        _ => Err(crate::Error::UnexpectedResponsePayload { want: std::stringify!($name) })
                    }
                }
            }

            impl Request for $req {
                const OPERATION: Operations = Operations::$name;
                type Response = $resp;
            }

            impl Response for $resp {
                type Request = $req;
            }
        )*
    };
}

impl RequestPayload {
    pub fn new(pl: impl Into<RequestPayload>) -> Self {
        pl.into()
    }
}

impl_payload! {
    DiscoverVersions => DiscoverVersionsRequestPayload, DiscoverVersionsResponsePayload;
    Create => CreateRequestPayload, CreateResponsePayload;
    CreateKeyPair => CreateKeyPairRequestPayload, CreateKeyPairResponsePayload;
    Locate => LocateRequestPayload, LocateResponsePayload;
    GetAttributeList => GetAttributeListRequestPayload, GetAttributeListResponsePayload;
    GetAttributes => GetAttributesRequestPayload, GetAttributesResponsePayload;
    AddAttribute => AddAttributeRequestPayload, AddAttributeResponsePayload;
    ModifyAttribute => ModifyAttributeRequestPayload, ModifyAttributeResponsePayload;
    DeleteAttribute => DeleteAttributeRequestPayload, DeleteAttributeResponsePayload;
    Get => GetRequestPayload, GetResponsePayload;
    Register => RegisterRequestPayload, RegisterResponsePayload;
    Activate => ActivateRequestPayload, ActivateResponsePayload;
    Revoke => RevokeRequestPayload, RevokeResponsePayload;
    Destroy => DestroyRequestPayload, DestroyResponsePayload;
    Archive => ArchiveRequestPayload, ArchiveResponsePayload;
    Recover => RecoverRequestPayload, RecoverResponsePayload;
    Query => QueryRequestPayload, QueryResponsePayload;
    ObtainLease => ObtainLeaseRequestPayload, ObtainLeaseResponsePayload;
    GetUsageAllocation => GetUsageAllocationRequestPayload, GetUsageAllocationResponsePayload;
    ReKey => ReKeyRequestPayload, ReKeyResponsePayload;
    ReKeyKeyPair => ReKeyKeyPairRequestPayload, ReKeyKeyPairResponsePayload;
    Encrypt => EncryptRequestPayload, EncryptResponsePayload;
    Decrypt => DecryptRequestPayload, DecryptResponsePayload;
    Sign => SignRequestPayload, SignResponsePayload;
    SignatureVerify => SignatureVerifyRequestPayload, SignatureVerifyResponsePayload;
    Import => ImportRequestPayload, ImportResponsePayload;
    Export => ExportRequestPayload, ExportResponsePayload;
}
