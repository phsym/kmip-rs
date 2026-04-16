use crate::{
    BatchErrorContinuationOption, DiscoverVersionsRequestPayload, DiscoverVersionsResponsePayload,
    Error, ProtocolError, ProtocolVersion, Request, RequestMessage, RequestPayload,
    ResponseBatchItem, ResponseMessage, ResponsePayload, Result, ResultReason,
};
use std::{
    fs,
    io::{self, ErrorKind, Read, Write},
    path::Path,
    sync::Arc,
    time::Instant,
    vec::IntoIter,
};

use ttlv::{Decodable, Decoder, Encodable, XmlDecoder, XmlEncoder};

mod batch;
pub use batch::*;

pub mod exec;

#[cfg(feature = "tls-rustls")]
mod rustls;
#[cfg(feature = "tls-rustls")]
pub use rustls::*;

#[cfg(feature = "tls-native")]
mod nativetls;
#[cfg(feature = "tls-native")]
pub use nativetls::*;

#[cfg(feature = "tls-openssl")]
mod openssl;
#[cfg(feature = "tls-openssl")]
pub use openssl::*;

#[cfg(feature = "tls-boring")]
mod boring;
#[cfg(feature = "tls-boring")]
pub use boring::*;

const DEFAULT_SUPPORTED_VERSIONS: &[ProtocolVersion] = &[
    ProtocolVersion::V1_4,
    ProtocolVersion::V1_3,
    ProtocolVersion::V1_2,
    ProtocolVersion::V1_1,
    ProtocolVersion::V1_0,
];

#[derive(Default)]
pub struct ClientBuilder {
    root_certs: Vec<Vec<u8>>,
    identity: Option<(Vec<u8>, Vec<u8>)>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_root_certificate_file(&mut self, path: impl AsRef<Path>) -> io::Result<&mut Self> {
        Ok(self.add_root_certificate(fs::read(path)?))
    }

    pub fn identity_file(
        &mut self,
        cert: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> io::Result<&mut Self> {
        Ok(self.identity(fs::read(cert)?, fs::read(key)?))
    }

    pub fn add_root_certificate(&mut self, pem: Vec<u8>) -> &mut Self {
        self.root_certs.push(pem);
        self
    }

    pub fn identity(&mut self, cert_pem: Vec<u8>, key_pem: Vec<u8>) -> &mut Self {
        self.identity = Some((cert_pem, key_pem));
        self
    }

    // TODO: Add KMIP authentication
    // TODO: Fine tune TLS cipher suites when/if possible
}

pub trait Transport: Read + Write + Send {}
impl<T> Transport for T where T: Read + Write + Send {}

pub trait Connector: Send {
    type Transport: Transport;
    fn connect(&self) -> Result<Self::Transport>;
}
struct BoxedConnector<C: Connector>(C);
impl<C: Connector> Connector for BoxedConnector<C>
where
    for<'a> C::Transport: 'a,
{
    type Transport = Box<dyn Transport>;

    fn connect(&self) -> Result<Self::Transport> {
        Ok(Box::new(self.0.connect()?))
    }
}

pub struct Client {
    connector: Box<dyn Connector<Transport = Box<dyn Transport>>>,
    supported_versions: Vec<ProtocolVersion>,
    version: Option<ProtocolVersion>,
    conn: ttlv::Stream<Box<dyn Transport>>,
    middlewares: Vec<Arc<dyn Middleware>>,
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub fn new<C: Connector + 'static>(connector: C) -> Result<Self> {
        let connector = Box::new(BoxedConnector(connector));
        Ok(Self {
            conn: ttlv::Stream::new(connector.connect()?),
            connector,
            supported_versions: DEFAULT_SUPPORTED_VERSIONS.to_vec(),
            version: None,
            middlewares: Vec::new(),
        })
    }

    pub fn with_middleware<M: Middleware + 'static>(mut self, middleware: M) -> Self {
        self.middlewares.push(Arc::new(middleware));
        self
    }

    pub fn with_version(mut self, version: ProtocolVersion) -> Self {
        self.version = Some(version);
        self
    }

    pub fn with_supported_versions(mut self, versions: &[ProtocolVersion]) -> Self {
        self.supported_versions.clear();
        self.supported_versions.extend_from_slice(versions);
        self.supported_versions.sort_by(|a, b| b.cmp(a));
        self.supported_versions.dedup();
        self
    }

    pub fn version(&mut self) -> crate::Result<ProtocolVersion> {
        if let Some(v) = &self.version {
            return Ok(*v);
        }
        let resp = self.roundtrip(&RequestMessage::new(
            ProtocolVersion::V1_1,
            DiscoverVersionsRequestPayload {
                protocol_version: if self.supported_versions.is_empty() {
                    DEFAULT_SUPPORTED_VERSIONS.to_vec()
                } else {
                    self.supported_versions.clone()
                },
            },
        ))?;

        let pl: DiscoverVersionsResponsePayload = match resp
            .batch_item
            .into_iter()
            .next()
            .ok_or(Error::MissingBatchItem)?
            .success()
        {
            Ok(pl) => pl.ok_or(Error::MissingResponsePayload)?.try_into()?,
            Err(ProtocolError {
                reason: Some(ResultReason::OperationNotSupported),
                ..
            }) => {
                // TODO: Check that default version is in the supported version list before using it
                self.version = Some(ProtocolVersion::default());
                return Ok(self.version.unwrap());
            }
            Err(other) => return Err(other.into()),
        };

        let version = pl.protocol_version.into_iter().next().unwrap_or_default();
        self.version = Some(version);
        // println!("Negociated version: {}", version);
        Ok(version)
    }

    fn roundtrip_ttlv<D: Decodable>(&mut self, msg: &impl Encodable) -> Result<D> {
        //TODO: Better reconnection loop. Do we really need a retry counter here ?
        let mut retry = 3;
        loop {
            match self.conn.roundtrip(msg) {
                Err(ttlv::Error::Io(e)) if retry > 0 && e.kind() == ErrorKind::UnexpectedEof => {
                    // println!("Error: {e:?}. Reconnecting");
                    self.conn = ttlv::Stream::new(self.connector.connect()?);
                    retry -= 1;
                    continue;
                }
                Err(e) => return Err(e.into()),
                Ok(resp) => return Ok(resp),
            }
        }
    }

    pub fn roundtrip(&mut self, msg: &RequestMessage) -> Result<ResponseMessage> {
        Next {
            idx: 0,
            client: self,
        }
        .run(msg)
    }

    pub fn request<R: Request>(&mut self, pl: R) -> Result<R::Response> {
        let msg = RequestMessage::new(self.version()?, pl);
        let resp = self.roundtrip(&msg)?;
        // TODO: Check batch item count
        resp.batch_item
            .into_iter()
            .next()
            .ok_or(Error::MissingBatchItem)?
            .success()?
            .ok_or(Error::MissingResponsePayload)?
            .try_into()
    }

    fn raw_batch<I, E>(
        &mut self,
        items: I,
        cont: Option<BatchErrorContinuationOption>,
    ) -> Result<ResponseBatchIter>
    where
        I: IntoIterator<Item = E>,
        E: Into<RequestPayload>,
    {
        let mut msg = RequestMessage::new_batched(self.version()?, items);
        msg.header.batch_error_continuation_option = cont;

        let resp = self.roundtrip(&msg)?;
        // TODO: Check batch item count
        Ok(ResponseBatchIter(resp.batch_item.into_iter()))
    }

    pub fn batch<I>(&mut self, batch: I) -> Result<I::Response>
    where
        I: Batch,
    {
        let resp = self.raw_batch(batch.into_iter(), None)?;
        I::map_response(resp)
    }

    pub fn batch_opt<I>(
        &mut self,
        batch: I,
        on_err: BatchErrorContinuationOption,
    ) -> Result<I::Response>
    where
        I: Batch,
    {
        let resp = self.raw_batch(batch.into_iter(), Some(on_err))?;
        I::map_response(resp)
    }
}

pub struct ResponseBatchIter(IntoIter<ResponseBatchItem>);

impl Iterator for ResponseBatchIter {
    type Item = Result<Option<ResponsePayload>>;
    fn next(&mut self) -> Option<Self::Item> {
        let next = self.0.next()?;
        Some(next.success().map_err(Into::into))
    }
}

pub trait Middleware: Send + Sync {
    fn call(&self, next: Next, req: &RequestMessage) -> Result<ResponseMessage>;
}

pub struct Next<'a> {
    idx: usize,
    client: &'a mut Client,
}

impl Next<'_> {
    fn run(mut self, req: &RequestMessage) -> Result<ResponseMessage> {
        if let Some(m) = self.client.middlewares.get(self.idx).cloned() {
            self.idx += 1;
            return m.call(self, req);
        }
        self.client.roundtrip_ttlv(req)
    }
}

pub struct DebugMiddleware;

impl Middleware for DebugMiddleware {
    fn call(&self, next: Next, req: &RequestMessage) -> Result<ResponseMessage> {
        let xml_req = XmlEncoder::encode_to_string(req);
        // println!("request: {msg:#?}");
        println!("Request:\n{xml_req}");
        let now = Instant::now();
        let response = next.run(req)?;
        // let response = client.roundtrip_ttlv::<ResponseMessage>(&msg).unwrap();
        // let response = client
        //     .roundtrip_ttlv::<TTLV<MaybeKnownTag<Tags>>>(&msg)
        //     .unwrap();

        let elapsed = now.elapsed().as_millis();

        let xml_resp = XmlEncoder::encode_to_string(&response);
        println!("\nResponse in {elapsed}ms:\n{xml_resp}\n");
        // println!("\nresponse in {elapsed}ms:\n{response:#?}");

        let mut xml_dec = XmlDecoder::new(xml_resp.as_bytes()).unwrap();
        let tt = xml_dec.decode().unwrap();
        // println!("\n{tt:#?}");
        assert_eq!(response, tt);
        Ok(response)
    }
}

pub struct CorrelationValueMiddleware<F>(F);

impl<T, F> Middleware for CorrelationValueMiddleware<F>
where
    T: Into<String>,
    F: Fn() -> T + Send + Sync,
{
    fn call(&self, next: Next, req: &RequestMessage) -> Result<ResponseMessage> {
        if req.header.client_correlation_value.is_some()
            || req.header.protocol_version < ProtocolVersion::V1_4
        {
            return next.run(req);
        }
        let mut req = req.clone();
        req.header.client_correlation_value = Some(self.0().into());
        next.run(&req)
    }
}

impl<T, F> CorrelationValueMiddleware<F>
where
    T: Into<String>,
    F: Fn() -> T + Send + Sync,
{
    pub fn new(f: F) -> Self {
        Self(f)
    }
}

#[cfg(feature = "uuid")]
impl CorrelationValueMiddleware<fn() -> uuid::Uuid> {
    pub fn uuid() -> Self {
        Self::new(uuid::Uuid::new_v4)
    }
}
