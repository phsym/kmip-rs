use crate::{
    Error, ProtocolError, RequestMessage, ResponseBatchItem, ResponseMessage, Result,
    enums::{BatchErrorContinuationOption, ResultReason},
    payloads::{
        DiscoverVersionsRequestPayload, DiscoverVersionsResponsePayload, Request, RequestPayload,
        ResponsePayload,
    },
    types::ProtocolVersion,
};
use std::{
    fs,
    io::{self, ErrorKind, Read, Write},
    net::TcpStream,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
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

const DEFAULT_SOCKET_TIMEOUT: Option<Duration> = Some(Duration::from_secs(30));

#[must_use = "builder must be used to create a Client"]
pub struct ClientBuilder {
    root_certs: Vec<Vec<u8>>,
    identity: Option<(Vec<u8>, Vec<u8>)>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            root_certs: Vec::new(),
            identity: None,
            read_timeout: DEFAULT_SOCKET_TIMEOUT,
            write_timeout: DEFAULT_SOCKET_TIMEOUT,
            tcp_nodelay: true,
        }
    }
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

    /// Sets the read timeout applied to the underlying `TcpStream` before the
    /// TLS handshake. `None` disables the timeout (reads block indefinitely).
    pub fn read_timeout(&mut self, timeout: Option<Duration>) -> &mut Self {
        self.read_timeout = timeout;
        self
    }

    /// Sets the write timeout applied to the underlying `TcpStream` before the
    /// TLS handshake. `None` disables the timeout (writes block indefinitely).
    pub fn write_timeout(&mut self, timeout: Option<Duration>) -> &mut Self {
        self.write_timeout = timeout;
        self
    }

    /// Enables or disables `TCP_NODELAY` (Nagle's algorithm) on the underlying
    /// socket. Enabled by default to minimize request/response latency.
    pub fn tcp_nodelay(&mut self, nodelay: bool) -> &mut Self {
        self.tcp_nodelay = nodelay;
        self
    }

    // TODO: Add KMIP authentication
    // TODO: Fine tune TLS cipher suites when/if possible
}

pub(crate) fn configure_stream(
    stream: &TcpStream,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    tcp_nodelay: bool,
) -> io::Result<()> {
    stream.set_read_timeout(read_timeout)?;
    stream.set_write_timeout(write_timeout)?;
    stream.set_nodelay(tcp_nodelay)?;
    Ok(())
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
        let resp = Next {
            idx: 0,
            client: self,
        }
        .run(msg)?;
        validate_batch_count(&resp)?;
        Ok(resp)
    }

    pub fn request<R: Request>(&mut self, pl: R) -> Result<R::Response> {
        let msg = RequestMessage::new(self.version()?, pl);
        let resp = self.roundtrip(&msg)?;
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
        let mut msg = RequestMessage::new_batched(self.version()?, items)?;
        msg.header.batch_error_continuation_option = cont;

        let resp = self.roundtrip(&msg)?;
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

/// Validates that the `batch_count` field in a response header matches the
/// actual number of batch items in the message, as required by the KMIP spec.
#[inline]
fn validate_batch_count(resp: &ResponseMessage) -> Result<()> {
    let expected = resp.header.batch_count;
    let got = resp.batch_item.len();
    if expected < 0 || (expected as usize) != got {
        return Err(Error::BatchCountMismatch { expected, got });
    }
    Ok(())
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
        let xml_req = XmlEncoder::encode_to_string(req)?;
        // println!("request: {msg:#?}");
        println!("Request:\n{xml_req}");
        let now = Instant::now();
        let response = next.run(req)?;
        // let response = client.roundtrip_ttlv::<ResponseMessage>(&msg).unwrap();
        // let response = client
        //     .roundtrip_ttlv::<TTLV<MaybeKnownTag<Tags>>>(&msg)
        //     .unwrap();

        let elapsed = now.elapsed().as_millis();

        let xml_resp = XmlEncoder::encode_to_string(&response)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_client_builder_defaults() {
        let builder = ClientBuilder::new();
        assert_eq!(builder.read_timeout, Some(Duration::from_secs(30)));
        assert_eq!(builder.write_timeout, Some(Duration::from_secs(30)));
        assert!(builder.tcp_nodelay);
    }

    #[test]
    fn test_client_builder_custom_timeouts() {
        let mut builder = ClientBuilder::new();
        builder
            .read_timeout(Some(Duration::from_secs(10)))
            .write_timeout(Some(Duration::from_secs(60)))
            .tcp_nodelay(false);

        assert_eq!(builder.read_timeout, Some(Duration::from_secs(10)));
        assert_eq!(builder.write_timeout, Some(Duration::from_secs(60)));
        assert!(!builder.tcp_nodelay);
    }

    #[test]
    fn test_client_builder_disable_timeouts() {
        let mut builder = ClientBuilder::new();
        builder.read_timeout(None).write_timeout(None);

        assert_eq!(builder.read_timeout, None);
        assert_eq!(builder.write_timeout, None);
    }

    #[test]
    fn test_configure_stream_applies_settings() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();

        configure_stream(
            &stream,
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(10)),
            true,
        )
        .unwrap();

        assert_eq!(stream.read_timeout().unwrap(), Some(Duration::from_secs(5)));
        assert_eq!(
            stream.write_timeout().unwrap(),
            Some(Duration::from_secs(10))
        );
        assert!(stream.nodelay().unwrap());
    }

    #[test]
    fn test_configure_stream_no_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();

        configure_stream(&stream, None, None, false).unwrap();

        assert_eq!(stream.read_timeout().unwrap(), None);
        assert_eq!(stream.write_timeout().unwrap(), None);
        assert!(!stream.nodelay().unwrap());
    }

    fn make_response(batch_count: i32, item_count: usize) -> ResponseMessage {
        let items: Vec<ResponseBatchItem> = (0..item_count)
            .map(|_| ResponseBatchItem {
                operation: None,
                response_payload: None,
                unique_batch_item_id: None,
                result_status: crate::enums::ResultStatus::Success,
                result_reason: None,
                result_message: None,
                asynchronous_correlation_value: None,
                message_extension: None,
            })
            .collect();
        ResponseMessage {
            header: crate::ResponseHeader {
                protocol_version: ProtocolVersion::V1_4,
                timestamp: chrono::Local::now(),
                nonce: None,
                attestation_type: None,
                client_correlation_value: None,
                server_correlation_value: None,
                batch_count,
            },
            batch_item: items,
        }
    }

    #[test]
    fn validate_batch_count_matches() {
        let resp = make_response(2, 2);
        assert!(validate_batch_count(&resp).is_ok());
    }

    #[test]
    fn validate_batch_count_zero_empty() {
        let resp = make_response(0, 0);
        assert!(validate_batch_count(&resp).is_ok());
    }

    #[test]
    fn validate_batch_count_header_too_large() {
        let resp = make_response(3, 1);
        match validate_batch_count(&resp) {
            Err(Error::BatchCountMismatch {
                expected: 3,
                got: 1,
            }) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn validate_batch_count_header_too_small() {
        let resp = make_response(1, 4);
        match validate_batch_count(&resp) {
            Err(Error::BatchCountMismatch {
                expected: 1,
                got: 4,
            }) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn validate_batch_count_negative_header() {
        let resp = make_response(-1, 0);
        match validate_batch_count(&resp) {
            Err(Error::BatchCountMismatch {
                expected: -1,
                got: 0,
            }) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }
}
