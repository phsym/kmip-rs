use std::{sync::Arc, time::Instant};

use ttlv::XmlEncoder;

use crate::{RequestMessage, ResponseMessage, types::ProtocolVersion};

pub trait Middleware<E>: Send + Sync {
    fn call(&self, next: Next<E>, req: RequestMessage) -> std::result::Result<ResponseMessage, E>;
}

pub(crate) trait Chain {
    type Error;
    fn get_middleware(&self, idx: usize) -> Option<Arc<dyn Middleware<Self::Error>>>;
    fn final_handler(
        &mut self,
        req: RequestMessage,
    ) -> std::result::Result<ResponseMessage, Self::Error>;
}

pub struct Next<'a, E> {
    pub(crate) idx: usize,
    pub(crate) chain: &'a mut dyn Chain<Error = E>,
}

impl<'a, E> Next<'a, E> {
    pub fn run(mut self, req: RequestMessage) -> std::result::Result<ResponseMessage, E> {
        if let Some(m) = self.chain.get_middleware(self.idx) {
            self.idx += 1;
            return m.call(self, req);
        }
        self.chain.final_handler(req)
    }
}

pub struct DebugMiddleware;

impl<E> Middleware<E> for DebugMiddleware {
    fn call(&self, next: Next<E>, req: RequestMessage) -> std::result::Result<ResponseMessage, E> {
        let xml_req =
            XmlEncoder::encode_to_string(&req).unwrap_or("<failed to encode to XML>".into());
        println!("Request:\n{xml_req}");
        let now = Instant::now();
        let response = next.run(req)?;

        let elapsed = now.elapsed().as_millis();

        let xml_resp =
            XmlEncoder::encode_to_string(&response).unwrap_or("<failed to encode to XML>".into());
        println!("\nResponse in {elapsed}ms:\n{xml_resp}\n");
        Ok(response)
    }
}

pub struct CorrelationValueMiddleware<F>(F);

impl<T, F, E> Middleware<E> for CorrelationValueMiddleware<F>
where
    T: Into<String>,
    F: Fn() -> T + Send + Sync,
{
    fn call(
        &self,
        next: Next<E>,
        mut req: RequestMessage,
    ) -> std::result::Result<ResponseMessage, E> {
        if req.header.client_correlation_value.is_some()
            || req.header.protocol_version < ProtocolVersion::V1_4
        {
            return next.run(req);
        }
        req.header.client_correlation_value = Some(self.0().into());
        next.run(req)
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
