use std::{collections::HashMap, marker::PhantomData, panic::RefUnwindSafe};

use tracing::{debug, error, error_span};

use crate::{
    Operations, ProtocolError, Request, RequestMessage, RequestPayload, ResponseBatchItem,
    ResponseHeader, ResponseMessage, ResponsePayload, ResultReason, ResultStatus,
};

use super::RequestHandler;

pub trait OperationHandler: RefUnwindSafe + Send + Sync + 'static {
    type Request: Request;
    fn handle(
        &self,
        req: Self::Request,
    ) -> Result<<Self::Request as Request>::Response, ProtocolError>;
}

struct FnOperationWrapper<R: Request, F: Fn(R) -> Result<R::Response, ProtocolError>>(
    F,
    PhantomData<R>,
);

impl<R, F> OperationHandler for FnOperationWrapper<R, F>
where
    R: Request + RefUnwindSafe + Send + Sync + 'static,
    F: Fn(R) -> Result<R::Response, ProtocolError> + RefUnwindSafe + Send + Sync + 'static,
{
    type Request = R;

    fn handle(&self, req: R) -> Result<R::Response, ProtocolError> {
        self.0(req)
    }
}

trait PayloadHandler: RefUnwindSafe + Send + Sync {
    fn handle(&self, req: RequestPayload) -> Result<ResponsePayload, ProtocolError>;
}

struct PayloadHandlerWrapper<H: OperationHandler>(H);

impl<H: OperationHandler> PayloadHandler for PayloadHandlerWrapper<H> {
    fn handle(&self, req: RequestPayload) -> Result<ResponsePayload, ProtocolError> {
        Ok(self.0.handle(req.try_into().unwrap())?.into())
    }
}

#[derive(Default)]
pub struct Router {
    routes: HashMap<Operations, Box<dyn PayloadHandler>>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    // TODO: Bind handler's lifetime to router lifetime
    pub fn route<H: OperationHandler>(&mut self, hdl: H) {
        debug!("add route for {} operation", H::Request::OPERATION);
        self.routes
            .insert(H::Request::OPERATION, Box::new(PayloadHandlerWrapper(hdl)));
    }

    pub fn route_fn<R, F>(&mut self, f: F)
    where
        R: Request + RefUnwindSafe + Send + Sync + 'static,
        F: Fn(R) -> Result<R::Response, ProtocolError> + RefUnwindSafe + Send + Sync + 'static,
    {
        self.route(FnOperationWrapper(f, PhantomData))
    }

    pub fn route_fn_with<S, R, F>(&mut self, state: S, f: F)
    where
        R: Request + RefUnwindSafe + Send + Sync + 'static,
        S: RefUnwindSafe + Send + Sync + 'static,
        F: Fn(&S, R) -> Result<R::Response, ProtocolError> + RefUnwindSafe + Send + Sync + 'static,
    {
        self.route_fn(move |r: R| f(&state, r))
    }

    fn get_handler(&self, op: Operations) -> Option<&dyn PayloadHandler> {
        self.routes.get(&op).map(|b| &**b)
    }

    fn handle_batch_item(&self, pl: RequestPayload) -> Result<ResponsePayload, ProtocolError> {
        let res = std::panic::catch_unwind(|| {
            self.get_handler(pl.operation())
                .ok_or(ProtocolError::new_failed(
                    ResultReason::OperationNotSupported,
                    Some("The operation is not supported"),
                ))?
                .handle(pl)
        });
        match res {
            Ok(resp) => resp,
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<&str>() {
                    *s
                } else if let Some(s) = e.downcast_ref::<String>() {
                    &**s
                } else {
                    "unknown error"
                };
                error!(err = msg, "handler panicked");
                Err(ProtocolError::new_failed(
                    ResultReason::GeneralFailure,
                    Some("Internal Server Error"),
                ))
            }
        }
    }
}

impl RequestHandler for Router {
    fn handle(&self, req: RequestMessage) -> ResponseMessage {
        let mut resp = ResponseMessage {
            header: ResponseHeader {
                batch_count: req.header.batch_count,
                protocol_version: req.header.protocol_version,
                timestamp: chrono::Local::now(),
                attestation_type: None,
                client_correlation_value: None,
                nonce: None,
                server_correlation_value: None,
            },
            batch_item: Vec::with_capacity(req.batch_item.len()),
        };
        // Per the KMIP spec, the `batch_count` header must equal the actual
        // number of batch items. A mismatch is a protocol violation and must
        // be reported as `InvalidMessage`.
        if req.header.batch_count < 0 || (req.header.batch_count as usize) != req.batch_item.len() {
            error!(
                batch_count = req.header.batch_count,
                batch_item_len = req.batch_item.len(),
                "batch_count header does not match batch_item length"
            );
            resp.header.batch_count = 1;
            resp.batch_item.clear();
            resp.batch_item.push(ResponseBatchItem {
                operation: None,
                response_payload: None,
                unique_batch_item_id: None,
                result_status: ResultStatus::OperationFailed,
                result_reason: Some(ResultReason::InvalidMessage),
                result_message: Some("batch_count does not match batch_item length".to_string()),
                asynchronous_correlation_value: None,
                message_extension: None,
            });
            return resp;
        }
        for bi in req.batch_item {
            let _sp = error_span!("batch-item", operation = %bi.operation).entered(); //TODO: Add batch-item id
            debug!("processing batch-item");
            let mut rbi = ResponseBatchItem {
                operation: Some(bi.request_payload.operation()),
                response_payload: None,
                unique_batch_item_id: bi.unique_batch_item_id,
                result_status: ResultStatus::Success,
                result_reason: None,
                result_message: None,
                asynchronous_correlation_value: None,
                message_extension: None,
            };
            match self.handle_batch_item(bi.request_payload) {
                Ok(pl) => rbi.response_payload = Some(pl),
                Err(e) => {
                    rbi.result_status = e.status;
                    rbi.result_reason = e.reason;
                    rbi.result_message = e.message
                }
            }
            resp.batch_item.push(rbi);
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DiscoverVersionsRequestPayload, ProtocolVersion, RequestBatchItem, RequestHeader};

    fn make_request(batch_count: i32, item_count: usize) -> RequestMessage {
        let items: Vec<RequestBatchItem> = (0..item_count)
            .map(|_| {
                RequestBatchItem::new(
                    DiscoverVersionsRequestPayload {
                        protocol_version: vec![],
                    },
                    None,
                )
            })
            .collect();
        RequestMessage {
            header: RequestHeader {
                protocol_version: ProtocolVersion::V1_4,
                batch_count,
                asynchronous_indicator: None,
                authentication: None,
                maximum_response_size: None,
                batch_error_continuation_option: None,
                batch_order_option: None,
                timestamp: Some(chrono::Local::now()),
                attestation_capable_indicator: None,
                attestation_type: None,
                client_correlation_value: None,
                server_correlation_value: None,
            },
            batch_item: items,
        }
    }

    #[test]
    fn router_rejects_batch_count_greater_than_items() {
        let router = Router::new();
        let req = make_request(2, 1);
        let resp = router.handle(req);
        assert_eq!(resp.batch_item.len(), 1);
        let bi = &resp.batch_item[0];
        assert_eq!(bi.result_status, ResultStatus::OperationFailed);
        assert_eq!(bi.result_reason, Some(ResultReason::InvalidMessage));
        assert_eq!(bi.operation, None);
    }

    #[test]
    fn router_rejects_batch_count_less_than_items() {
        let router = Router::new();
        let req = make_request(1, 3);
        let resp = router.handle(req);
        assert_eq!(resp.batch_item.len(), 1);
        assert_eq!(
            resp.batch_item[0].result_status,
            ResultStatus::OperationFailed
        );
        assert_eq!(
            resp.batch_item[0].result_reason,
            Some(ResultReason::InvalidMessage)
        );
    }

    #[test]
    fn router_rejects_negative_batch_count() {
        let router = Router::new();
        let req = make_request(-1, 0);
        let resp = router.handle(req);
        assert_eq!(resp.batch_item.len(), 1);
        assert_eq!(
            resp.batch_item[0].result_status,
            ResultStatus::OperationFailed
        );
        assert_eq!(
            resp.batch_item[0].result_reason,
            Some(ResultReason::InvalidMessage)
        );
    }

    #[test]
    fn router_accepts_matching_batch_count() {
        // No route is registered, so batch items will get OperationNotSupported,
        // but the batch_count validation must pass (it happens before per-item
        // handling).
        let router = Router::new();
        let req = make_request(2, 2);
        let resp = router.handle(req);
        assert_eq!(resp.header.batch_count, 2);
        assert_eq!(resp.batch_item.len(), 2);
        for bi in &resp.batch_item {
            assert_eq!(bi.result_status, ResultStatus::OperationFailed);
            assert_eq!(bi.result_reason, Some(ResultReason::OperationNotSupported));
        }
    }

    #[test]
    fn router_accepts_zero_batch_count_with_zero_items() {
        let router = Router::new();
        let req = make_request(0, 0);
        let resp = router.handle(req);
        assert_eq!(resp.header.batch_count, 0);
        assert!(resp.batch_item.is_empty());
    }
}
