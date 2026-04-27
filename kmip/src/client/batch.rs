use crate::{
    Error, Result,
    client::{Client, ResponseBatchIter, exec::Exec},
    enums::BatchErrorContinuationOption,
    payloads::{Request, RequestPayload},
};

pub struct BatchClient<'a>(pub(crate) &'a mut Client);

#[must_use = "exec() must be called"]
pub struct BatchExec<'a, B> {
    client: &'a mut Client,
    batch: B,
}

impl<B: Batch> BatchExec<'_, B> {
    pub fn exec(self) -> Result<B::Response> {
        self.client.batch(self.batch)
    }

    pub fn exec_opt(self, on_err: BatchErrorContinuationOption) -> Result<B::Response> {
        self.client.batch_opt(self.batch, on_err)
    }
}

impl<'a, B> BatchExec<'a, B> {
    pub(crate) fn new(client: &'a mut Client, batch: B) -> Self {
        Self { client, batch }
    }

    pub fn into_inner(self) -> B {
        self.batch
    }

    pub fn inner(&self) -> &B {
        &self.batch
    }

    pub fn inner_mut(&mut self) -> &mut B {
        &mut self.batch
    }

    pub fn then<R>(self, req: R) -> BatchExec<'a, B::Output>
    where
        R: Into<RequestPayload>,
        B: BatchAppend<R>,
    {
        BatchExec {
            client: self.client,
            batch: self.batch.batch_append(req),
        }
    }

    pub fn and_then<R, F>(self, f: F) -> BatchExec<'a, B::Output>
    where
        R: Request,
        B: BatchAppend<R>,
        F: Fn(BatchClient<'a>) -> Exec<'a, R>,
    {
        let (client, next) = f(BatchClient(self.client)).unpack();
        BatchExec {
            client,
            batch: self.batch.batch_append(next),
        }
    }

    pub fn and_then_try<R, F, E>(self, f: F) -> std::result::Result<BatchExec<'a, B::Output>, E>
    where
        R: Request,
        B: BatchAppend<R>,
        F: Fn(BatchClient<'a>) -> std::result::Result<Exec<'a, R>, E>,
    {
        let (client, next) = f(BatchClient(self.client))?.unpack();
        Ok(BatchExec {
            client,
            batch: self.batch.batch_append(next),
        })
    }
}

pub trait BatchResultExt {
    type Output;
    type Error;
    fn flatten(self) -> std::result::Result<Self::Output, Self::Error>;
}

impl<T, E> BatchResultExt for Vec<std::result::Result<T, E>> {
    type Output = Vec<T>;
    type Error = E;
    fn flatten(self) -> std::result::Result<Self::Output, Self::Error> {
        self.into_iter().collect::<std::result::Result<Vec<_>, _>>()
    }
}

impl<T, E, const N: usize> BatchResultExt for [std::result::Result<T, E>; N] {
    type Output = Vec<T>;
    type Error = E;
    fn flatten(self) -> std::result::Result<Self::Output, Self::Error> {
        self.into_iter().collect::<std::result::Result<Vec<_>, _>>()
    }
}

impl<T: BatchResultExt> BatchResultExt for std::result::Result<T, T::Error> {
    type Output = T::Output;
    type Error = T::Error;
    fn flatten(self) -> std::result::Result<Self::Output, Self::Error> {
        self?.flatten()
    }
}

pub trait Batch {
    type Response: 'static;

    fn into_iter(self) -> impl Iterator<Item = RequestPayload>;
    fn map_response(resp: ResponseBatchIter) -> Result<Self::Response>;
}

pub trait BatchAppend<R: Into<RequestPayload>> {
    type Output: Batch;

    fn batch_append(self, req: R) -> Self::Output;
}

impl<E> Batch for Vec<E>
where
    E: Into<RequestPayload>,
{
    type Response = ResponseBatchIter;

    fn into_iter(self) -> impl Iterator<Item = RequestPayload> {
        IntoIterator::into_iter(self).map(Into::into)
    }

    fn map_response(resp: ResponseBatchIter) -> Result<Self::Response> {
        Ok(resp)
    }
}

impl<E> BatchAppend<E> for Vec<E>
where
    E: Into<RequestPayload>,
{
    type Output = Vec<E>;
    fn batch_append(mut self, req: E) -> Self::Output {
        self.push(req);
        self
    }
}

impl<E, const N: usize> Batch for [E; N]
where
    E: Into<RequestPayload>,
{
    type Response = ResponseBatchIter;

    fn into_iter(self) -> impl Iterator<Item = RequestPayload> {
        IntoIterator::into_iter(self).map(Into::into)
    }

    fn map_response(resp: ResponseBatchIter) -> Result<Self::Response> {
        Ok(resp)
    }
}

macro_rules! impl_batch {
    ()=> {};
    ($first:ident, $($ident:ident,)*) => {
        impl <$first: Request+'static, $($ident: Request+'static),*> Batch for ($first, $($ident),*) {
            type Response = (Result<$first::Response>, $(Result<$ident::Response>), *);

            fn into_iter(self) -> impl Iterator<Item=RequestPayload> {
                #[allow(non_snake_case)]
                let ($first, $($ident,) *) = self;
                IntoIterator::into_iter([$first.into(), $($ident.into(),) *])
            }

            #[allow(non_snake_case)]
            fn map_response(mut resp: ResponseBatchIter) -> Result<Self::Response> {
                let $first = resp.next().unwrap_or(Err(Error::MissingBatchItem));
                $(
                    let $ident = resp.next().unwrap_or(Err(Error::MissingBatchItem));
                )*
                Ok((
                    $first.and_then(|r|
                        r.ok_or(Error::MissingResponsePayload)
                            .and_then(|r| r.try_into())
                    ),
                    $(
                        $ident.and_then(|r|
                            r.ok_or(Error::MissingResponsePayload)
                                .and_then(|r| r.try_into())
                        ),
                    ) *
                ))
            }
        }

        impl<EE, $($ident: Request+'static),*> BatchAppend<EE> for ($($ident,)*)
        where
            EE: Request+'static,
        {
            type Output = ($($ident, )* EE,);

            fn batch_append(self, req: EE) -> Self::Output {
                #[allow(non_snake_case)]
                let ($($ident, )*) = self;
                ($($ident, )* req,)
            }
        }

        impl <ERR, $first, $($ident),*> BatchResultExt for (std::result::Result<$first, ERR>, $(std::result::Result<$ident, ERR>),*) {
            type Output = ($first, $($ident),*);
            type Error = ERR;

            fn flatten(self) -> std::result::Result<Self::Output, Self::Error> {
                #[allow(non_snake_case)]
                let ($first, $($ident,) *) = self;
                Ok(
                    ($first?, $($ident?),*)
                )
            }
        }

        impl_batch!($($ident,)*);
    };
}

impl_batch!(
    A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z,
);
