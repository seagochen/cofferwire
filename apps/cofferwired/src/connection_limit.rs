//! Process-wide TLS connection admission control.

use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower_service::Service;

use crate::MAX_CONNECTIONS;

/// Acceptor layer that rejects TLS connections above a process-wide bound.
#[derive(Clone, Debug)]
pub struct ConnectionLimit {
    permits: Arc<Semaphore>,
}

impl ConnectionLimit {
    /// Creates the reference daemon's connection limiter.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(MAX_CONNECTIONS)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(capacity)),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }
}

impl Default for ConnectionLimit {
    fn default() -> Self {
        Self::new()
    }
}

impl<I, S> axum_server::accept::Accept<I, S> for ConnectionLimit {
    type Stream = I;
    type Service = ConnectionService<S>;
    type Future = std::future::Ready<std::io::Result<(I, Self::Service)>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let result = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map(|permit| {
                (
                    stream,
                    ConnectionService {
                        inner: service,
                        permit: ConnectionPermit {
                            _permit: Arc::new(permit),
                        },
                    },
                )
            })
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "connection limit reached",
                )
            });
        std::future::ready(result)
    }
}

/// Service wrapper retaining one connection permit until Hyper drops it.
#[derive(Clone, Debug)]
pub struct ConnectionService<S> {
    inner: S,
    permit: ConnectionPermit,
}

#[derive(Clone, Debug)]
pub(crate) struct ConnectionPermit {
    _permit: Arc<OwnedSemaphorePermit>,
}

impl<S, B> Service<axum::http::Request<B>> for ConnectionService<S>
where
    S: Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: axum::http::Request<B>) -> Self::Future {
        request.extensions_mut().insert(self.permit.clone());
        self.inner.call(request)
    }
}
