//! Bounded HTTPS and WebSocket transport adapters.

use std::convert::Infallible;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode as HttpStatus};
use axum::response::{IntoResponse, Response as HttpResponse};
use axum::routing::{get, post};
use axum::Router;
use cofferwire_types::blob::MAX_BLOB_FRAME_BYTES;
use cofferwire_types::MAX_FRAME_BYTES;
use futures_util::StreamExt;
use tokio::sync::OwnedSemaphorePermit;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::connection_limit::ConnectionPermit;
use crate::{
    RelayService, BLOB_FRAME_MEDIA_TYPE, BLOB_WEBSOCKET_PROTOCOL, FRAME_MEDIA_TYPE,
    REQUEST_TIMEOUT, WEBSOCKET_IDLE_TIMEOUT, WEBSOCKET_PROTOCOL,
};

struct OptionalConnectionPermit(Option<ConnectionPermit>);

impl<S> FromRequestParts<S> for OptionalConnectionPermit
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.extensions.get::<ConnectionPermit>().cloned()))
    }
}

/// Builds the bounded HTTPS/WebSocket application router.
pub fn router(service: RelayService) -> Router {
    let queue_routes = Router::new()
        .route("/v1/frame", post(post_frame))
        .route("/v1/ws", get(upgrade_websocket))
        .layer(RequestBodyLimitLayer::new(MAX_FRAME_BYTES));
    let blob_routes = Router::new()
        .route("/blob/v1/frame", post(post_blob_frame))
        .route("/blob/v1/ws", get(upgrade_blob_websocket))
        .layer(RequestBodyLimitLayer::new(MAX_BLOB_FRAME_BYTES));
    Router::new()
        .route("/healthz", get(|| async { HttpStatus::NO_CONTENT }))
        .merge(queue_routes)
        .merge(blob_routes)
        .layer(DefaultBodyLimit::disable())
        .layer(TimeoutLayer::new(REQUEST_TIMEOUT))
        .with_state(service)
}

async fn post_blob_frame(
    State(service): State<RelayService>,
    headers: HeaderMap,
    body: Bytes,
) -> HttpResponse {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(BLOB_FRAME_MEDIA_TYPE)
    {
        return HttpStatus::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    match service.exchange_blob(body.to_vec()).await {
        Ok(response) => ([(header::CONTENT_TYPE, BLOB_FRAME_MEDIA_TYPE)], response).into_response(),
        Err(_) => HttpStatus::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn post_frame(
    State(service): State<RelayService>,
    headers: HeaderMap,
    body: Bytes,
) -> HttpResponse {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(FRAME_MEDIA_TYPE)
    {
        return HttpStatus::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    match service.exchange(body.to_vec()).await {
        Ok(response) => ([(header::CONTENT_TYPE, FRAME_MEDIA_TYPE)], response).into_response(),
        Err(_) => HttpStatus::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn upgrade_blob_websocket(
    State(service): State<RelayService>,
    OptionalConnectionPermit(connection_permit): OptionalConnectionPermit,
    upgrade: WebSocketUpgrade,
) -> HttpResponse {
    let Ok(permit) = Arc::clone(&service.websocket_connections).try_acquire_owned() else {
        return HttpStatus::SERVICE_UNAVAILABLE.into_response();
    };
    upgrade
        .protocols([BLOB_WEBSOCKET_PROTOCOL])
        .max_message_size(MAX_BLOB_FRAME_BYTES)
        .max_frame_size(MAX_BLOB_FRAME_BYTES)
        .on_upgrade(move |socket| {
            websocket_session(socket, service, permit, connection_permit, true)
        })
        .into_response()
}

async fn upgrade_websocket(
    State(service): State<RelayService>,
    OptionalConnectionPermit(connection_permit): OptionalConnectionPermit,
    upgrade: WebSocketUpgrade,
) -> HttpResponse {
    let Ok(permit) = Arc::clone(&service.websocket_connections).try_acquire_owned() else {
        return HttpStatus::SERVICE_UNAVAILABLE.into_response();
    };
    upgrade
        .protocols([WEBSOCKET_PROTOCOL])
        .max_message_size(MAX_FRAME_BYTES)
        .max_frame_size(MAX_FRAME_BYTES)
        .on_upgrade(move |socket| {
            websocket_session(socket, service, permit, connection_permit, false)
        })
        .into_response()
}

async fn websocket_session(
    mut socket: WebSocket,
    service: RelayService,
    _permit: OwnedSemaphorePermit,
    _connection_permit: Option<ConnectionPermit>,
    blob: bool,
) {
    loop {
        let Ok(Some(Ok(message))) =
            tokio::time::timeout(WEBSOCKET_IDLE_TIMEOUT, socket.next()).await
        else {
            break;
        };
        match message {
            Message::Binary(bytes) => {
                let response = if blob {
                    service.exchange_blob(bytes.to_vec()).await
                } else {
                    service.exchange(bytes.to_vec()).await
                };
                let Ok(response) = response else {
                    break;
                };
                if socket.send(Message::Binary(response.into())).await.is_err() {
                    break;
                }
            }
            Message::Close(_) | Message::Text(_) => break,
            Message::Ping(_) | Message::Pong(_) => {}
        }
    }
}
