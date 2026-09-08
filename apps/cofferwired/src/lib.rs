//! HTTPS and WebSocket bindings for the durable Cofferwire relay.

#![forbid(unsafe_code)]

mod connection_limit;
mod rate_limit;
mod transport;

pub use connection_limit::ConnectionLimit;
use rate_limit::RateLimiter;
pub use transport::router;

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cofferwire_codec::blob::{decode_blob_request, encode_blob_response};
use cofferwire_codec::{decode_request, encode_response, DecodeError, ResponseFrame};
use cofferwire_crypto::blob::verify_blob_request;
use cofferwire_crypto::verify_request;
use cofferwire_relay as relay;
use cofferwire_types::blob::{BlobResponse, BlobResponseBody, BlobResponseFrame, BlobStatus};
use cofferwire_types::{
    Command, ErrorResponse, Principal, Request, RequestId, Response, ResponseBody, Status,
};
use tokio::sync::Semaphore;

/// Media type for an exact Cofferwire protocol frame.
pub const FRAME_MEDIA_TYPE: &str = "application/cofferwire";
/// WebSocket subprotocol for exact v1 frames.
pub const WEBSOCKET_PROTOCOL: &str = "cofferwire.v1";
/// Media type for a blob/1 frame.
pub const BLOB_FRAME_MEDIA_TYPE: &str = "application/cofferwire-blob";
/// WebSocket subprotocol for blob/1 frames.
pub const BLOB_WEBSOCKET_PROTOCOL: &str = "cofferwire.blob.v1";
/// Maximum concurrent commands across both bindings.
pub const MAX_CONCURRENT_COMMANDS: usize = 64;
/// Maximum accepted TLS connections, including HTTP keep-alive and WebSocket.
pub const MAX_CONNECTIONS: usize = 256;
/// Maximum live WebSocket sessions.
pub const MAX_WEBSOCKET_CONNECTIONS: usize = 128;
/// Hard deadline for one HTTPS request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Idle deadline while waiting for the next WebSocket frame.
pub const WEBSOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Rolling window over which queue-command requests are rate-limited per
/// authenticated principal.
pub const QUEUE_RATE_LIMIT_WINDOW_SECS: u64 = 60;
/// Maximum queue-command requests one principal may make per
/// [`QUEUE_RATE_LIMIT_WINDOW_SECS`]-second window.
pub const QUEUE_RATE_LIMIT_MAX_REQUESTS: usize = 300;
/// Rolling window over which blob-command requests are rate-limited per
/// authenticated capability.
pub const BLOB_RATE_LIMIT_WINDOW_SECS: u64 = 60;
/// Maximum blob-command requests one capability may make per
/// [`BLOB_RATE_LIMIT_WINDOW_SECS`]-second window. Higher than the queue
/// budget because one legitimate large-object transfer issues one request
/// per chunk under the same upload or download capability.
pub const BLOB_RATE_LIMIT_MAX_REQUESTS: usize = 1_000;
/// Maximum distinct principals or capabilities tracked at once by a rate
/// limiter, bounding its memory under a flood of distinct identities.
pub const RATE_LIMIT_MAX_TRACKED_KEYS: usize = 100_000;

/// Shared durable relay state used by both transport bindings.
#[derive(Clone, Debug)]
pub struct RelayService {
    relay: Arc<Mutex<relay::DurableRelay>>,
    commands: Arc<Semaphore>,
    websocket_connections: Arc<Semaphore>,
    queue_rate_limiter: Arc<RateLimiter<Principal>>,
    blob_rate_limiter: Arc<RateLimiter<cofferwire_types::blob::CapabilityId>>,
}

impl RelayService {
    /// Opens the durable relay database.
    ///
    /// # Errors
    ///
    /// Returns a durable storage error if the database cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, relay::DurableRelayError> {
        Ok(Self::new(relay::DurableRelay::open(path)?))
    }

    /// Wraps an already-open durable relay.
    #[must_use]
    pub fn new(relay: relay::DurableRelay) -> Self {
        Self {
            relay: Arc::new(Mutex::new(relay)),
            commands: Arc::new(Semaphore::new(MAX_CONCURRENT_COMMANDS)),
            websocket_connections: Arc::new(Semaphore::new(MAX_WEBSOCKET_CONNECTIONS)),
            queue_rate_limiter: Arc::new(RateLimiter::new(
                QUEUE_RATE_LIMIT_WINDOW_SECS,
                QUEUE_RATE_LIMIT_MAX_REQUESTS,
                RATE_LIMIT_MAX_TRACKED_KEYS,
            )),
            blob_rate_limiter: Arc::new(RateLimiter::new(
                BLOB_RATE_LIMIT_WINDOW_SECS,
                BLOB_RATE_LIMIT_MAX_REQUESTS,
                RATE_LIMIT_MAX_TRACKED_KEYS,
            )),
        }
    }

    /// Exchanges one frame at a caller-supplied relay time.
    ///
    /// This deterministic entry point exists for transport-neutral conformance
    /// and cross-implementation runners. Production transports sample their own
    /// clock through the private asynchronous exchange path.
    ///
    /// # Errors
    ///
    /// Returns [`FrameExchangeError`] when durable storage cannot complete the
    /// command.
    pub fn exchange_frame_at(
        &self,
        bytes: &[u8],
        now_seconds: u64,
    ) -> Result<Vec<u8>, FrameExchangeError> {
        self.exchange_at(bytes, relay::Timestamp::from_secs(now_seconds))
            .map_err(|_| FrameExchangeError)
    }

    /// Exchanges one blob/1 frame at a caller-supplied relay time.
    ///
    /// # Errors
    ///
    /// Returns [`FrameExchangeError`] when durable storage cannot complete the command.
    pub fn exchange_blob_frame_at(
        &self,
        bytes: &[u8],
        now_seconds: u64,
    ) -> Result<Vec<u8>, FrameExchangeError> {
        self.exchange_blob_at(bytes, relay::Timestamp::from_secs(now_seconds))
            .map_err(|_| FrameExchangeError)
    }

    async fn exchange(&self, bytes: Vec<u8>) -> Result<Vec<u8>, ExchangeError> {
        let permit = Arc::clone(&self.commands)
            .try_acquire_owned()
            .map_err(|_| ExchangeError::Overloaded)?;
        let service = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            service.exchange_at(&bytes, relay_time())
        })
        .await
        .map_err(|_| ExchangeError::Internal)?
    }

    fn exchange_at(&self, bytes: &[u8], now: relay::Timestamp) -> Result<Vec<u8>, ExchangeError> {
        let decoded = match decode_request(bytes) {
            Ok(decoded) => decoded,
            Err(error) => return Ok(decode_error_response(bytes, &error)),
        };
        let request_id = decoded.frame().request_id();
        let request = decoded.frame().request();
        let command = request.command();
        let principal = request_principal(request);
        if verify_request(
            principal,
            decoded.authenticated_bytes(),
            decoded.frame().auth(),
        )
        .is_err()
        {
            return Ok(error_response(
                request_id,
                Some(command),
                Status::AuthInvalid,
            ));
        }
        if !self.queue_rate_limiter.admit(principal, now.as_secs()) {
            return Err(ExchangeError::Overloaded);
        }

        if let Err(status) = validate_queue_request(request) {
            return Ok(error_response(request_id, Some(command), status));
        }

        let mut durable = self.relay.lock().map_err(|_| ExchangeError::Storage)?;
        if let Some((stored_request, stored_response)) = durable
            .queue_replay(principal, request_id)
            .map_err(|_| ExchangeError::Storage)?
        {
            return if stored_request == bytes {
                Ok(stored_response)
            } else {
                Ok(error_response(
                    request_id,
                    Some(command),
                    Status::AuthReplay,
                ))
            };
        }
        match durable.queue_request_exchange(principal, request_id, bytes, request, now, |result| {
            encode_queue_outcome(request_id, command, result)
        }) {
            Ok(relay::QueueExchange::Respond(response)) => Ok(response),
            Ok(relay::QueueExchange::Conflict) => Ok(error_response(
                request_id,
                Some(command),
                Status::AuthReplay,
            )),
            Err(_) => Err(ExchangeError::Storage),
        }
    }

    async fn exchange_blob(&self, bytes: Vec<u8>) -> Result<Vec<u8>, ExchangeError> {
        let permit = Arc::clone(&self.commands)
            .try_acquire_owned()
            .map_err(|_| ExchangeError::Overloaded)?;
        let service = self.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            service.exchange_blob_at(&bytes, relay_time())
        })
        .await
        .map_err(|_| ExchangeError::Internal)?
    }

    fn exchange_blob_at(
        &self,
        bytes: &[u8],
        now: relay::Timestamp,
    ) -> Result<Vec<u8>, ExchangeError> {
        let decoded = match decode_blob_request(bytes) {
            Ok(decoded) => decoded,
            Err(error) => return Ok(blob_decode_error_response(bytes, &error)),
        };
        let request_id = decoded.frame.request_id;
        let request = &decoded.frame.request;
        let command = request.command();
        let capability = request.capability();
        if verify_blob_request(capability, decoded.authenticated_bytes, &decoded.frame.auth)
            .is_err()
        {
            return Ok(blob_error_response(
                request_id,
                Some(command),
                BlobStatus::AuthInvalid,
            ));
        }
        if !self.blob_rate_limiter.admit(capability, now.as_secs()) {
            return Err(ExchangeError::Overloaded);
        }
        let mut durable = self.relay.lock().map_err(|_| ExchangeError::Storage)?;
        if let Some((stored_request, stored_response)) = durable
            .blob_replay(capability, request_id)
            .map_err(|_| ExchangeError::Storage)?
        {
            return if stored_request == bytes {
                Ok(stored_response)
            } else {
                Ok(blob_error_response(
                    request_id,
                    Some(command),
                    BlobStatus::AuthReplay,
                ))
            };
        }
        match durable.blob_request_exchange(capability, request_id, bytes, request, now, |result| {
            encode_blob_outcome(request_id, command, result)
        }) {
            Ok(relay::BlobExchange::Respond(response)) => Ok(response),
            Ok(relay::BlobExchange::Conflict) => Ok(blob_error_response(
                request_id,
                Some(command),
                BlobStatus::AuthReplay,
            )),
            Err(_) => Err(ExchangeError::Storage),
        }
    }
}

/// Rejects a request whose numeric fields cannot be represented locally.
///
/// This check is a pure function of the request's own bytes: it never
/// depends on mutable stored state, so a byte-identical retry always
/// re-derives the same verdict and does not need a durable replay record.
fn validate_queue_request(request: &Request) -> Result<(), Status> {
    match request {
        Request::CreateQueue(create) => {
            usize::try_from(create.limits().max_messages()).map_err(|_| Status::LimitOutOfRange)?;
            usize::try_from(create.limits().max_message_bytes())
                .map_err(|_| Status::LimitOutOfRange)?;
            Ok(())
        }
        Request::Send(send) => {
            relay::Ttl::from_secs(send.ttl().as_secs()).ok_or(Status::LimitOutOfRange)?;
            Ok(())
        }
        Request::Fetch(_) | Request::Ack(_) | Request::DeleteQueue(_) => Ok(()),
    }
}

fn encode_queue_outcome(
    request_id: RequestId,
    command: Command,
    result: Result<ResponseBody, relay::RelayError>,
) -> Vec<u8> {
    let response = match result {
        Ok(body) => Response::Success(body),
        Err(error) => Response::Error(
            ErrorResponse::new(Some(command), relay_status(error))
                .expect("status is always an error"),
        ),
    };
    encode_response(&ResponseFrame::new(request_id, response))
}

fn encode_blob_outcome(
    request_id: RequestId,
    command: cofferwire_types::blob::BlobCommand,
    result: Result<BlobResponseBody, relay::BlobRelayError>,
) -> Vec<u8> {
    let response = match result {
        Ok(body) => BlobResponse {
            command: Some(command),
            status: BlobStatus::Ok,
            body: Some(body),
        },
        Err(error) => BlobResponse {
            command: Some(command),
            status: blob_status(error),
            body: None,
        },
    };
    encode_blob_response(&BlobResponseFrame {
        request_id,
        response,
    })
}

#[derive(Debug)]
enum ExchangeError {
    Overloaded,
    Storage,
    Internal,
}

/// A storage failure at the deterministic conformance exchange boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameExchangeError;

impl std::fmt::Display for FrameExchangeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("relay frame exchange failed")
    }
}

impl std::error::Error for FrameExchangeError {}

fn blob_status(error: relay::BlobRelayError) -> BlobStatus {
    match error {
        relay::BlobRelayError::NotFound => BlobStatus::NotFound,
        relay::BlobRelayError::Unauthorized => BlobStatus::Unauthorized,
        relay::BlobRelayError::IdConflict => BlobStatus::IdConflict,
        relay::BlobRelayError::LimitOutOfRange => BlobStatus::LimitOutOfRange,
        relay::BlobRelayError::ChunkConflict => BlobStatus::ChunkConflict,
        relay::BlobRelayError::Incomplete => BlobStatus::Incomplete,
        relay::BlobRelayError::IdentityMismatch => BlobStatus::IdentityMismatch,
        relay::BlobRelayError::Expired => BlobStatus::Expired,
    }
}

fn decode_error_response(bytes: &[u8], error: &DecodeError) -> Vec<u8> {
    let request_id = match error {
        DecodeError::UnsupportedVersion { request_id, .. } => *request_id,
        _ => request_id_from_prefix(bytes),
    };
    let status = match error {
        DecodeError::UnsupportedVersion { .. } => Status::UnsupportedVersion,
        DecodeError::FrameTooLarge { .. } => Status::FrameTooLarge,
        _ => Status::MalformedFrame,
    };
    error_response(request_id, None, status)
}

fn blob_decode_error_response(bytes: &[u8], error: &DecodeError) -> Vec<u8> {
    let request_id = match error {
        DecodeError::UnsupportedVersion { request_id, .. } => *request_id,
        _ => request_id_from_prefix(bytes),
    };
    let status = match error {
        DecodeError::UnsupportedVersion { .. } => BlobStatus::UnsupportedVersion,
        DecodeError::FrameTooLarge { .. } => BlobStatus::FrameTooLarge,
        DecodeError::InvalidValue {
            field: "blob command",
            ..
        } => BlobStatus::UnknownCommand,
        _ => BlobStatus::MalformedFrame,
    };
    blob_error_response(request_id, None, status)
}

fn blob_error_response(
    request_id: RequestId,
    command: Option<cofferwire_types::blob::BlobCommand>,
    status: BlobStatus,
) -> Vec<u8> {
    encode_blob_response(&BlobResponseFrame {
        request_id,
        response: BlobResponse {
            command,
            status,
            body: None,
        },
    })
}

fn request_id_from_prefix(bytes: &[u8]) -> RequestId {
    let mut id = [0_u8; 16];
    if let Some(source) = bytes.get(1..17) {
        id.copy_from_slice(source);
    }
    RequestId::from_bytes(id)
}

fn error_response(request_id: RequestId, command: Option<Command>, status: Status) -> Vec<u8> {
    let response = Response::Error(
        ErrorResponse::new(command, status).expect("callers pass only non-success status"),
    );
    encode_response(&ResponseFrame::new(request_id, response))
}

fn request_principal(request: &Request) -> Principal {
    match request {
        Request::CreateQueue(create) => create.sender(),
        Request::Send(send) => send.sender(),
        Request::Fetch(fetch) => fetch.recipient(),
        Request::Ack(ack) => ack.recipient(),
        Request::DeleteQueue(delete) => delete.recipient(),
    }
}

const fn relay_status(error: relay::RelayError) -> Status {
    match error {
        relay::RelayError::QueueNotFound => Status::QueueNotFound,
        relay::RelayError::Unauthorized => Status::Unauthorized,
        relay::RelayError::QueueIdConflict => Status::QueueIdConflict,
        relay::RelayError::MessageIdConflict => Status::MessageIdConflict,
        relay::RelayError::MessageTooLarge => Status::MessageTooLarge,
        relay::RelayError::QueueFull => Status::QueueFull,
        relay::RelayError::ExpiryOverflow => Status::ExpiryOverflow,
        relay::RelayError::LimitOutOfRange => Status::LimitOutOfRange,
        relay::RelayError::AckMismatch => Status::AckMismatch,
        relay::RelayError::NotDelivered => Status::NotDelivered,
    }
}

fn relay_time() -> relay::Timestamp {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    relay::Timestamp::from_secs(seconds)
}

#[cfg(test)]
mod tests;
