//! Transport-independent protocol types for Cofferwire's v1 wire contract.
//!
//! Every type here validates its invariants at construction, so a value
//! that exists in this crate's public API can always be encoded onto the
//! wire defined by `spec/05-wire-format.md`. This crate performs no CBOR
//! encoding or decoding itself and does not depend on `SQLite`, HTTP,
//! WebSocket or any relay storage engine; it exists so a codec, client and
//! relay daemon share one definition of "valid" instead of each defining
//! their own validation, defaults and error semantics for the same wire
//! fields.

#![forbid(unsafe_code)]

mod auth;
mod body;
mod command;
mod error;
mod ids;
mod limits;
mod payload;
mod status;
mod time;
mod version;

pub use auth::Auth;
pub use body::{
    AckRequest, CreateQueueOutcome, CreateQueueRequest, DeleteQueueRequest, Delivery,
    ErrorResponse, FetchRequest, Request, Response, ResponseBody, SendOutcome, SendRequest,
};
pub use command::Command;
pub use error::TypeError;
pub use ids::{MessageId, Principal, QueueId, RequestId};
pub use limits::QueueLimits;
pub use payload::Payload;
pub use status::Status;
pub use time::{Timestamp, Ttl};
pub use version::Version;

/// Maximum encoded size of one frame in either direction, in bytes
/// (`CW-WIRE-020`).
pub const MAX_FRAME_BYTES: usize = 65_536;

/// Maximum content length of a request's `auth` byte string, in bytes
/// (`CW-WIRE-014`).
pub const MAX_AUTH_BYTES: usize = 1_024;

/// Maximum opaque `SEND`/`FETCH` payload size, in bytes (`CW-WIRE-029`).
///
/// This is the protocol-wide bound derived from [`MAX_FRAME_BYTES`] with
/// a maximum-width `ttl` and a maximum-size `auth`; an individual queue's
/// configured `max-message-bytes` (`CW-WIRE-030`) MAY be smaller but MUST
/// NOT exceed it.
pub const MAX_MESSAGE_BYTES: usize = 64_374;
