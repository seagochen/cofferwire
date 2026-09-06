//! Deterministic Cofferwire v1 frame encoding and strict decoding.
//!
//! This crate intentionally implements only the canonical CBOR subset used by
//! Cofferwire. Decode work is bounded by [`cofferwire_types::MAX_FRAME_BYTES`],
//! and byte-string lengths are checked before any owned protocol value is made.

#![forbid(unsafe_code)]

pub mod blob;
mod cbor;
mod error;

use cbor::{encode_array, encode_bytes, encode_unsigned, Decoder};
use cofferwire_types::{
    AckRequest, Auth, Command, CreateQueueOutcome, CreateQueueRequest, DeleteQueueRequest,
    Delivery, ErrorResponse, FetchRequest, MessageId, Payload, Principal, QueueId, QueueLimits,
    Request, RequestId, Response, ResponseBody, SendOutcome, SendRequest, Status, Timestamp, Ttl,
    MAX_AUTH_BYTES, MAX_FRAME_BYTES, MAX_MESSAGE_BYTES,
};
pub use error::DecodeError;

const PREAMBLE_BYTES: usize = 17;
const VERSION: u8 = 1;

/// An owned v1 request frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestFrame {
    request_id: RequestId,
    request: Request,
    auth: Auth,
}

impl RequestFrame {
    /// Constructs a v1 request frame.
    #[must_use]
    pub const fn new(request_id: RequestId, request: Request, auth: Auth) -> Self {
        Self {
            request_id,
            request,
            auth,
        }
    }

    /// Returns the response-correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the command and body.
    #[must_use]
    pub const fn request(&self) -> &Request {
        &self.request
    }

    /// Returns the opaque authentication field.
    #[must_use]
    pub const fn auth(&self) -> &Auth {
        &self.auth
    }
}

/// A decoded request plus the exact bytes its authentication proof binds.
#[derive(Debug, Eq, PartialEq)]
pub struct DecodedRequest<'a> {
    frame: RequestFrame,
    authenticated_bytes: &'a [u8],
}

impl<'a> DecodedRequest<'a> {
    /// Returns the decoded semantic frame.
    #[must_use]
    pub const fn frame(&self) -> &RequestFrame {
        &self.frame
    }

    /// Returns the exact received `preamble || payload`, excluding `auth`.
    #[must_use]
    pub const fn authenticated_bytes(&self) -> &'a [u8] {
        self.authenticated_bytes
    }

    /// Consumes the wrapper and returns the owned semantic frame.
    #[must_use]
    pub fn into_frame(self) -> RequestFrame {
        self.frame
    }
}

/// An owned v1 response frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseFrame {
    request_id: RequestId,
    response: Response,
}

impl ResponseFrame {
    /// Constructs a v1 response frame.
    #[must_use]
    pub const fn new(request_id: RequestId, response: Response) -> Self {
        Self {
            request_id,
            response,
        }
    }

    /// Returns the echoed response-correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the response value.
    #[must_use]
    pub const fn response(&self) -> &Response {
        &self.response
    }
}

/// Encodes the exact bytes authenticated by a v1 request proof.
#[must_use]
pub fn encode_authenticated_request(request_id: RequestId, request: &Request) -> Vec<u8> {
    let mut output = Vec::with_capacity(256);
    encode_preamble(&mut output, request_id);
    encode_request_payload(&mut output, request);
    output
}

/// Deterministically encodes one complete v1 request frame.
#[must_use]
pub fn encode_request(frame: &RequestFrame) -> Vec<u8> {
    let mut output = encode_authenticated_request(frame.request_id, &frame.request);
    encode_bytes(&mut output, frame.auth.as_bytes());
    debug_assert!(output.len() <= MAX_FRAME_BYTES);
    output
}

/// Deterministically encodes one complete v1 response frame.
#[must_use]
pub fn encode_response(frame: &ResponseFrame) -> Vec<u8> {
    let mut output = Vec::with_capacity(128);
    encode_preamble(&mut output, frame.request_id);
    encode_response_payload(&mut output, &frame.response);
    debug_assert!(output.len() <= MAX_FRAME_BYTES);
    output
}

/// Strictly decodes one complete v1 request frame.
///
/// # Errors
///
/// Rejects oversized, unsupported, truncated, non-canonical, structurally
/// invalid and trailing input.
pub fn decode_request(bytes: &[u8]) -> Result<DecodedRequest<'_>, DecodeError> {
    let request_id = decode_preamble(bytes)?;
    let mut decoder = Decoder::new(bytes, PREAMBLE_BYTES);
    decoder.array("request payload", 3)?;
    expect_value(&mut decoder, "request direction", 0)?;
    let command = decode_command(&mut decoder)?;
    let request = decode_request_body(&mut decoder, command)?;
    let authenticated_end = decoder.offset();
    let auth = Auth::new(decoder.bytes("auth", MAX_AUTH_BYTES)?.to_vec())?;
    finish(&decoder, bytes)?;
    Ok(DecodedRequest {
        frame: RequestFrame::new(request_id, request, auth),
        authenticated_bytes: &bytes[..authenticated_end],
    })
}

/// Strictly decodes one complete v1 response frame.
///
/// # Errors
///
/// Returns [`DecodeError`] for every non-canonical or invalid frame.
pub fn decode_response(bytes: &[u8]) -> Result<ResponseFrame, DecodeError> {
    let request_id = decode_preamble(bytes)?;
    let mut decoder = Decoder::new(bytes, PREAMBLE_BYTES);
    decoder.array("response payload", 4)?;
    expect_value(&mut decoder, "response direction", 1)?;
    let command_code = decoder.unsigned("response command")?;
    let status = decode_status(&mut decoder)?;
    let response = if status.is_ok() {
        let command = command_from_u64(command_code)?;
        Response::Success(decode_response_body(&mut decoder, command)?)
    } else {
        decoder.array("error response body", 0)?;
        let command = if command_code == 0 {
            None
        } else {
            Some(command_from_u64(command_code)?)
        };
        Response::Error(ErrorResponse::new(command, status)?)
    };
    finish(&decoder, bytes)?;
    Ok(ResponseFrame::new(request_id, response))
}

fn decode_preamble(bytes: &[u8]) -> Result<RequestId, DecodeError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(DecodeError::FrameTooLarge {
            actual: bytes.len(),
        });
    }
    let preamble = bytes.get(..PREAMBLE_BYTES).ok_or(DecodeError::Truncated {
        offset: bytes.len(),
    })?;
    let version = preamble[0];
    if version == 0 {
        return Err(DecodeError::ReservedVersion);
    }
    let mut id = [0_u8; 16];
    id.copy_from_slice(&preamble[1..]);
    let request_id = RequestId::from_bytes(id);
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion {
            version,
            request_id,
        });
    }
    Ok(request_id)
}

fn finish(decoder: &Decoder<'_>, bytes: &[u8]) -> Result<(), DecodeError> {
    if decoder.offset() == bytes.len() {
        Ok(())
    } else {
        Err(DecodeError::TrailingBytes {
            offset: decoder.offset(),
        })
    }
}

fn expect_value(
    decoder: &mut Decoder<'_>,
    field: &'static str,
    expected: u64,
) -> Result<(), DecodeError> {
    let value = decoder.unsigned(field)?;
    if value == expected {
        Ok(())
    } else {
        Err(DecodeError::InvalidValue { field, value })
    }
}

fn command_from_u64(value: u64) -> Result<Command, DecodeError> {
    let value = u8::try_from(value).map_err(|_| DecodeError::InvalidValue {
        field: "command",
        value,
    })?;
    Command::try_from(value).map_err(Into::into)
}

fn decode_command(decoder: &mut Decoder<'_>) -> Result<Command, DecodeError> {
    command_from_u64(decoder.unsigned("command")?)
}

fn decode_status(decoder: &mut Decoder<'_>) -> Result<Status, DecodeError> {
    let value = decoder.unsigned("status")?;
    let byte = u8::try_from(value).map_err(|_| DecodeError::InvalidValue {
        field: "status",
        value,
    })?;
    Status::try_from(byte).map_err(Into::into)
}

fn fixed_bytes<const N: usize>(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<[u8; N], DecodeError> {
    let bytes = decoder.bytes(field, N)?;
    if bytes.len() != N {
        return Err(DecodeError::WrongByteStringLength {
            field,
            expected: N,
            actual: bytes.len() as u64,
        });
    }
    let mut output = [0_u8; N];
    output.copy_from_slice(bytes);
    Ok(output)
}

fn queue_id(decoder: &mut Decoder<'_>) -> Result<QueueId, DecodeError> {
    Ok(QueueId::from_bytes(fixed_bytes(decoder, "queue-id")?))
}

fn principal(decoder: &mut Decoder<'_>) -> Result<Principal, DecodeError> {
    Ok(Principal::from_bytes(fixed_bytes(decoder, "principal")?))
}

fn message_id(decoder: &mut Decoder<'_>) -> Result<MessageId, DecodeError> {
    Ok(MessageId::from_bytes(fixed_bytes(decoder, "message-id")?))
}

fn decode_request_body(
    decoder: &mut Decoder<'_>,
    command: Command,
) -> Result<Request, DecodeError> {
    match command {
        Command::CreateQueue => {
            decoder.array("CREATE_QUEUE request body", 5)?;
            let queue = queue_id(decoder)?;
            let sender = principal(decoder)?;
            let recipient = principal(decoder)?;
            let max_messages = decoder.unsigned("max-messages")?;
            let max_message_bytes = decoder.unsigned("max-message-bytes")?;
            let limits = QueueLimits::new(max_messages, max_message_bytes)?;
            Ok(Request::CreateQueue(CreateQueueRequest::new(
                queue, sender, recipient, limits,
            )))
        }
        Command::Send => {
            decoder.array("SEND request body", 5)?;
            let queue = queue_id(decoder)?;
            let sender = principal(decoder)?;
            let message = message_id(decoder)?;
            let payload = Payload::new(decoder.bytes("payload", MAX_MESSAGE_BYTES)?.to_vec())?;
            let ttl = Ttl::from_secs(decoder.unsigned("ttl")?);
            Ok(Request::Send(SendRequest::new(
                queue, sender, message, payload, ttl,
            )))
        }
        Command::Fetch => {
            decoder.array("FETCH request body", 2)?;
            Ok(Request::Fetch(FetchRequest::new(
                queue_id(decoder)?,
                principal(decoder)?,
            )))
        }
        Command::Ack => {
            decoder.array("ACK request body", 3)?;
            Ok(Request::Ack(AckRequest::new(
                queue_id(decoder)?,
                principal(decoder)?,
                message_id(decoder)?,
            )))
        }
        Command::DeleteQueue => {
            decoder.array("DELETE_QUEUE request body", 2)?;
            Ok(Request::DeleteQueue(DeleteQueueRequest::new(
                queue_id(decoder)?,
                principal(decoder)?,
            )))
        }
    }
}

fn decode_response_body(
    decoder: &mut Decoder<'_>,
    command: Command,
) -> Result<ResponseBody, DecodeError> {
    match command {
        Command::CreateQueue => {
            decoder.array("CREATE_QUEUE response body", 1)?;
            let value = small_u8(decoder, "CREATE_QUEUE outcome")?;
            Ok(ResponseBody::CreateQueue(CreateQueueOutcome::try_from(
                value,
            )?))
        }
        Command::Send => {
            decoder.array("SEND response body", 1)?;
            let value = small_u8(decoder, "SEND outcome")?;
            Ok(ResponseBody::Send(SendOutcome::try_from(value)?))
        }
        Command::Fetch => match decoder.array_length()? {
            1 => {
                expect_value(decoder, "FETCH availability", 0)?;
                Ok(ResponseBody::Fetch(None))
            }
            4 => {
                expect_value(decoder, "FETCH availability", 1)?;
                let message = message_id(decoder)?;
                let payload = Payload::new(decoder.bytes("payload", MAX_MESSAGE_BYTES)?.to_vec())?;
                let expires_at = Timestamp::from_secs(decoder.unsigned("expires-at")?);
                Ok(ResponseBody::Fetch(Some(Delivery::new(
                    message, payload, expires_at,
                ))))
            }
            actual => Err(DecodeError::InvalidValue {
                field: "FETCH response body length",
                value: actual,
            }),
        },
        Command::Ack => {
            decoder.array("ACK response body", 0)?;
            Ok(ResponseBody::Ack)
        }
        Command::DeleteQueue => {
            decoder.array("DELETE_QUEUE response body", 0)?;
            Ok(ResponseBody::DeleteQueue)
        }
    }
}

fn small_u8(decoder: &mut Decoder<'_>, field: &'static str) -> Result<u8, DecodeError> {
    let value = decoder.unsigned(field)?;
    u8::try_from(value).map_err(|_| DecodeError::InvalidValue { field, value })
}

fn encode_preamble(output: &mut Vec<u8>, request_id: RequestId) {
    output.push(VERSION);
    output.extend_from_slice(request_id.as_bytes());
}

fn encode_request_payload(output: &mut Vec<u8>, request: &Request) {
    encode_array(output, 3);
    encode_unsigned(output, 0);
    encode_unsigned(output, u64::from(request.command().as_u8()));
    match request {
        Request::CreateQueue(value) => {
            encode_array(output, 5);
            encode_id(output, value.queue_id().as_bytes());
            encode_id(output, value.sender().as_bytes());
            encode_id(output, value.recipient().as_bytes());
            encode_unsigned(output, value.limits().max_messages());
            encode_unsigned(output, value.limits().max_message_bytes());
        }
        Request::Send(value) => {
            encode_array(output, 5);
            encode_id(output, value.queue_id().as_bytes());
            encode_id(output, value.sender().as_bytes());
            encode_id(output, value.message_id().as_bytes());
            encode_bytes(output, value.payload().as_bytes());
            encode_unsigned(output, value.ttl().as_secs());
        }
        Request::Fetch(value) => {
            encode_array(output, 2);
            encode_id(output, value.queue_id().as_bytes());
            encode_id(output, value.recipient().as_bytes());
        }
        Request::Ack(value) => {
            encode_array(output, 3);
            encode_id(output, value.queue_id().as_bytes());
            encode_id(output, value.recipient().as_bytes());
            encode_id(output, value.message_id().as_bytes());
        }
        Request::DeleteQueue(value) => {
            encode_array(output, 2);
            encode_id(output, value.queue_id().as_bytes());
            encode_id(output, value.recipient().as_bytes());
        }
    }
}

fn encode_response_payload(output: &mut Vec<u8>, response: &Response) {
    encode_array(output, 4);
    encode_unsigned(output, 1);
    encode_unsigned(
        output,
        response
            .command()
            .map_or(0, |command| u64::from(command.as_u8())),
    );
    encode_unsigned(output, u64::from(response.status().as_u8()));
    match response {
        Response::Error(_) => encode_array(output, 0),
        Response::Success(body) => encode_success_body(output, body),
    }
}

fn encode_success_body(output: &mut Vec<u8>, body: &ResponseBody) {
    match body {
        ResponseBody::CreateQueue(outcome) => {
            encode_array(output, 1);
            encode_unsigned(output, u64::from(outcome.as_u8()));
        }
        ResponseBody::Send(outcome) => {
            encode_array(output, 1);
            encode_unsigned(output, u64::from(outcome.as_u8()));
        }
        ResponseBody::Fetch(None) => {
            encode_array(output, 1);
            encode_unsigned(output, 0);
        }
        ResponseBody::Fetch(Some(delivery)) => {
            encode_array(output, 4);
            encode_unsigned(output, 1);
            encode_id(output, delivery.message_id().as_bytes());
            encode_bytes(output, delivery.payload().as_bytes());
            encode_unsigned(output, delivery.expires_at().as_secs());
        }
        ResponseBody::Ack | ResponseBody::DeleteQueue => encode_array(output, 0),
    }
}

fn encode_id(output: &mut Vec<u8>, bytes: &[u8; 32]) {
    encode_bytes(output, bytes);
}
