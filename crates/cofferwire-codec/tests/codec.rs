use cofferwire_codec::{
    decode_request, decode_response, encode_authenticated_request, encode_request, encode_response,
    DecodeError, RequestFrame, ResponseFrame,
};
use cofferwire_types::{
    AckRequest, Auth, CreateQueueOutcome, CreateQueueRequest, DeleteQueueRequest, Delivery,
    ErrorResponse, FetchRequest, MessageId, Payload, Principal, QueueId, QueueLimits, Request,
    RequestId, Response, ResponseBody, SendOutcome, SendRequest, Status, Timestamp, Ttl,
    MAX_AUTH_BYTES, MAX_FRAME_BYTES, MAX_MESSAGE_BYTES,
};

const REQUEST_ID: RequestId = RequestId::from_bytes([0xaa; 16]);
const QUEUE: QueueId = QueueId::from_bytes([0x11; 32]);
const SENDER: Principal = Principal::from_bytes([0x22; 32]);
const RECIPIENT: Principal = Principal::from_bytes([0x44; 32]);
const MESSAGE: MessageId = MessageId::from_bytes([0x33; 32]);

fn payload(bytes: &[u8]) -> Payload {
    Payload::new(bytes.to_vec()).expect("test payload is bounded")
}

fn requests() -> Vec<Request> {
    vec![
        Request::CreateQueue(CreateQueueRequest::new(
            QUEUE,
            SENDER,
            RECIPIENT,
            QueueLimits::new(10, 4096).expect("valid limits"),
        )),
        Request::Send(SendRequest::new(
            QUEUE,
            SENDER,
            MESSAGE,
            payload(b"hi"),
            Ttl::from_secs(60),
        )),
        Request::Fetch(FetchRequest::new(QUEUE, RECIPIENT)),
        Request::Ack(AckRequest::new(QUEUE, RECIPIENT, MESSAGE)),
        Request::DeleteQueue(DeleteQueueRequest::new(QUEUE, RECIPIENT)),
    ]
}

fn responses() -> Vec<Response> {
    vec![
        Response::Success(ResponseBody::CreateQueue(CreateQueueOutcome::Created)),
        Response::Success(ResponseBody::CreateQueue(CreateQueueOutcome::AlreadyExists)),
        Response::Success(ResponseBody::Send(SendOutcome::Accepted)),
        Response::Success(ResponseBody::Send(SendOutcome::Duplicate)),
        Response::Success(ResponseBody::Fetch(None)),
        Response::Success(ResponseBody::Fetch(Some(Delivery::new(
            MESSAGE,
            payload(b"ciphertext"),
            Timestamp::from_secs(u64::MAX),
        )))),
        Response::Success(ResponseBody::Ack),
        Response::Success(ResponseBody::DeleteQueue),
        Response::Error(
            ErrorResponse::new(Some(cofferwire_types::Command::Send), Status::QueueFull)
                .expect("error status"),
        ),
        Response::Error(
            ErrorResponse::new(None, Status::UnsupportedVersion).expect("error status"),
        ),
    ]
}

#[test]
fn every_v1_request_round_trips_byte_for_byte() {
    for request in requests() {
        let frame = RequestFrame::new(
            REQUEST_ID,
            request,
            Auth::new(vec![0x55; 64]).expect("bounded auth"),
        );
        let encoded = encode_request(&frame);
        let decoded = decode_request(&encoded).expect("encoded request decodes");
        assert_eq!(decoded.frame(), &frame);
        assert_eq!(
            decoded.authenticated_bytes(),
            encode_authenticated_request(REQUEST_ID, frame.request())
        );
        assert_eq!(encode_request(decoded.frame()), encoded);
    }
}

#[test]
fn every_v1_response_round_trips_byte_for_byte() {
    for response in responses() {
        let frame = ResponseFrame::new(REQUEST_ID, response);
        let encoded = encode_response(&frame);
        let decoded = decode_response(&encoded).expect("encoded response decodes");
        assert_eq!(decoded, frame);
        assert_eq!(encode_response(&decoded), encoded);
    }
}

#[test]
fn worked_send_vector_is_exact() {
    let request = Request::Send(SendRequest::new(
        QUEUE,
        SENDER,
        MESSAGE,
        payload(b"hi"),
        Ttl::from_secs(60),
    ));
    let encoded = encode_request(&RequestFrame::new(REQUEST_ID, request, Auth::empty()));
    assert_eq!(to_hex(&encoded), vector_hex("send_request_empty_auth"));
}

#[test]
fn rejects_noncanonical_forbidden_truncated_trailing_and_oversized_input() {
    let canonical = encode_request(&RequestFrame::new(
        REQUEST_ID,
        Request::Fetch(FetchRequest::new(QUEUE, RECIPIENT)),
        Auth::empty(),
    ));

    let mut noncanonical_direction = canonical.clone();
    noncanonical_direction.splice(18..19, [0x18, 0x00]);
    assert!(matches!(
        decode_request(&noncanonical_direction),
        Err(DecodeError::NonCanonicalArgument { .. })
    ));

    let mut map_payload = canonical.clone();
    map_payload[17] = 0xa3;
    assert!(matches!(
        decode_request(&map_payload),
        Err(DecodeError::UnexpectedType { .. })
    ));

    let mut indefinite_payload = canonical.clone();
    indefinite_payload[17] = 0x9f;
    assert!(matches!(
        decode_request(&indefinite_payload),
        Err(DecodeError::UnexpectedType { .. })
    ));

    let mut duplicate_body_field = canonical.clone();
    duplicate_body_field[20] = 0x83;
    let auth_offset = duplicate_body_field.len() - 1;
    let mut duplicate_recipient = vec![0x58, 0x20];
    duplicate_recipient.extend([0x44; 32]);
    duplicate_body_field.splice(auth_offset..auth_offset, duplicate_recipient);
    assert!(matches!(
        decode_request(&duplicate_body_field),
        Err(DecodeError::WrongArrayLength { .. })
    ));

    for length in 0..canonical.len() {
        assert!(
            decode_request(&canonical[..length]).is_err(),
            "accepted prefix {length}"
        );
    }

    let mut trailing = canonical;
    trailing.push(0);
    assert!(matches!(
        decode_request(&trailing),
        Err(DecodeError::TrailingBytes { .. })
    ));

    let oversized = vec![0; MAX_FRAME_BYTES + 1];
    assert_eq!(
        decode_request(&oversized),
        Err(DecodeError::FrameTooLarge {
            actual: MAX_FRAME_BYTES + 1
        })
    );
}

#[test]
fn maximum_send_frame_fits_exactly_and_declared_bombs_are_rejected_before_copy() {
    let request = Request::Send(SendRequest::new(
        QUEUE,
        SENDER,
        MESSAGE,
        Payload::new(vec![0; MAX_MESSAGE_BYTES]).expect("maximum payload"),
        Ttl::from_secs(u64::MAX),
    ));
    let frame = RequestFrame::new(
        REQUEST_ID,
        request,
        Auth::new(vec![0; MAX_AUTH_BYTES]).expect("maximum auth"),
    );
    let encoded = encode_request(&frame);
    assert_eq!(encoded.len(), MAX_FRAME_BYTES);
    assert_eq!(
        decode_request(&encoded).expect("maximum frame").frame(),
        &frame
    );

    let mut bomb = vec![1];
    bomb.extend([0; 16]);
    bomb.extend([0x83, 0x00, 0x02, 0x85]);
    for value in [0x11, 0x22, 0x33] {
        bomb.extend([0x58, 0x20]);
        bomb.extend([value; 32]);
    }
    bomb.extend([0x5a, 0xff, 0xff, 0xff, 0xff]);
    assert!(matches!(
        decode_request(&bomb),
        Err(DecodeError::ByteStringTooLarge {
            field: "payload",
            ..
        })
    ));
}

#[test]
fn unsupported_version_returns_readable_preamble_without_parsing_payload() {
    let mut bytes = vec![2];
    bytes.extend([0xaa; 16]);
    bytes.extend([0xff; 10]);
    assert_eq!(
        decode_request(&bytes),
        Err(DecodeError::UnsupportedVersion {
            version: 2,
            request_id: REQUEST_ID,
        })
    );
}

fn vector_hex(name: &str) -> String {
    let vectors = include_str!("../../../vectors/codec-v1.json");
    let marker = format!("\"name\": \"{name}\"");
    let entry = vectors.split(&marker).nth(1).expect("named public vector");
    let value = entry
        .split("\"frame_hex\": \"")
        .nth(1)
        .expect("frame_hex field")
        .split('"')
        .next()
        .expect("quoted frame_hex value");
    value.to_owned()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
