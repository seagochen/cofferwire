use cddl::validate_cbor_from_slice;

const WIRE_CDDL: &str = include_str!("../../../docs/spec/05-wire-format.cddl");
const MAX_AUTH_BYTES: usize = 1024;
const MAX_FRAME_BYTES: usize = 65_536;
const MAX_MESSAGE_BYTES: usize = 64_374;
const PREAMBLE_BYTES: usize = 17;

fn repeated_identifier(value: u8) -> Vec<u8> {
    let mut encoded = vec![0x58, 0x20];
    encoded.extend([value; 32]);
    encoded
}

fn send_payload(message_bytes: usize) -> Vec<u8> {
    assert!(message_bytes <= u16::MAX.into());

    let mut encoded = vec![0x83, 0x00, 0x02, 0x85];
    encoded.extend(repeated_identifier(0x11));
    encoded.extend(repeated_identifier(0x22));
    encoded.extend(repeated_identifier(0x33));
    encoded.extend([
        0x59,
        u8::try_from(message_bytes >> 8).expect("high length byte"),
        u8::try_from(message_bytes & 0xff).expect("low length byte"),
    ]);
    encoded.resize(encoded.len() + message_bytes, 0);
    encoded.extend([0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    encoded
}

fn assert_validation(name: &str, encoded: &[u8], expected: bool) {
    let result = validate_cbor_from_slice(WIRE_CDDL, encoded, None);
    assert_eq!(
        result.is_ok(),
        expected,
        "{name}: expected accepted={expected}, got {result:?}"
    );
}

#[test]
fn cddl_accepts_complete_request_and_response_payloads() {
    let mut send = vec![0x83, 0x00, 0x02, 0x85];
    send.extend(repeated_identifier(0x11));
    send.extend(repeated_identifier(0x22));
    send.extend(repeated_identifier(0x33));
    send.extend([0x42, 0x68, 0x69, 0x18, 0x3c]);

    for (name, encoded) in [
        ("SEND request", send),
        (
            "SEND success response",
            vec![0x84, 0x01, 0x02, 0x00, 0x81, 0x00],
        ),
        ("SEND error response", vec![0x84, 0x01, 0x02, 0x0e, 0x80]),
    ] {
        assert_validation(name, &encoded, true);
    }
}

#[test]
fn cddl_rejects_discriminator_body_and_data_model_errors() {
    for (name, encoded) in [
        ("command/body mismatch", vec![0x83, 0x00, 0x02, 0x80]),
        (
            "wrong SEND response body",
            vec![0x84, 0x01, 0x02, 0x00, 0x80],
        ),
        (
            "invalid SEND outcome",
            vec![0x84, 0x01, 0x02, 0x00, 0x81, 0x02],
        ),
        (
            "nonempty error body",
            vec![0x84, 0x01, 0x02, 0x0e, 0x81, 0x00],
        ),
        ("unknown command", vec![0x83, 0x00, 0x06, 0x80]),
        ("map body", vec![0x83, 0x00, 0x02, 0xa0]),
    ] {
        assert_validation(name, &encoded, false);
    }
}

#[test]
fn cddl_and_encoded_frame_agree_on_message_boundary() {
    let maximum = send_payload(MAX_MESSAGE_BYTES);
    let oversized = send_payload(MAX_MESSAGE_BYTES + 1);

    assert_validation("maximum message payload", &maximum, true);
    assert_validation("maximum plus one", &oversized, false);

    let encoded_max_auth_bytes = 3 + MAX_AUTH_BYTES;
    assert_eq!(
        PREAMBLE_BYTES + maximum.len() + encoded_max_auth_bytes,
        MAX_FRAME_BYTES
    );
    assert_eq!(
        PREAMBLE_BYTES + oversized.len() + encoded_max_auth_bytes,
        MAX_FRAME_BYTES + 1
    );
}

#[test]
fn request_auth_obeys_the_cddl_size_bound() {
    const AUTH_CDDL: &str = "request-auth = bstr .size (0..1024)";

    let mut maximum = vec![0x59, 0x04, 0x00];
    maximum.resize(3 + MAX_AUTH_BYTES, 0);
    let mut oversized = vec![0x59, 0x04, 0x01];
    oversized.resize(3 + MAX_AUTH_BYTES + 1, 0);

    for (name, encoded, expected) in [
        ("empty auth", vec![0x40], true),
        ("maximum auth", maximum, true),
        ("oversized auth", oversized, false),
    ] {
        let result = validate_cbor_from_slice(AUTH_CDDL, &encoded, None);
        assert_eq!(
            result.is_ok(),
            expected,
            "{name}: expected accepted={expected}, got {result:?}"
        );
    }
}
