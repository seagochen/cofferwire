#![no_main]

use cofferwire_types::Request;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(decoded) = cofferwire_codec::decode_request(data) {
        let principal = match decoded.frame().request() {
            Request::CreateQueue(value) => value.sender(),
            Request::Send(value) => value.sender(),
            Request::Fetch(value) => value.recipient(),
            Request::Ack(value) => value.recipient(),
            Request::DeleteQueue(value) => value.recipient(),
        };
        let _ = cofferwire_crypto::verify_request(
            principal,
            decoded.authenticated_bytes(),
            decoded.frame().auth(),
        );
    }
    if let Ok(decoded) = cofferwire_codec::blob::decode_blob_request(data) {
        let _ = cofferwire_crypto::blob::verify_blob_request(
            decoded.frame.request.capability(),
            decoded.authenticated_bytes,
            &decoded.frame.auth,
        );
    }
});
