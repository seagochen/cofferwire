#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cofferwire_codec::blob::decode_blob_request(data);
    let _ = cofferwire_codec::blob::decode_blob_response(data);
});
