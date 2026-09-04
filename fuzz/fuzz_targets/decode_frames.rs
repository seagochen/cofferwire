#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cofferwire_codec::decode_request(data);
    let _ = cofferwire_codec::decode_response(data);
});
