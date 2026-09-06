//! Cross-checks `conformance/evidence/operational-limits-v1.json` against the
//! real `pub const` values in the wire-type and reference-daemon crates
//! (`CW-SECURITY-002`), so the published catalog cannot silently drift from
//! the code that actually enforces it.

use cofferwire_types::blob::{MAX_BLOB_FRAME_BYTES, MAX_CHUNK_BYTES, MAX_PADDED_BYTES};
use cofferwire_types::{MAX_AUTH_BYTES, MAX_FRAME_BYTES, MAX_MESSAGE_BYTES};
use cofferwired::{
    BLOB_RATE_LIMIT_MAX_REQUESTS, BLOB_RATE_LIMIT_WINDOW_SECS, MAX_CONCURRENT_COMMANDS,
    MAX_CONNECTIONS, MAX_WEBSOCKET_CONNECTIONS, QUEUE_RATE_LIMIT_MAX_REQUESTS,
    QUEUE_RATE_LIMIT_WINDOW_SECS, RATE_LIMIT_MAX_TRACKED_KEYS, REQUEST_TIMEOUT,
    WEBSOCKET_IDLE_TIMEOUT,
};

#[test]
fn published_operational_limits_match_the_implementation() {
    let document = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/evidence/operational-limits-v1.json"
    ))
    .expect("operational-limits-v1.json exists");
    let value: serde_json::Value =
        serde_json::from_str(&document).expect("operational-limits-v1.json is valid JSON");

    let at = |pointer: &str| {
        value
            .pointer(pointer)
            .unwrap_or_else(|| panic!("missing {pointer} in operational-limits-v1.json"))
            .as_u64()
            .unwrap_or_else(|| panic!("{pointer} is not an integer"))
    };

    assert_eq!(at("/queue_v1/max_frame_bytes"), MAX_FRAME_BYTES as u64);
    assert_eq!(at("/queue_v1/max_auth_bytes"), MAX_AUTH_BYTES as u64);
    assert_eq!(at("/queue_v1/max_message_bytes"), MAX_MESSAGE_BYTES as u64);

    assert_eq!(
        at("/blob_v1/max_blob_frame_bytes"),
        MAX_BLOB_FRAME_BYTES as u64
    );
    assert_eq!(at("/blob_v1/max_chunk_bytes"), MAX_CHUNK_BYTES as u64);
    assert_eq!(at("/blob_v1/max_padded_bytes"), MAX_PADDED_BYTES);

    assert_eq!(
        at("/reference_daemon/max_connections"),
        MAX_CONNECTIONS as u64
    );
    assert_eq!(
        at("/reference_daemon/max_websocket_connections"),
        MAX_WEBSOCKET_CONNECTIONS as u64
    );
    assert_eq!(
        at("/reference_daemon/max_concurrent_commands"),
        MAX_CONCURRENT_COMMANDS as u64
    );
    assert_eq!(
        at("/reference_daemon/request_timeout_secs"),
        REQUEST_TIMEOUT.as_secs()
    );
    assert_eq!(
        at("/reference_daemon/websocket_idle_timeout_secs"),
        WEBSOCKET_IDLE_TIMEOUT.as_secs()
    );
    assert_eq!(
        at("/reference_daemon/queue_rate_limit_window_secs"),
        QUEUE_RATE_LIMIT_WINDOW_SECS
    );
    assert_eq!(
        at("/reference_daemon/queue_rate_limit_max_requests"),
        QUEUE_RATE_LIMIT_MAX_REQUESTS as u64
    );
    assert_eq!(
        at("/reference_daemon/blob_rate_limit_window_secs"),
        BLOB_RATE_LIMIT_WINDOW_SECS
    );
    assert_eq!(
        at("/reference_daemon/blob_rate_limit_max_requests"),
        BLOB_RATE_LIMIT_MAX_REQUESTS as u64
    );
    assert_eq!(
        at("/reference_daemon/rate_limit_max_tracked_keys"),
        RATE_LIMIT_MAX_TRACKED_KEYS as u64
    );
}
