use std::fs;

use cofferwire_codec::{
    decode_response, encode_authenticated_request, encode_request, RequestFrame,
};
use cofferwire_crypto::RelaySigningKey;
use cofferwire_types::{
    CreateQueueRequest, QueueId, QueueLimits, Request, RequestId, Response, Status,
};
use cofferwired::RelayService;

fn signed_frame(key: &RelaySigningKey, request_id: RequestId, request: Request) -> Vec<u8> {
    let authenticated = encode_authenticated_request(request_id, &request);
    let auth = key.sign_request(&authenticated);
    encode_request(&RequestFrame::new(request_id, request, auth))
}

#[test]
fn queue_replays_survive_daemon_restart() {
    let path = std::env::temp_dir().join(format!(
        "cofferwire-queue-replay-{}.sqlite3",
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    let sender = RelaySigningKey::from_seed([2; 32]);
    let recipient = RelaySigningKey::from_seed([3; 32]);
    let queue = QueueId::from_bytes([1; 32]);
    let request_id = RequestId::from_bytes([9; 16]);
    let create = Request::CreateQueue(CreateQueueRequest::new(
        queue,
        sender.principal(),
        recipient.principal(),
        QueueLimits::new(4, 1024).expect("valid limits"),
    ));
    let create_frame = signed_frame(&sender, request_id, create);

    let create_response = {
        let service = RelayService::open(&path).expect("relay opens");
        let response = service
            .exchange_frame_at(&create_frame, 1_000)
            .expect("create exchange succeeds");
        assert!(decode_response(&response)
            .expect("response decodes")
            .response()
            .status()
            .is_ok());
        response
    };

    // Restart: a fresh service over the same database must replay the stored
    // response byte-for-byte instead of re-executing CreateQueue against
    // whatever state happens to exist after reopening.
    let service = RelayService::open(&path).expect("relay reopens");
    let retry_response = service
        .exchange_frame_at(&create_frame, 1_001)
        .expect("retry exchange succeeds");
    assert_eq!(retry_response, create_response);

    // Reusing the recorded request identifier with different request bytes
    // is rejected after restart, not silently re-executed or dropped.
    let conflicting = Request::CreateQueue(CreateQueueRequest::new(
        queue,
        sender.principal(),
        recipient.principal(),
        QueueLimits::new(5, 1024).expect("valid limits"),
    ));
    let conflicting_frame = signed_frame(&sender, request_id, conflicting);
    let conflict_response = service
        .exchange_frame_at(&conflicting_frame, 1_002)
        .expect("conflicting exchange resolves");
    assert!(matches!(
        decode_response(&conflict_response)
            .expect("response decodes")
            .response(),
        Response::Error(error) if error.status() == Status::AuthReplay
    ));

    drop(service);
    let _ = fs::remove_file(&path);
}
