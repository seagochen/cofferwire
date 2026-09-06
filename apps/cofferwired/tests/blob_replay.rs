use std::fs;

use cofferwire_codec::blob::{
    decode_blob_response, encode_blob_authenticated_request, encode_blob_request,
};
use cofferwire_crypto::blob::{seal_blob, BlobSigningKey};
use cofferwire_types::blob::{
    BlobCapabilities, BlobRequest, BlobRequestFrame, BlobStatus, UploadId,
};
use cofferwire_types::RequestId;
use cofferwired::RelayService;
use rand_core::OsRng;

fn signed_frame(serial: u128, key: &BlobSigningKey, request: BlobRequest) -> Vec<u8> {
    let request_id = RequestId::from_bytes(serial.to_be_bytes());
    let authenticated = encode_blob_authenticated_request(request_id, &request);
    let auth = key.sign_request(&authenticated);
    encode_blob_request(&BlobRequestFrame {
        request_id,
        request,
        auth,
    })
}

fn exchange(service: &RelayService, frame: &[u8], now: u64) -> Vec<u8> {
    service
        .exchange_blob_frame_at(frame, now)
        .expect("storage succeeds")
}

fn status(response: &[u8]) -> BlobStatus {
    decode_blob_response(response)
        .expect("response decodes")
        .response
        .status
}

#[test]
#[allow(clippy::too_many_lines)]
fn blob_replays_survive_daemon_restart() {
    let path = std::env::temp_dir().join(format!(
        "cofferwire-blob-replay-{}.sqlite3",
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    let encrypted = seal_blob(b"durable replay boundary", 32, &mut OsRng).expect("encrypts");
    let upload = BlobSigningKey::generate(&mut OsRng);
    let download = BlobSigningKey::generate(&mut OsRng);
    let renew = BlobSigningKey::generate(&mut OsRng);
    let delete = BlobSigningKey::generate(&mut OsRng);
    let upload_id = UploadId::from_bytes([42; 32]);
    let caps = BlobCapabilities {
        upload: upload.capability(),
        download: download.capability(),
        renew: renew.capability(),
        delete: delete.capability(),
    };

    let begin = signed_frame(
        1,
        &upload,
        BlobRequest::BeginUpload {
            upload_id,
            capabilities: caps,
            manifest: encrypted.manifest.clone(),
            ttl: 100,
        },
    );
    let commit = signed_frame(
        2,
        &upload,
        BlobRequest::Commit {
            upload_id,
            upload_cap: upload.capability(),
            blob_id: encrypted.blob_id,
        },
    );
    let renew_request = signed_frame(
        3,
        &renew,
        BlobRequest::Renew {
            blob_id: encrypted.blob_id,
            renew_cap: renew.capability(),
            ttl: 500,
        },
    );
    let delete_request = signed_frame(
        4,
        &delete,
        BlobRequest::Delete {
            blob_id: encrypted.blob_id,
            delete_cap: delete.capability(),
        },
    );

    let (begin_response, commit_response, renew_response, delete_response) = {
        let service = RelayService::open(&path).expect("relay opens");
        let begin_response = exchange(&service, &begin, 1);
        assert_eq!(status(&begin_response), BlobStatus::Ok);
        for (index, chunk) in encrypted.chunks.iter().enumerate() {
            let put = signed_frame(
                10 + index as u128,
                &upload,
                BlobRequest::PutChunk {
                    upload_id,
                    upload_cap: upload.capability(),
                    index: u32::try_from(index).expect("test chunk index fits u32"),
                    ciphertext: chunk.clone(),
                },
            );
            assert_eq!(status(&exchange(&service, &put, 1)), BlobStatus::Ok);
        }
        let commit_response = exchange(&service, &commit, 1);
        assert_eq!(status(&commit_response), BlobStatus::Ok);
        let renew_response = exchange(&service, &renew_request, 1);
        assert_eq!(status(&renew_response), BlobStatus::Ok);
        let delete_response = exchange(&service, &delete_request, 1);
        assert_eq!(status(&delete_response), BlobStatus::Ok);
        (
            begin_response,
            commit_response,
            renew_response,
            delete_response,
        )
    };

    // Restart: a fresh service over the same database must replay the stored
    // responses byte-for-byte instead of re-executing against current state.
    let service = RelayService::open(&path).expect("relay reopens");
    assert_eq!(exchange(&service, &begin, 1), begin_response);
    assert_eq!(exchange(&service, &commit, 1), commit_response);
    assert_eq!(exchange(&service, &renew_request, 1), renew_response);
    // The object is deleted; without the durable replay record this retry
    // would drift to NOT_FOUND after the lost original response.
    let delete_retry = exchange(&service, &delete_request, 1);
    assert_eq!(delete_retry, delete_response);
    assert_eq!(status(&delete_retry), BlobStatus::Ok);

    // The underlying state really is gone for new request identifiers.
    let fresh_delete = signed_frame(
        200,
        &delete,
        BlobRequest::Delete {
            blob_id: encrypted.blob_id,
            delete_cap: delete.capability(),
        },
    );
    assert_eq!(
        status(&exchange(&service, &fresh_delete, 1)),
        BlobStatus::NotFound
    );

    // Reusing a recorded request identifier with different request bytes is
    // rejected after restart.
    let conflicting = signed_frame(
        1,
        &upload,
        BlobRequest::BeginUpload {
            upload_id,
            capabilities: caps,
            manifest: encrypted.manifest.clone(),
            ttl: 200,
        },
    );
    assert_eq!(
        status(&exchange(&service, &conflicting, 1)),
        BlobStatus::AuthReplay
    );

    drop(service);
    let _ = fs::remove_file(&path);
}
