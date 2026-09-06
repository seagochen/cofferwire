use std::fs;

use cofferwire_codec::blob::{
    decode_blob_response, encode_blob_authenticated_request, encode_blob_request,
};
use cofferwire_crypto::blob::{open_blob, seal_blob, BlobSigningKey};
use cofferwire_types::blob::{
    BlobCapabilities, BlobRequest, BlobRequestFrame, BlobResponseBody, BlobStatus, UploadId,
};
use cofferwire_types::RequestId;
use cofferwired::RelayService;
use rand_core::OsRng;

fn exchange(
    service: &RelayService,
    serial: u128,
    key: &BlobSigningKey,
    request: BlobRequest,
    now: u64,
) -> cofferwire_types::blob::BlobResponse {
    let request_id = RequestId::from_bytes(serial.to_be_bytes());
    let authenticated = encode_blob_authenticated_request(request_id, &request);
    let auth = key.sign_request(&authenticated);
    let frame = encode_blob_request(&BlobRequestFrame {
        request_id,
        request,
        auth,
    });
    decode_blob_response(
        &service
            .exchange_blob_frame_at(&frame, now)
            .expect("storage succeeds"),
    )
    .expect("response decodes")
    .response
}

#[test]
#[allow(clippy::too_many_lines)]
fn partial_tampered_cross_role_expiry_and_delete_fail_closed() {
    let path = std::env::temp_dir().join(format!(
        "cofferwire-blob-contract-{}.sqlite3",
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    let service = RelayService::open(&path).expect("relay opens");
    let encrypted = seal_blob(b"contract negative paths", 32, &mut OsRng).expect("encrypts");
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

    assert_eq!(
        exchange(
            &service,
            1,
            &upload,
            BlobRequest::BeginUpload {
                upload_id,
                capabilities: caps,
                manifest: encrypted.manifest.clone(),
                ttl: 100
            },
            1
        )
        .status,
        BlobStatus::Ok
    );
    assert_eq!(
        exchange(
            &service,
            2,
            &upload,
            BlobRequest::PutChunk {
                upload_id,
                upload_cap: upload.capability(),
                index: 0,
                ciphertext: encrypted.chunks[0].clone()
            },
            1
        )
        .status,
        BlobStatus::Ok
    );
    assert_eq!(
        exchange(
            &service,
            3,
            &download,
            BlobRequest::GetManifest {
                blob_id: encrypted.blob_id,
                download_cap: download.capability()
            },
            1
        )
        .status,
        BlobStatus::NotFound
    );
    assert_eq!(
        exchange(
            &service,
            4,
            &upload,
            BlobRequest::Commit {
                upload_id,
                upload_cap: upload.capability(),
                blob_id: encrypted.blob_id
            },
            1
        )
        .status,
        BlobStatus::Incomplete
    );
    let mut tampered = encrypted.chunks[1].clone();
    tampered[0] ^= 1;
    assert_eq!(
        exchange(
            &service,
            5,
            &upload,
            BlobRequest::PutChunk {
                upload_id,
                upload_cap: upload.capability(),
                index: 1,
                ciphertext: tampered
            },
            1
        )
        .status,
        BlobStatus::ChunkConflict
    );
    for (index, chunk) in encrypted.chunks.iter().enumerate().skip(1) {
        assert_eq!(
            exchange(
                &service,
                10 + index as u128,
                &upload,
                BlobRequest::PutChunk {
                    upload_id,
                    upload_cap: upload.capability(),
                    index: u32::try_from(index).expect("test chunk index fits u32"),
                    ciphertext: chunk.clone()
                },
                1
            )
            .status,
            BlobStatus::Ok
        );
    }
    assert_eq!(
        exchange(
            &service,
            100,
            &upload,
            BlobRequest::Commit {
                upload_id,
                upload_cap: upload.capability(),
                blob_id: cofferwire_types::blob::BlobId::from_bytes([0; 32])
            },
            1
        )
        .status,
        BlobStatus::IdentityMismatch
    );
    assert_eq!(
        exchange(
            &service,
            101,
            &upload,
            BlobRequest::Commit {
                upload_id,
                upload_cap: upload.capability(),
                blob_id: encrypted.blob_id
            },
            1
        )
        .status,
        BlobStatus::Ok
    );
    assert_eq!(
        exchange(
            &service,
            102,
            &upload,
            BlobRequest::GetManifest {
                blob_id: encrypted.blob_id,
                download_cap: upload.capability()
            },
            1
        )
        .status,
        BlobStatus::Unauthorized
    );
    let renewed = exchange(
        &service,
        103,
        &renew,
        BlobRequest::Renew {
            blob_id: encrypted.blob_id,
            renew_cap: renew.capability(),
            ttl: 1,
        },
        2,
    );
    assert!(matches!(renewed.body, Some(BlobResponseBody::Renew(101))));

    let mut reversed = encrypted.chunks.clone();
    reversed.reverse();
    assert!(open_blob(
        &encrypted.key,
        encrypted.blob_id,
        &encrypted.manifest,
        &reversed
    )
    .is_err());
    assert_eq!(
        exchange(
            &service,
            104,
            &delete,
            BlobRequest::Delete {
                blob_id: encrypted.blob_id,
                delete_cap: delete.capability()
            },
            2
        )
        .status,
        BlobStatus::Ok
    );
    assert_eq!(
        exchange(
            &service,
            105,
            &download,
            BlobRequest::GetManifest {
                blob_id: encrypted.blob_id,
                download_cap: download.capability()
            },
            2
        )
        .status,
        BlobStatus::NotFound
    );
    let _ = fs::remove_file(path);
}
