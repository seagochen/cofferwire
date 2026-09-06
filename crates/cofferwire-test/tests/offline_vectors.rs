//! Vector coverage for `cofferwire-offline/1` (`spec/13-offline-bundles.md`).
//!
//! The HPKE construction sealing a bundle's payload is unchanged from
//! ordinary application messages and is already independently vector-tested
//! by `vectors/crypto-v1.json`'s hpke vectors; this file instead
//! independently re-derives the envelope header and inner plaintext framing
//! this profile adds, using `cofferwire_crypto::open_message` only for the
//! already-covered decryption step.

use cofferwire_crypto::{open_message, EncryptionPublicKey, EncryptionSecretKey, MessageContext};
use cofferwire_types::{MessageId, Payload, Principal, QueueId};
use serde_json::Value;

const VECTOR_JSON: &str = include_str!("../../../vectors/offline-v1.json");
const MAGIC: [u8; 4] = *b"CWOB";
const ENVELOPE_HEADER_LEN: usize = 4 + 1 + 32 + 32;
const MAX_RELAY_HINTS: usize = 8;
const MAX_RELAY_HINT_BYTES: usize = 256;

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(value[key].as_str().expect("hex vector string")).expect("valid vector hex")
}

fn array32(value: &Value, key: &str) -> [u8; 32] {
    bytes(value, key).try_into().expect("32-byte field")
}

/// Independently parses the envelope's cleartext header and decrypts its
/// payload, without going through `cofferwire_client::offline::open_bundle`.
fn open_envelope(
    envelope: &[u8],
    importer_key: &EncryptionSecretKey,
    exporter_principal: Principal,
    exporter_encryption_public: EncryptionPublicKey,
) -> Vec<u8> {
    assert!(envelope.len() >= ENVELOPE_HEADER_LEN);
    assert_eq!(&envelope[..4], &MAGIC);
    assert_eq!(envelope[4], 1, "version");
    let queue_id = QueueId::from_bytes(envelope[5..37].try_into().expect("32 bytes"));
    let bundle_id = MessageId::from_bytes(envelope[37..69].try_into().expect("32 bytes"));
    let sealed = Payload::new(envelope[69..].to_vec()).expect("payload within bounds");
    let context = MessageContext {
        queue_id,
        sender: exporter_principal,
        recipient: exporter_principal, // self-directed recovery in this vector
        message_id: bundle_id,
    };
    open_message(importer_key, exporter_encryption_public, context, &sealed)
        .expect("vector envelope decrypts")
}

/// The inner plaintext's fields, independently decoded byte offset by byte
/// offset per `spec/13-offline-bundles.md`'s wire format.
struct DecodedFields {
    bundle_type: u8,
    role: u8,
    peer_principal: [u8; 32],
    peer_key: [u8; 32],
    created_at: u64,
    hints: Vec<Vec<u8>>,
}

fn decode_plaintext(plaintext: &[u8]) -> DecodedFields {
    let bundle_type = plaintext[0];
    let role = plaintext[1];
    let peer_principal: [u8; 32] = plaintext[2..34].try_into().expect("32 bytes");
    let peer_key: [u8; 32] = plaintext[34..66].try_into().expect("32 bytes");
    let created_at = u64::from_be_bytes(plaintext[66..74].try_into().expect("8 bytes"));
    let mut offset = 74;
    if bundle_type == 2 {
        offset += 64; // own-signing-seed || own-encryption-ikm, recovery only
    }
    let hint_count = usize::from(plaintext[offset]);
    offset += 1;
    assert!(hint_count <= MAX_RELAY_HINTS);
    let mut hints = Vec::with_capacity(hint_count);
    for _ in 0..hint_count {
        let length = usize::from(u16::from_be_bytes(
            plaintext[offset..offset + 2].try_into().expect("2 bytes"),
        ));
        offset += 2;
        assert!(length <= MAX_RELAY_HINT_BYTES);
        hints.push(plaintext[offset..offset + length].to_vec());
        offset += length;
    }
    assert_eq!(offset, plaintext.len(), "no trailing bytes");
    DecodedFields {
        bundle_type,
        role,
        peer_principal,
        peer_key,
        created_at,
        hints,
    }
}

#[test]
fn offline_positive_vector_reproduces_envelope_and_plaintext_framing() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).expect("valid offline vector JSON");
    let exporter_ikm: [u8; 32] = bytes(&vector, "exporter_encryption_ikm_hex")
        .try_into()
        .expect("32 bytes");
    let importer_ikm: [u8; 32] = bytes(&vector, "importer_encryption_ikm_hex")
        .try_into()
        .expect("32 bytes");
    let exporter_key = EncryptionSecretKey::derive(&exporter_ikm);
    let importer_key = EncryptionSecretKey::derive(&importer_ikm);
    let exporter_principal = Principal::from_bytes(array32(&vector, "exporter_principal_hex"));

    let envelope = bytes(&vector, "envelope_hex");
    assert_eq!(
        &envelope[5..37],
        array32(&vector, "queue_id_hex").as_slice()
    );
    assert_eq!(
        &envelope[37..69],
        array32(&vector, "bundle_id_hex").as_slice()
    );

    let plaintext = open_envelope(
        &envelope,
        &importer_key,
        exporter_principal,
        exporter_key.public_key(),
    );
    let decoded = decode_plaintext(&plaintext);

    assert_eq!(decoded.bundle_type, 2, "recovery");
    assert_eq!(decoded.role, 1, "recipient");
    assert_eq!(
        decoded.peer_principal,
        exporter_principal.as_bytes().to_owned()
    );
    assert_eq!(
        decoded.peer_key,
        array32(&vector, "peer_encryption_public_hex")
    );
    assert_eq!(
        decoded.created_at,
        vector["created_at_secs"].as_u64().expect("created_at_secs")
    );
    let expected_hints: Vec<Vec<u8>> = vector["relay_hints"]
        .as_array()
        .expect("relay hints")
        .iter()
        .map(|hint| hint.as_str().expect("hint string").as_bytes().to_vec())
        .collect();
    assert_eq!(decoded.hints, expected_hints);
}

#[test]
fn offline_vector_byte_tamper_and_structural_negatives_are_rejected() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).expect("valid offline vector JSON");
    let exporter_ikm: [u8; 32] = bytes(&vector, "exporter_encryption_ikm_hex")
        .try_into()
        .expect("32 bytes");
    let importer_ikm: [u8; 32] = bytes(&vector, "importer_encryption_ikm_hex")
        .try_into()
        .expect("32 bytes");
    let peer_ikm: [u8; 32] = bytes(&vector, "peer_encryption_ikm_hex")
        .try_into()
        .expect("32 bytes");
    let exporter_key = EncryptionSecretKey::derive(&exporter_ikm);
    let importer_key = EncryptionSecretKey::derive(&importer_ikm);
    let wrong_key = EncryptionSecretKey::derive(&peer_ikm);
    let exporter_principal = Principal::from_bytes(array32(&vector, "exporter_principal_hex"));
    let envelope = bytes(&vector, "envelope_hex");

    let attempt = |candidate: &[u8], key: &EncryptionSecretKey, expected: EncryptionPublicKey| {
        if candidate.len() < ENVELOPE_HEADER_LEN || candidate[..4] != MAGIC || candidate[4] != 1 {
            return false;
        }
        let queue_id = QueueId::from_bytes(candidate[5..37].try_into().unwrap_or([0; 32]));
        let bundle_id = MessageId::from_bytes(candidate[37..69].try_into().unwrap_or([0; 32]));
        let Ok(sealed) = Payload::new(candidate[69..].to_vec()) else {
            return false;
        };
        let context = MessageContext {
            queue_id,
            sender: exporter_principal,
            recipient: exporter_principal,
            message_id: bundle_id,
        };
        open_message(key, expected, context, &sealed).is_ok()
    };

    assert!(
        attempt(&envelope, &importer_key, exporter_key.public_key()),
        "vector's own envelope must open before tampering"
    );

    for offset in 0..envelope.len() {
        let mut tampered = envelope.clone();
        tampered[offset] ^= 0x01;
        assert!(
            !attempt(&tampered, &importer_key, exporter_key.public_key()),
            "byte {offset} tamper unexpectedly opened"
        );
    }

    assert!(
        !attempt(&envelope, &wrong_key, exporter_key.public_key()),
        "wrong recipient key must not open"
    );
    assert!(
        !attempt(&envelope, &importer_key, wrong_key.public_key()),
        "wrong expected exporter key must not open"
    );

    let mut truncated = envelope.clone();
    truncated.pop();
    assert!(!attempt(
        &truncated,
        &importer_key,
        exporter_key.public_key()
    ));

    let mut wrong_version = envelope.clone();
    wrong_version[4] = 0xFF;
    assert!(!attempt(
        &wrong_version,
        &importer_key,
        exporter_key.public_key()
    ));

    let negative = vector["negative"].as_array().expect("negative vectors");
    assert_eq!(negative.len(), 6);
    for case in negative {
        assert!(case["operation"].as_str().expect("operation").len() > 20);
    }
}
