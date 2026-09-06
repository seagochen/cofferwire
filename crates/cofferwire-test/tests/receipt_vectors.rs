use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTOR_JSON: &str = include_str!("../../../vectors/receipts-v1.json");
const RECEIPT_DOMAIN: &[u8] = b"cofferwire receipt v1\0";
const MAGIC: [u8; 4] = *b"CWR1";
const RECEIPT_LEN: usize = 237;
const SIGNATURE_BYTES: usize = 64;

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(value[key].as_str().expect("hex vector string")).expect("valid vector hex")
}

/// Independently reconstructs `docs/spec/08-receipts.md`'s signed structure from
/// raw primitives, without calling into `cofferwire_crypto::receipt`.
#[test]
fn receipt_positive_vector_reproduces_signed_structure() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).expect("valid receipt vector JSON");
    let seed: [u8; 32] = bytes(&vector, "confirming_device_seed_hex")
        .try_into()
        .expect("32-byte seed");
    let signing_key = SigningKey::from_bytes(&seed);
    let principal = bytes(&vector, "confirming_device_principal_hex");
    assert_eq!(
        signing_key.verifying_key().to_bytes().as_slice(),
        principal.as_slice()
    );

    let queue_id = bytes(&vector, "confirmed_queue_id_hex");
    let sender = bytes(&vector, "confirmed_sender_hex");
    let message_id = bytes(&vector, "confirmed_message_id_hex");
    let plaintext = bytes(&vector, "applied_plaintext_hex");
    let digest = Sha256::digest(&plaintext);
    assert_eq!(
        digest.as_slice(),
        bytes(&vector, "applied_content_digest_hex")
    );
    let applied_at = vector["applied_at_secs"].as_u64().expect("applied_at_secs");

    let mut signed = Vec::new();
    signed.extend_from_slice(&MAGIC);
    signed.push(1); // receipt.applied
    signed.extend_from_slice(&queue_id);
    signed.extend_from_slice(&sender);
    signed.extend_from_slice(&principal); // confirmed recipient == confirming device
    signed.extend_from_slice(&message_id);
    signed.extend_from_slice(&digest);
    signed.extend_from_slice(&applied_at.to_be_bytes());
    assert_eq!(signed.len(), RECEIPT_LEN - SIGNATURE_BYTES);

    let mut to_sign = RECEIPT_DOMAIN.to_vec();
    to_sign.extend_from_slice(&signed);
    let signature = signing_key.sign(&to_sign);

    let mut receipt = signed;
    receipt.extend_from_slice(&signature.to_bytes());
    assert_eq!(receipt, bytes(&vector, "receipt_hex"));

    let verifying_key =
        VerifyingKey::from_bytes(&principal.try_into().expect("32 bytes")).expect("valid key");
    verifying_key
        .verify(&to_sign, &signature)
        .expect("signature verifies (CW-RECEIPT-005)");
}

/// Minimal re-implementation of `verify_applied_receipt`'s structural and
/// signature checks, used only to exercise the tampered vectors below
/// independently of `cofferwire_crypto::receipt`.
fn verifies(expected_signer: &VerifyingKey, candidate: &[u8]) -> bool {
    if candidate.len() != RECEIPT_LEN {
        return false;
    }
    if candidate[..MAGIC.len()] != MAGIC || candidate[MAGIC.len()] != 1 {
        return false;
    }
    let signed = &candidate[..RECEIPT_LEN - SIGNATURE_BYTES];
    let Ok(signature_bytes) =
        <[u8; SIGNATURE_BYTES]>::try_from(&candidate[RECEIPT_LEN - SIGNATURE_BYTES..])
    else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_bytes);
    let mut to_sign = RECEIPT_DOMAIN.to_vec();
    to_sign.extend_from_slice(signed);
    expected_signer.verify(&to_sign, &signature).is_ok()
}

#[test]
fn receipt_vector_byte_tamper_and_structural_negatives_are_rejected() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).expect("valid receipt vector JSON");
    let principal: [u8; 32] = bytes(&vector, "confirming_device_principal_hex")
        .try_into()
        .expect("32 bytes");
    let verifying_key = VerifyingKey::from_bytes(&principal).expect("valid key");
    let receipt = bytes(&vector, "receipt_hex");

    assert!(
        verifies(&verifying_key, &receipt),
        "vector's own receipt must verify before tampering"
    );

    for offset in 0..receipt.len() {
        let mut tampered = receipt.clone();
        tampered[offset] ^= 0x01;
        assert!(
            !verifies(&verifying_key, &tampered),
            "byte {offset} tamper unexpectedly verified"
        );
    }

    let mut truncated = receipt.clone();
    truncated.pop();
    assert!(!verifies(&verifying_key, &truncated));

    let mut oversized = receipt.clone();
    oversized.push(0);
    assert!(!verifies(&verifying_key, &oversized));

    let mut wrong_type = receipt.clone();
    wrong_type[4] = 0xFF;
    assert!(!verifies(&verifying_key, &wrong_type));

    // Wrong confirming device: the same bytes must not verify under an
    // unrelated key (CW-RECEIPT-005).
    let other_key = SigningKey::from_bytes(&[0x99; 32]);
    assert!(!verifies(&other_key.verifying_key(), &receipt));

    let negative = vector["negative"].as_array().expect("negative vectors");
    assert_eq!(negative.len(), 6);
    for case in negative {
        assert!(case["operation"].as_str().expect("operation").len() > 20);
    }
}
