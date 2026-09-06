use cddl::validate_cbor_from_slice;
use chacha20poly1305::{aead::Aead, aead::Payload, ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTOR_JSON: &str = include_str!("../../../vectors/blob-v1.json");
const BLOB_CDDL: &str = include_str!("../../../spec/07-blobs.cddl");
const AUTH_CDDL: &str = "request-auth = bstr .size 68";
const KEY_INFO: &[u8] = b"cofferwire blob key v1\0";
const CHUNK_DOMAIN: &[u8] = b"cofferwire blob chunk v1\0";
const IDENTITY_DOMAIN: &[u8] = b"cofferwire blob identity v1\0";

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(value[key].as_str().expect("hex vector string")).expect("valid vector hex")
}

fn u32_parameter(vector: &Value, key: &str) -> u32 {
    u32::try_from(
        vector["parameters"][key]
            .as_u64()
            .expect("integer parameter"),
    )
    .expect("u32 parameter")
}

fn repeated_identifier(value: u8) -> Vec<u8> {
    let mut encoded = vec![0x58, 0x20];
    encoded.extend([value; 32]);
    encoded
}

fn assert_capability_vectors(positive: &Value) {
    for role in ["upload", "download", "renew", "delete"] {
        let capability = &positive["capabilities"][role];
        let seed: [u8; 32] = bytes(capability, "seed_hex")
            .try_into()
            .expect("32-byte capability seed");
        assert_eq!(
            SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
            bytes(capability, "public_key_hex").as_slice()
        );
    }
}

fn assert_stream_vector(positive: &Value, stream: &[u8]) {
    let plaintext = bytes(positive, "plaintext_hex");
    let mut expected = u64::try_from(plaintext.len())
        .expect("plaintext length")
        .to_be_bytes()
        .to_vec();
    expected.extend(&plaintext);
    expected.extend(bytes(positive, "padding_hex"));
    assert_eq!(stream, expected);
}

#[test]
fn blob_cddl_discriminates_commands_and_auth_size() {
    let mut get_manifest = vec![0x83, 0x00, 0x04, 0x82];
    get_manifest.extend(repeated_identifier(0x11));
    get_manifest.extend(repeated_identifier(0x22));
    assert!(validate_cbor_from_slice(BLOB_CDDL, &get_manifest, None).is_ok());

    let wrong_body = vec![0x83, 0x00, 0x04, 0x80];
    assert!(validate_cbor_from_slice(BLOB_CDDL, &wrong_body, None).is_err());

    let mut exact_auth = vec![0x58, 0x44];
    exact_auth.extend([0_u8; 68]);
    let mut short_auth = vec![0x58, 0x43];
    short_auth.extend([0_u8; 67]);
    assert!(validate_cbor_from_slice(AUTH_CDDL, &exact_auth, None).is_ok());
    assert!(validate_cbor_from_slice(AUTH_CDDL, &short_auth, None).is_err());
}

#[test]
fn blob_positive_vector_reproduces_content_and_identity() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).expect("valid blob vector JSON");
    let positive = &vector["positive"];
    let profile = u16::try_from(u32_parameter(&vector, "profile")).expect("profile u16");
    let suite = u16::try_from(u32_parameter(&vector, "content_suite")).expect("suite u16");
    let padded_size = vector["parameters"]["padded_size"]
        .as_u64()
        .expect("padded size");
    let chunk_size = u32_parameter(&vector, "chunk_size");
    let chunk_count = u32_parameter(&vector, "chunk_count");
    let object_key = bytes(positive, "object_key_hex");
    let salt = bytes(positive, "object_salt_hex");
    let stream = bytes(positive, "padded_stream_hex");
    let plaintext = bytes(positive, "plaintext_hex");
    assert_stream_vector(positive, &stream);

    let mut aead_key = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), &object_key)
        .expand(KEY_INFO, &mut aead_key)
        .expect("32-byte HKDF output");
    assert_eq!(aead_key.as_slice(), bytes(positive, "aead_key_hex"));

    let cipher = ChaCha20Poly1305::new((&aead_key).into());
    let expected_chunks = positive["ciphertext_chunks_hex"]
        .as_array()
        .expect("ciphertext chunk array");
    let expected_digests = positive["chunk_digests_hex"]
        .as_array()
        .expect("digest array");
    let mut digests = Vec::new();
    let mut recovered_stream = Vec::new();

    for index in 0..chunk_count {
        let mut nonce = [0_u8; 12];
        nonce[4..].copy_from_slice(&u64::from(index).to_be_bytes());
        let mut aad = CHUNK_DOMAIN.to_vec();
        aad.extend(profile.to_be_bytes());
        aad.extend(suite.to_be_bytes());
        aad.extend(&salt);
        aad.extend(padded_size.to_be_bytes());
        aad.extend(chunk_size.to_be_bytes());
        aad.extend(chunk_count.to_be_bytes());
        aad.extend(index.to_be_bytes());
        let start = usize::try_from(index * chunk_size).expect("chunk start");
        let end = start + usize::try_from(chunk_size).expect("chunk size");
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &stream[start..end],
                    aad: &aad,
                },
            )
            .expect("vector encryption");
        assert_eq!(
            ciphertext,
            hex::decode(
                expected_chunks[usize::try_from(index).expect("index")]
                    .as_str()
                    .expect("chunk hex")
            )
            .expect("valid chunk hex")
        );
        recovered_stream.extend(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .expect("vector decryption"),
        );
        digests.extend(Sha256::digest(&ciphertext));
    }
    assert_eq!(recovered_stream, stream);
    let declared_length = usize::try_from(u64::from_be_bytes(
        recovered_stream[..8].try_into().expect("length prefix"),
    ))
    .expect("plaintext length fits usize");
    assert_eq!(&recovered_stream[8..8 + declared_length], plaintext);

    for (actual, expected) in digests.chunks_exact(32).zip(expected_digests) {
        assert_eq!(
            actual,
            hex::decode(expected.as_str().expect("digest hex")).expect("valid digest hex")
        );
    }

    let mut manifest = b"CWB1".to_vec();
    manifest.extend(profile.to_be_bytes());
    manifest.extend(suite.to_be_bytes());
    manifest.extend(&salt);
    manifest.extend(padded_size.to_be_bytes());
    manifest.extend(chunk_size.to_be_bytes());
    manifest.extend(chunk_count.to_be_bytes());
    manifest.extend(&digests);
    assert_eq!(manifest, bytes(positive, "manifest_hex"));

    let mut identity_input = IDENTITY_DOMAIN.to_vec();
    identity_input.extend(&manifest);
    assert_eq!(
        Sha256::digest(identity_input).as_slice(),
        bytes(positive, "blob_id_hex")
    );

    assert_capability_vectors(positive);
}

#[test]
fn blob_vector_has_stable_negative_ids() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).expect("valid blob vector JSON");
    let negative = vector["negative"].as_array().expect("negative vectors");
    assert_eq!(negative.len(), 8);
    for (offset, case) in negative.iter().enumerate() {
        assert_eq!(
            case["id"].as_str().expect("vector ID"),
            format!("CW-BLOB-VECTOR-NEG-{:03}", offset + 1)
        );
        assert!(case["operation"].as_str().expect("operation").len() > 20);
    }
}
