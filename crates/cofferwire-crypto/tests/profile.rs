use cofferwire_crypto::{
    open_message, seal_message, verify_request, CryptoError, EncryptionSecretKey, MessageContext,
    RelaySigningKey, MAX_PLAINTEXT_BYTES,
};
use cofferwire_types::{Auth, MessageId, Payload, Principal, QueueId};
use rand_core::{CryptoRng, Error, RngCore};

const CONTEXT: MessageContext = MessageContext {
    queue_id: QueueId::from_bytes([0x11; 32]),
    sender: Principal::from_bytes([0x22; 32]),
    recipient: Principal::from_bytes([0x33; 32]),
    message_id: MessageId::from_bytes([0x44; 32]),
};

struct VectorRng {
    next: u8,
}

impl RngCore for VectorRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for byte in destination {
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for VectorRng {}

#[test]
fn relay_auth_vector_verifies_and_every_bound_byte_is_authenticated() {
    let key = RelaySigningKey::from_seed([7; 32]);
    let vector_message = vector("relay_authenticated_bytes_hex");
    let message = hex_decode(&vector_message);
    let proof = key.sign_request(&message);
    assert_eq!(to_hex(proof.as_bytes()), vector("relay_auth_hex"));
    verify_request(key.principal(), &message, &proof).expect("valid proof");

    for index in 0..message.len() {
        let mut changed = message.clone();
        changed[index] ^= 1;
        assert_eq!(
            verify_request(key.principal(), &changed, &proof),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    let mut downgraded = proof.as_bytes().to_vec();
    downgraded[1] = 2;
    assert_eq!(
        verify_request(
            key.principal(),
            &message,
            &Auth::new(downgraded).expect("bounded proof")
        ),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn hpke_vector_round_trips_and_matches_public_bytes() {
    let sender = EncryptionSecretKey::derive(&[0x55; 32]);
    let recipient = EncryptionSecretKey::derive(&[0x66; 32]);
    let mut rng = VectorRng { next: 0 };
    let ciphertext = seal_message(
        &sender,
        recipient.public_key(),
        CONTEXT,
        b"family update",
        &mut rng,
    )
    .expect("encryption succeeds");
    assert_eq!(to_hex(ciphertext.as_bytes()), vector("hpke_payload_hex"));
    assert_eq!(
        open_message(&recipient, sender.public_key(), CONTEXT, &ciphertext)
            .expect("decryption succeeds"),
        b"family update"
    );
}

#[test]
fn tampering_profile_context_key_or_ciphertext_is_rejected() {
    let sender = EncryptionSecretKey::derive(&[0x55; 32]);
    let recipient = EncryptionSecretKey::derive(&[0x66; 32]);
    let outsider = EncryptionSecretKey::derive(&[0x77; 32]);
    let mut rng = VectorRng { next: 0 };
    let ciphertext = seal_message(
        &sender,
        recipient.public_key(),
        CONTEXT,
        b"family update",
        &mut rng,
    )
    .expect("encryption succeeds");

    for index in 0..ciphertext.len() {
        let mut changed = ciphertext.as_bytes().to_vec();
        changed[index] ^= 1;
        let changed = Payload::new(changed).expect("still bounded");
        assert!(open_message(&recipient, sender.public_key(), CONTEXT, &changed).is_err());
    }

    for context in [
        MessageContext {
            queue_id: QueueId::from_bytes([9; 32]),
            ..CONTEXT
        },
        MessageContext {
            sender: Principal::from_bytes([9; 32]),
            ..CONTEXT
        },
        MessageContext {
            recipient: Principal::from_bytes([9; 32]),
            ..CONTEXT
        },
        MessageContext {
            message_id: MessageId::from_bytes([9; 32]),
            ..CONTEXT
        },
    ] {
        assert_eq!(
            open_message(&recipient, sender.public_key(), context, &ciphertext),
            Err(CryptoError::DecryptionFailed)
        );
    }
    assert_eq!(
        open_message(&outsider, sender.public_key(), CONTEXT, &ciphertext),
        Err(CryptoError::DecryptionFailed)
    );
    assert_eq!(
        open_message(&recipient, outsider.public_key(), CONTEXT, &ciphertext),
        Err(CryptoError::DecryptionFailed)
    );
}

#[test]
fn plaintext_boundary_is_enforced() {
    let sender = EncryptionSecretKey::derive(&[0x55; 32]);
    let recipient = EncryptionSecretKey::derive(&[0x66; 32]);
    let mut rng = VectorRng { next: 0 };
    let maximum = seal_message(
        &sender,
        recipient.public_key(),
        CONTEXT,
        &vec![0; MAX_PLAINTEXT_BYTES],
        &mut rng,
    )
    .expect("maximum plaintext");
    assert_eq!(maximum.len(), cofferwire_types::MAX_MESSAGE_BYTES);

    assert_eq!(
        seal_message(
            &sender,
            recipient.public_key(),
            CONTEXT,
            &vec![0; MAX_PLAINTEXT_BYTES + 1],
            &mut rng,
        ),
        Err(CryptoError::PlaintextTooLarge {
            max: MAX_PLAINTEXT_BYTES,
            actual: MAX_PLAINTEXT_BYTES + 1,
        })
    );
}

#[test]
fn debug_output_never_contains_secret_or_plaintext() {
    let signing_seed = [0xab; 32];
    let signing = RelaySigningKey::from_seed(signing_seed);
    let encryption = EncryptionSecretKey::derive(&[0xcd; 32]);
    let rendered = format!("{signing:?} {encryption:?}");
    assert!(!rendered.contains(&to_hex(&signing_seed)));
    assert!(!rendered.contains("family update"));
    assert!(format!("{:?}", CryptoError::DecryptionFailed).contains("DecryptionFailed"));
}

fn vector(field: &str) -> String {
    let vectors = include_str!("../../../vectors/crypto-v1.json");
    vectors
        .split(&format!("\"{field}\": \""))
        .nth(1)
        .expect("public vector field")
        .split('"')
        .next()
        .expect("quoted public vector value")
        .to_owned()
}

fn hex_decode(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("valid hex")
        })
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
