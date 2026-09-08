use std::collections::HashMap;

use rand_core::{CryptoRng, Error, OsRng, RngCore};

use super::*;

struct TestRng(u8);
impl RngCore for TestRng {
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
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}
impl CryptoRng for TestRng {}

#[derive(Default)]
struct Imports(HashMap<(QueueId, u8), (Principal, MessageId)>);
impl BundleStore for Imports {
    fn record(
        &mut self,
        queue_id: QueueId,
        role: Role,
        peer_principal: Principal,
        bundle_id: MessageId,
    ) -> Result<ImportOutcome, BundleStoreError> {
        let key = (
            queue_id,
            match role {
                Role::Sender => 0,
                Role::Recipient => 1,
            },
        );
        match self.0.get(&key) {
            Some((existing_peer, existing_bundle)) if *existing_peer == peer_principal => {
                if *existing_bundle == bundle_id {
                    Ok(ImportOutcome::AlreadyImported)
                } else {
                    self.0.insert(key, (peer_principal, bundle_id));
                    Ok(ImportOutcome::Imported)
                }
            }
            Some(_) => Err(BundleStoreError::ConflictingIdentity),
            None => {
                self.0.insert(key, (peer_principal, bundle_id));
                Ok(ImportOutcome::Imported)
            }
        }
    }
}

fn device(seed: u8) -> (Principal, EncryptionSecretKey) {
    (
        RelaySigningKey::from_seed([seed; 32]).principal(),
        EncryptionSecretKey::derive(&[seed.wrapping_add(100); 32]),
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    })
}

fn recovery_fields(peer_principal: Principal, peer_key: EncryptionPublicKey) -> BundleFields {
    BundleFields {
        role: Role::Recipient,
        peer_principal,
        peer_encryption_public_key: peer_key,
        created_at_secs: 1_700_000_000,
        own_identity: Some(OwnIdentitySeed {
            signing_seed: [7; 32],
            encryption_ikm: [8; 32],
        }),
        relay_hints: vec![
            b"https://relay-a.example".to_vec(),
            b"https://relay-b.example".to_vec(),
        ],
    }
}

#[test]
fn recovery_bundle_round_trips_and_reconstructs_identity() {
    let (exporter_principal, exporter_key) = device(1);
    let (importer_principal, importer_key) = device(2);
    let queue = QueueId::from_bytes([9; 32]);
    let bundle_id = MessageId::from_bytes([10; 32]);
    let fields = recovery_fields(exporter_principal, exporter_key.public_key());

    let envelope = seal_bundle(
        MessageContext {
            queue_id: queue,
            sender: exporter_principal,
            recipient: importer_principal,
            message_id: bundle_id,
        },
        &exporter_key,
        importer_key.public_key(),
        &fields,
        &mut TestRng(0),
    )
    .expect("bundle seals");

    let (opened_queue, opened_bundle_id, opened) = open_bundle(
        &importer_key,
        importer_principal,
        exporter_principal,
        exporter_key.public_key(),
        &envelope,
    )
    .expect("bundle opens");
    assert_eq!(opened_queue, queue);
    assert_eq!(opened_bundle_id, bundle_id);
    assert_eq!(opened.peer_principal, exporter_principal);
    assert_eq!(opened.relay_hints, fields.relay_hints);
    let (signing, encryption) = opened
        .own_identity
        .as_ref()
        .expect("recovery carries identity")
        .reconstruct();
    assert_eq!(
        signing.principal(),
        RelaySigningKey::from_seed([7; 32]).principal()
    );
    assert_eq!(
        encryption.public_key(),
        EncryptionSecretKey::derive(&[8; 32]).public_key()
    );
}

#[test]
fn invitation_bundle_carries_no_secret_and_round_trips() {
    let (exporter_principal, exporter_key) = device(3);
    let (importer_principal, importer_key) = device(4);
    let queue = QueueId::from_bytes([11; 32]);
    let bundle_id = MessageId::from_bytes([12; 32]);
    let fields = BundleFields {
        own_identity: None,
        ..recovery_fields(exporter_principal, exporter_key.public_key())
    };

    let envelope = seal_bundle(
        MessageContext {
            queue_id: queue,
            sender: exporter_principal,
            recipient: importer_principal,
            message_id: bundle_id,
        },
        &exporter_key,
        importer_key.public_key(),
        &fields,
        &mut OsRng,
    )
    .expect("bundle seals");
    let (_, _, opened) = open_bundle(
        &importer_key,
        importer_principal,
        exporter_principal,
        exporter_key.public_key(),
        &envelope,
    )
    .expect("bundle opens");
    assert!(opened.own_identity.is_none());
}

#[test]
fn wrong_expected_exporter_and_wrong_recipient_are_rejected() {
    let (exporter_principal, exporter_key) = device(5);
    let (importer_principal, importer_key) = device(6);
    let (other_principal, other_key) = device(7);
    let queue = QueueId::from_bytes([13; 32]);
    let bundle_id = MessageId::from_bytes([14; 32]);
    let fields = recovery_fields(exporter_principal, exporter_key.public_key());
    let envelope = seal_bundle(
        MessageContext {
            queue_id: queue,
            sender: exporter_principal,
            recipient: importer_principal,
            message_id: bundle_id,
        },
        &exporter_key,
        importer_key.public_key(),
        &fields,
        &mut OsRng,
    )
    .expect("bundle seals");

    // Wrong expected exporter: verifier trusts a different principal.
    assert!(matches!(
        open_bundle(
            &importer_key,
            importer_principal,
            other_principal,
            other_key.public_key(),
            &envelope
        ),
        Err(BundleError::Crypto(_))
    ));

    // Wrong recipient: a different device attempts to open it.
    assert!(matches!(
        open_bundle(
            &other_key,
            other_principal,
            exporter_principal,
            exporter_key.public_key(),
            &envelope
        ),
        Err(BundleError::Crypto(_))
    ));
}

#[test]
fn every_byte_tamper_and_truncation_is_rejected() {
    let (exporter_principal, exporter_key) = device(8);
    let (importer_principal, importer_key) = device(9);
    let queue = QueueId::from_bytes([15; 32]);
    let bundle_id = MessageId::from_bytes([16; 32]);
    let fields = recovery_fields(exporter_principal, exporter_key.public_key());
    let envelope = seal_bundle(
        MessageContext {
            queue_id: queue,
            sender: exporter_principal,
            recipient: importer_principal,
            message_id: bundle_id,
        },
        &exporter_key,
        importer_key.public_key(),
        &fields,
        &mut OsRng,
    )
    .expect("bundle seals");

    for offset in 0..envelope.len() {
        let mut tampered = envelope.clone();
        tampered[offset] ^= 0x01;
        assert!(
            open_bundle(
                &importer_key,
                importer_principal,
                exporter_principal,
                exporter_key.public_key(),
                &tampered
            )
            .is_err(),
            "byte {offset} tamper unexpectedly opened"
        );
    }

    let mut truncated = envelope.clone();
    truncated.pop();
    assert!(open_bundle(
        &importer_key,
        importer_principal,
        exporter_principal,
        exporter_key.public_key(),
        &truncated
    )
    .is_err());

    let mut wrong_version = envelope.clone();
    wrong_version[MAGIC.len()] = 0xFF;
    assert!(matches!(
        open_bundle(
            &importer_key,
            importer_principal,
            exporter_principal,
            exporter_key.public_key(),
            &wrong_version
        ),
        Err(BundleError::UnsupportedVersion)
    ));
}

#[test]
fn duplicate_import_is_a_no_op_and_conflicting_identity_is_rejected() {
    let (exporter_principal, exporter_key) = device(10);
    let (importer_principal, importer_key) = device(11);
    let (other_exporter_principal, _) = device(12);
    let queue = QueueId::from_bytes([17; 32]);
    let bundle_id = MessageId::from_bytes([18; 32]);
    let fields = recovery_fields(exporter_principal, exporter_key.public_key());
    let envelope = seal_bundle(
        MessageContext {
            queue_id: queue,
            sender: exporter_principal,
            recipient: importer_principal,
            message_id: bundle_id,
        },
        &exporter_key,
        importer_key.public_key(),
        &fields,
        &mut OsRng,
    )
    .expect("bundle seals");

    let mut store = Imports::default();
    let (_, _, first) = open_and_record_bundle(
        &mut store,
        &importer_key,
        importer_principal,
        exporter_principal,
        exporter_key.public_key(),
        &envelope,
    )
    .expect("first import succeeds");
    assert_eq!(first, ImportOutcome::Imported);

    let (_, _, second) = open_and_record_bundle(
        &mut store,
        &importer_key,
        importer_principal,
        exporter_principal,
        exporter_key.public_key(),
        &envelope,
    )
    .expect("duplicate import still verifies");
    assert_eq!(second, ImportOutcome::AlreadyImported);

    // A different bundle_id claiming the same (queue, role) but a
    // DIFFERENT peer principal must be rejected as a conflict.
    let conflicting_bundle_id = MessageId::from_bytes([19; 32]);
    let conflicting_fields = recovery_fields(other_exporter_principal, exporter_key.public_key());
    let conflicting_envelope = seal_bundle(
        MessageContext {
            queue_id: queue,
            sender: other_exporter_principal,
            recipient: importer_principal,
            message_id: conflicting_bundle_id,
        },
        &exporter_key,
        importer_key.public_key(),
        &conflicting_fields,
        &mut OsRng,
    )
    .expect("bundle seals");
    assert!(matches!(
        open_and_record_bundle(
            &mut store,
            &importer_key,
            importer_principal,
            other_exporter_principal,
            exporter_key.public_key(),
            &conflicting_envelope
        ),
        Err(ImportError::ConflictingIdentity)
    ));
}

#[test]
fn bundle_error_debug_never_contains_relay_hints_or_key_material() {
    let (exporter_principal, exporter_key) = device(30);
    let (importer_principal, importer_key) = device(31);
    let queue = QueueId::from_bytes([31; 32]);
    let bundle_id = MessageId::from_bytes([32; 32]);
    let mut fields = recovery_fields(exporter_principal, exporter_key.public_key());
    fields.relay_hints = vec![b"https://SECRET-RELAY-MARKER.example".to_vec()];
    fields.own_identity = Some(OwnIdentitySeed {
        signing_seed: [0xAB; 32],
        encryption_ikm: [0xCD; 32],
    });

    let envelope = seal_bundle(
        MessageContext {
            queue_id: queue,
            sender: exporter_principal,
            recipient: importer_principal,
            message_id: bundle_id,
        },
        &exporter_key,
        importer_key.public_key(),
        &fields,
        &mut OsRng,
    )
    .expect("bundle seals");
    let mut tampered = envelope.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;

    let error = open_bundle(
        &importer_key,
        importer_principal,
        exporter_principal,
        exporter_key.public_key(),
        &tampered,
    )
    .expect_err("tampered envelope fails authentication");

    let rendered = format!("{error:?} {error}");
    assert!(
        !rendered.contains("SECRET-RELAY-MARKER"),
        "relay hint plaintext leaked"
    );
    assert!(
        !rendered.contains(&hex_encode(&tampered)),
        "tampered ciphertext leaked"
    );
    assert!(
        !rendered.contains(&hex_encode(&envelope)),
        "original ciphertext leaked"
    );
    assert!(
        !rendered.contains(&hex_encode(&[0xAB; 32])),
        "signing seed leaked"
    );
    assert!(
        !rendered.contains(&hex_encode(&[0xCD; 32])),
        "encryption ikm leaked"
    );
}

#[test]
fn import_error_debug_never_contains_relay_hints_or_key_material() {
    let (exporter_principal, exporter_key) = device(32);
    let (importer_principal, importer_key) = device(33);
    let queue = QueueId::from_bytes([33; 32]);
    let bundle_id = MessageId::from_bytes([34; 32]);
    let mut fields = recovery_fields(exporter_principal, exporter_key.public_key());
    fields.relay_hints = vec![b"https://SECRET-RELAY-MARKER.example".to_vec()];

    let envelope = seal_bundle(
        MessageContext {
            queue_id: queue,
            sender: exporter_principal,
            recipient: importer_principal,
            message_id: bundle_id,
        },
        &exporter_key,
        importer_key.public_key(),
        &fields,
        &mut OsRng,
    )
    .expect("bundle seals");

    let mut store = Imports::default();
    let error = open_and_record_bundle(
        &mut store,
        &importer_key,
        importer_principal,
        importer_principal,
        exporter_key.public_key(),
        &envelope,
    )
    .expect_err("wrong expected exporter fails authentication");

    let rendered = format!("{error:?} {error}");
    assert!(
        !rendered.contains("SECRET-RELAY-MARKER"),
        "relay hint plaintext leaked"
    );
    assert!(
        !rendered.contains(&hex_encode(&envelope)),
        "ciphertext leaked"
    );
}
