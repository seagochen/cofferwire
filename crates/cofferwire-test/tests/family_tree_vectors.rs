//! Vector coverage for the `family-tree/1` application profile
//! (`profiles/family-tree-v1.md`). This is an application-layer profile,
//! not core protocol: it has no Rust implementation elsewhere in this
//! repository, so this test is itself an independent reference
//! implementation of `FT-UPDATE-V1` parsing and the `## Conflict detection
//! and resolution` algorithm, checked against the shared fixture.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

const VECTOR_JSON: &str = include_str!("../../../profiles/vectors/family-tree-v1.json");
const DOMAIN: &[u8] = b"cofferwire family-tree update v1\0";

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(value[key].as_str().expect("hex vector string")).expect("valid vector hex")
}

fn array32(value: &Value, key: &str) -> [u8; 32] {
    bytes(value, key).try_into().expect("32-byte field")
}

struct ParsedUpdate {
    revision_id: [u8; 32],
    parents: Vec<[u8; 32]>,
    author_key: [u8; 32],
}

/// Independently parses `FT-UPDATE-V1` and verifies its signature, per
/// `## Update wire format` and `FT-UPDATE-002`.
fn parse_and_verify(update: &[u8]) -> ParsedUpdate {
    assert_eq!(&update[..4], b"FTU1");
    assert_eq!(update[4], 1, "version");
    let mut offset = 6 + 32; // skip object-type, object-id
    let revision_id: [u8; 32] = update[offset..offset + 32].try_into().unwrap();
    offset += 32;
    let parent_count = usize::from(update[offset]);
    offset += 1;
    let mut parents = Vec::with_capacity(parent_count);
    for _ in 0..parent_count {
        parents.push(update[offset..offset + 32].try_into().unwrap());
        offset += 32;
    }
    let author_key: [u8; 32] = update[offset..offset + 32].try_into().unwrap();
    offset += 32;
    offset += 8; // created-at
    let field_count = usize::from(update[offset]);
    offset += 1;
    for _ in 0..field_count {
        offset += 1; // tag
        let length = usize::from(u16::from_be_bytes(
            update[offset..offset + 2].try_into().unwrap(),
        ));
        offset += 2 + length;
    }
    let signed = &update[..offset];
    let signature_bytes: [u8; 64] = update[offset..offset + 64].try_into().unwrap();
    assert_eq!(offset + 64, update.len(), "no trailing bytes");

    let verifying_key = VerifyingKey::from_bytes(&author_key).expect("valid author key");
    let signature = Signature::from_bytes(&signature_bytes);
    let mut to_verify = DOMAIN.to_vec();
    to_verify.extend_from_slice(signed);
    verifying_key
        .verify(&to_verify, &signature)
        .expect("update signature verifies");

    ParsedUpdate {
        revision_id,
        parents,
        author_key,
    }
}

/// Independent implementation of `## Conflict detection and resolution`
/// (`FT-CONFLICT-001` through `FT-CONFLICT-005`).
#[derive(Default)]
struct ObjectState {
    leaves: HashSet<[u8; 32]>,
    seen_any: bool,
}

enum ApplyOutcome {
    Applied { conflict: bool },
    RejectedDuplicateCreation,
    RejectedMergeNonLeafParent,
}

impl ObjectState {
    fn apply(&mut self, update: &ParsedUpdate) -> ApplyOutcome {
        match update.parents.len() {
            0 => {
                if self.seen_any {
                    return ApplyOutcome::RejectedDuplicateCreation;
                }
                self.seen_any = true;
                self.leaves.insert(update.revision_id);
                ApplyOutcome::Applied { conflict: false }
            }
            1 => {
                self.seen_any = true;
                let parent = update.parents[0];
                if self.leaves.len() == 1 && self.leaves.contains(&parent) {
                    self.leaves.remove(&parent);
                    self.leaves.insert(update.revision_id);
                    ApplyOutcome::Applied { conflict: false }
                } else {
                    self.leaves.insert(update.revision_id);
                    ApplyOutcome::Applied { conflict: true }
                }
            }
            _ => {
                if update
                    .parents
                    .iter()
                    .all(|parent| self.leaves.contains(parent))
                {
                    for parent in &update.parents {
                        self.leaves.remove(parent);
                    }
                    self.leaves.insert(update.revision_id);
                    ApplyOutcome::Applied { conflict: false }
                } else {
                    ApplyOutcome::RejectedMergeNonLeafParent
                }
            }
        }
    }
}

#[test]
fn family_tree_vector_history_reproduces_conflict_algorithm() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).expect("valid family-tree vector JSON");
    let author_a = array32(&vector, "author_a_key_hex");
    let author_b = array32(&vector, "author_b_key_hex");
    let updates = vector["updates"].as_array().expect("updates array");

    let mut names_to_revision: std::collections::HashMap<String, [u8; 32]> =
        std::collections::HashMap::default();
    let mut state = ObjectState::default();

    for entry in updates {
        let name = entry["name"].as_str().expect("name").to_owned();
        let update_bytes = bytes(entry, "update_hex");
        let parsed = parse_and_verify(&update_bytes);
        assert_eq!(
            parsed.revision_id,
            array32(entry, "revision_id_hex"),
            "{name}: revision id"
        );
        let expected_author = match entry["author"].as_str().expect("author") {
            "a" => author_a,
            "b" => author_b,
            other => panic!("unknown author label {other}"),
        };
        assert_eq!(parsed.author_key, expected_author, "{name}: author key");

        let expected_parent_names: Vec<String> = entry["parents"]
            .as_array()
            .expect("parents")
            .iter()
            .map(|value| value.as_str().expect("parent name").to_owned())
            .collect();
        let expected_parents: Vec<[u8; 32]> = expected_parent_names
            .iter()
            .map(|parent_name| names_to_revision[parent_name])
            .collect();
        assert_eq!(parsed.parents, expected_parents, "{name}: parents");

        let outcome = state.apply(&parsed);
        let expect = &entry["expect_after_apply"];
        let expect_conflict = expect["conflict"].as_bool().expect("conflict flag");
        match outcome {
            ApplyOutcome::Applied { conflict } => {
                assert_eq!(conflict, expect_conflict, "{name}: conflict flag");
            }
            ApplyOutcome::RejectedDuplicateCreation | ApplyOutcome::RejectedMergeNonLeafParent => {
                panic!("{name}: unexpectedly rejected");
            }
        }
        let expected_leaves: HashSet<[u8; 32]> = expect["leaves"]
            .as_array()
            .expect("leaves")
            .iter()
            .map(|value| {
                names_to_revision
                    .get(value.as_str().expect("leaf name"))
                    .copied()
                    .unwrap_or(parsed.revision_id)
            })
            .collect();
        assert_eq!(state.leaves, expected_leaves, "{name}: leaf set");

        names_to_revision.insert(name, parsed.revision_id);
    }
}

#[test]
fn family_tree_vector_negatives_are_rejected() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).expect("valid family-tree vector JSON");
    let updates = vector["updates"].as_array().expect("updates array");

    // update_byte_tamper: every byte of every update must be tamper-evident.
    // parse_and_verify panics via expect() on rejection, which is expected
    // here at every offset; silence the default panic hook for this loop.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for entry in updates {
        let update_bytes = bytes(entry, "update_hex");
        for offset in 0..update_bytes.len() {
            let mut tampered = update_bytes.clone();
            tampered[offset] ^= 0x01;
            let result = std::panic::catch_unwind(|| parse_and_verify(&tampered));
            assert!(
                result.is_err(),
                "{}: byte {offset} tamper unexpectedly verified",
                entry["name"].as_str().unwrap()
            );
        }
    }
    std::panic::set_hook(default_hook);

    // duplicate_creation: replaying U1 after later updates must be rejected.
    let mut state = ObjectState::default();
    for entry in updates {
        let update_bytes = bytes(entry, "update_hex");
        let parsed = parse_and_verify(&update_bytes);
        state.apply(&parsed);
    }
    let creation = &updates[0];
    let creation_bytes = bytes(creation, "update_hex");
    let parsed_creation = parse_and_verify(&creation_bytes);
    assert!(matches!(
        state.apply(&parsed_creation),
        ApplyOutcome::RejectedDuplicateCreation
    ));

    // merge_with_non_leaf_parent: a merge naming one current leaf (U3a) and
    // one already-superseded parent (U2, superseded by U3a/U3b) must be
    // rejected rather than partially resolving the conflict.
    let u2_revision = array32(&updates[1], "revision_id_hex");
    let u3a_revision = array32(&updates[2], "revision_id_hex");
    let fake_merge = ParsedUpdate {
        revision_id: [0xAA; 32],
        parents: vec![u3a_revision, u2_revision],
        author_key: array32(&vector, "author_a_key_hex"),
    };
    let mut replay_state = ObjectState::default();
    for entry in &updates[..4] {
        let update_bytes = bytes(entry, "update_hex");
        let parsed = parse_and_verify(&update_bytes);
        replay_state.apply(&parsed);
    }
    assert!(matches!(
        replay_state.apply(&fake_merge),
        ApplyOutcome::RejectedMergeNonLeafParent
    ));

    // wrong_author_key_signature: verifying against a mismatched key fails.
    let other_key = ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]).verifying_key();
    let signed_len = bytes(&updates[0], "update_hex").len() - 64;
    let update_bytes = bytes(&updates[0], "update_hex");
    let signature = Signature::from_bytes(&update_bytes[signed_len..].try_into().unwrap());
    let mut to_verify = DOMAIN.to_vec();
    to_verify.extend_from_slice(&update_bytes[..signed_len]);
    assert!(other_key.verify(&to_verify, &signature).is_err());

    let negative = vector["negative"].as_array().expect("negative vectors");
    assert_eq!(negative.len(), 4);
    for case in negative {
        assert!(case["operation"].as_str().expect("operation").len() > 20);
    }
}
