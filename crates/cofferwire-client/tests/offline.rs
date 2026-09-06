use std::collections::{HashMap, HashSet, VecDeque};

use cofferwire_client::offline::{
    open_and_record_bundle, open_bundle, seal_bundle, BundleFields, BundleStore, BundleStoreError,
    ImportOutcome, OwnIdentitySeed, Role,
};
use cofferwire_client::{
    CommitOutcome, InboxStore, PollOutcome, Recipient, RequestIdSource, Sender, StoreError,
    Transport, TransportError,
};
use cofferwire_codec::{decode_request, encode_response, ResponseFrame};
use cofferwire_crypto::{seal_message, EncryptionSecretKey, MessageContext, RelaySigningKey};
use cofferwire_types::{
    MessageId, Principal, QueueId, RequestId, Response, ResponseBody, SendOutcome, Ttl,
};
use rand_core::OsRng;

fn device(seed: u8) -> (RelaySigningKey, EncryptionSecretKey) {
    (
        RelaySigningKey::from_seed([seed; 32]),
        EncryptionSecretKey::derive(&[seed.wrapping_add(100); 32]),
    )
}

#[derive(Clone)]
enum Action {
    Respond(Response),
}

struct ScriptedTransport {
    actions: VecDeque<Action>,
}
impl ScriptedTransport {
    fn new(actions: impl IntoIterator<Item = Action>) -> Self {
        Self {
            actions: actions.into_iter().collect(),
        }
    }
}
impl Transport for ScriptedTransport {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let decoded = decode_request(request).expect("client emits valid requests");
        match self.actions.pop_front().expect("scripted action") {
            Action::Respond(response) => Ok(encode_response(&ResponseFrame::new(
                decoded.frame().request_id(),
                response,
            ))),
        }
    }
}

struct Ids(u8);
impl RequestIdSource for Ids {
    fn next_request_id(&mut self) -> RequestId {
        let id = RequestId::from_bytes([self.0; 16]);
        self.0 = self.0.checked_add(1).expect("test ID range");
        id
    }
}

#[derive(Default)]
struct Inbox(HashMap<MessageId, Vec<u8>>);
impl InboxStore for Inbox {
    fn commit(
        &mut self,
        message_id: MessageId,
        plaintext: &[u8],
    ) -> Result<CommitOutcome, StoreError> {
        match self.0.get(&message_id) {
            Some(existing) if existing == plaintext => Ok(CommitOutcome::AlreadyCommitted),
            Some(_) => Err(StoreError),
            None => {
                self.0.insert(message_id, plaintext.to_vec());
                Ok(CommitOutcome::Applied)
            }
        }
    }
}

#[derive(Default)]
struct Imports(HashSet<(QueueId, bool, Principal)>);
impl BundleStore for Imports {
    fn record(
        &mut self,
        queue_id: QueueId,
        role: Role,
        peer_principal: Principal,
        _bundle_id: MessageId,
    ) -> Result<ImportOutcome, BundleStoreError> {
        let is_recipient = matches!(role, Role::Recipient);
        let key = (queue_id, is_recipient, peer_principal);
        if self.0.insert(key) {
            Ok(ImportOutcome::Imported)
        } else {
            Ok(ImportOutcome::AlreadyImported)
        }
    }
}

/// A device that has fully recovered its identity from a bundle, with no
/// runtime state beyond what the bundle and its own newly reconstructed
/// keys provide, resumes an existing conversation and continues working
/// unchanged after its relay is replaced -- the flow `spec/13-offline-
/// bundles.md` describes and acceptance criteria 3 and 4 of issue #18
/// require.
#[test]
#[allow(clippy::too_many_lines)]
fn recovery_bundle_lets_a_fresh_device_resume_and_survive_relay_replacement() {
    let (a_signing, a_encryption) = device(1);
    let a_principal = a_signing.principal();
    let a_encryption_public = a_encryption.public_key();

    let signing_seed = [21_u8; 32];
    let encryption_ikm = [22_u8; 32];
    let original_b_signing = RelaySigningKey::from_seed(signing_seed);
    let original_b_encryption = EncryptionSecretKey::derive(&encryption_ikm);
    let b_principal = original_b_signing.principal();
    let queue = QueueId::from_bytes([30; 32]);

    // The new device generates a fresh transfer keypair purely to receive
    // this one bundle; before import it holds none of B's identity.
    let transfer_key = EncryptionSecretKey::generate(&mut OsRng);
    let transfer_public = transfer_key.public_key();

    let bundle_id = MessageId::from_bytes([31; 32]);
    let fields = BundleFields {
        role: Role::Recipient,
        peer_principal: a_principal,
        peer_encryption_public_key: a_encryption_public,
        created_at_secs: 1_700_000_000,
        own_identity: Some(OwnIdentitySeed {
            signing_seed,
            encryption_ikm,
        }),
        relay_hints: vec![b"https://relay-old.example".to_vec()],
    };
    let envelope = seal_bundle(
        MessageContext {
            queue_id: queue,
            sender: b_principal,
            recipient: b_principal,
            message_id: bundle_id,
        },
        &original_b_encryption,
        transfer_public,
        &fields,
        &mut OsRng,
    )
    .expect("bundle seals");

    let mut imports = Imports::default();
    let (opened_queue, opened_fields, outcome) = open_and_record_bundle(
        &mut imports,
        &transfer_key,
        b_principal,
        b_principal,
        original_b_encryption.public_key(),
        &envelope,
    )
    .expect("bundle opens and records on the new device");
    assert_eq!(opened_queue, queue);
    assert_eq!(outcome, ImportOutcome::Imported);

    let (recovered_signing, recovered_encryption) = opened_fields
        .own_identity
        .as_ref()
        .expect("recovery bundle carries identity")
        .reconstruct();
    assert_eq!(recovered_signing.principal(), b_principal);
    let recovered_encryption_public = recovered_encryption.public_key();
    assert_eq!(
        recovered_encryption_public,
        original_b_encryption.public_key()
    );

    // The new device builds its Recipient exactly as it would have from
    // locally provisioned keys -- no separate "recovered" code path.
    let recipient = Recipient::new(
        opened_queue,
        opened_fields.peer_principal,
        b_principal,
        recovered_signing,
        recovered_encryption,
        opened_fields.peer_encryption_public_key,
    )
    .expect("recipient reconstructs from recovered identity");

    // A's plaintext, sealed exactly as any ordinary application message.
    let delivery_message = MessageId::from_bytes([32; 32]);
    let context = MessageContext {
        queue_id: opened_queue,
        sender: a_principal,
        recipient: b_principal,
        message_id: delivery_message,
    };
    let sealed = seal_message(
        &a_encryption,
        recovered_encryption_public,
        context,
        b"resumed after recovery",
        &mut OsRng,
    )
    .expect("message encrypts");
    let delivery = cofferwire_types::Delivery::new(
        delivery_message,
        sealed,
        cofferwire_types::Timestamp::from_secs(2_000),
    );

    let mut inbox = Inbox::default();
    // Poll once through the "old" relay's transport.
    let mut old_relay = ScriptedTransport::new([
        Action::Respond(Response::Success(ResponseBody::Fetch(Some(
            delivery.clone(),
        )))),
        Action::Respond(Response::Success(ResponseBody::Ack)),
    ]);
    assert_eq!(
        recipient
            .poll(&mut old_relay, &mut inbox, &mut Ids(1))
            .expect("poll through the old relay succeeds"),
        PollOutcome::Applied(delivery_message)
    );

    // Relay replacement: the identical Recipient, with its identical local
    // durable state, now talks to a completely different Transport (a
    // stand-in for a new relay reached through an updated relay hint). A
    // redelivery of the same message must still be recognized, not
    // reapplied, proving identity and object semantics are transport-
    // independent (CW-OFFLINE-011, CW-ARCH-004, CW-ARCH-010).
    let mut new_relay = ScriptedTransport::new([
        Action::Respond(Response::Success(ResponseBody::Fetch(Some(delivery)))),
        Action::Respond(Response::Success(ResponseBody::Ack)),
    ]);
    assert_eq!(
        recipient
            .poll(&mut new_relay, &mut inbox, &mut Ids(3))
            .expect("poll through the replacement relay succeeds"),
        PollOutcome::RedeliveryAcknowledged(delivery_message)
    );
    assert_eq!(
        inbox.0.len(),
        1,
        "redelivery through a new relay is not a second application"
    );
}

/// An invitation carries no secret: the invitee already holds its own keys
/// and only needs to learn the counterparty's public identity and relay
/// hints.
#[test]
fn invitation_bundle_carries_no_secret_and_lets_the_invitee_construct_a_sender() {
    let (host_signing, host_encryption) = device(5);
    let host_principal = host_signing.principal();
    let (guest_signing, guest_encryption) = device(6);
    let guest_principal = guest_signing.principal();
    let queue = QueueId::from_bytes([40; 32]);
    let bundle_id = MessageId::from_bytes([41; 32]);

    let fields = BundleFields {
        role: Role::Sender,
        peer_principal: host_principal,
        peer_encryption_public_key: host_encryption.public_key(),
        created_at_secs: 1_700_000_100,
        own_identity: None,
        relay_hints: vec![b"https://relay.example/queue".to_vec()],
    };
    let envelope = seal_bundle(
        MessageContext {
            queue_id: queue,
            sender: host_principal,
            recipient: guest_principal,
            message_id: bundle_id,
        },
        &host_encryption,
        guest_encryption.public_key(),
        &fields,
        &mut OsRng,
    )
    .expect("invitation seals");

    let (opened_queue, _, opened) = open_bundle(
        &guest_encryption,
        guest_principal,
        host_principal,
        host_encryption.public_key(),
        &envelope,
    )
    .expect("invitation opens");
    assert!(opened.own_identity.is_none());

    let sender = Sender::new(
        opened_queue,
        guest_principal,
        opened.peer_principal,
        guest_signing,
        guest_encryption,
        opened.peer_encryption_public_key,
    )
    .expect("sender constructs from the invitation");
    let prepared = sender
        .prepare(
            RequestId::from_bytes([1; 16]),
            MessageId::from_bytes([42; 32]),
            b"hello",
            Ttl::from_secs(60),
            &mut OsRng,
        )
        .expect("prepared send encrypts using the invited relationship");
    let mut transport = ScriptedTransport::new([Action::Respond(Response::Success(
        ResponseBody::Send(SendOutcome::Accepted),
    ))]);
    assert!(sender.send(&prepared, &mut transport).is_ok());
}
