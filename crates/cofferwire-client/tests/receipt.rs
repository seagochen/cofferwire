use std::collections::{HashMap, HashSet, VecDeque};

use cofferwire_client::receipt::{
    build_applied_receipt, verify_and_record_applied_receipt, ConfirmedObject, ReceiptOutcome,
    ReceiptStore, ReceiptVerificationError,
};
use cofferwire_client::{
    CommitOutcome, InboxStore, PollOutcome, Recipient, RequestIdSource, Sender, StoreError,
    Transport, TransportError,
};
use cofferwire_codec::{decode_request, encode_response, ResponseFrame};
use cofferwire_crypto::{EncryptionSecretKey, RelaySigningKey};
use cofferwire_types::{MessageId, Principal, QueueId, Response, ResponseBody, SendOutcome, Ttl};
use rand_core::{CryptoRng, Error, RngCore};

const FORWARD_QUEUE: QueueId = QueueId::from_bytes([10; 32]);
const REVERSE_QUEUE: QueueId = QueueId::from_bytes([11; 32]);
const ORIGINAL_MESSAGE: MessageId = MessageId::from_bytes([20; 32]);
const RECEIPT_MESSAGE: MessageId = MessageId::from_bytes([21; 32]);

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
    fn next_request_id(&mut self) -> cofferwire_types::RequestId {
        let id = cofferwire_types::RequestId::from_bytes([self.0; 16]);
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
struct Receipts(HashSet<(QueueId, Principal, Principal, MessageId)>);
impl ReceiptStore for Receipts {
    fn record(&mut self, confirmed: ConfirmedObject) -> Result<ReceiptOutcome, StoreError> {
        let key = (
            confirmed.queue_id,
            confirmed.sender,
            confirmed.recipient,
            confirmed.message_id,
        );
        if self.0.insert(key) {
            Ok(ReceiptOutcome::Recorded)
        } else {
            Ok(ReceiptOutcome::AlreadyRecorded)
        }
    }
}

fn device(seed: u8) -> (RelaySigningKey, EncryptionSecretKey) {
    (
        RelaySigningKey::from_seed([seed; 32]),
        EncryptionSecretKey::derive(&[seed.wrapping_add(100); 32]),
    )
}

/// Device B (the original recipient on `FORWARD_QUEUE`, hence the confirming
/// device) already durably committed the application message; generates a
/// signed `receipt.applied`, sends it as an ordinary message on the
/// independent reverse queue, and device A (the original sender) polls,
/// verifies, and durably records it -- exactly the flow `docs/spec/08-receipts.md`
/// describes and acceptance criterion 5 of issue #17 requires.
#[test]
fn client_generates_and_verifies_a_receipt_after_local_durable_commit() {
    let (a_signing, a_encryption) = device(2);
    let (b_signing, b_encryption) = device(3);
    let a_principal = a_signing.principal();
    let b_principal = b_signing.principal();

    let applied_plaintext = b"family update applied";
    let confirmed = ConfirmedObject {
        queue_id: FORWARD_QUEUE,
        sender: a_principal,
        recipient: b_principal,
        message_id: ORIGINAL_MESSAGE,
    };
    // This is the exact point a reference client generates a receipt: after
    // its own local durable commit of the original application message.
    let receipt_plaintext =
        build_applied_receipt(&b_signing, confirmed, applied_plaintext, 1_700_000_000);

    let b_encryption_public = b_encryption.public_key();
    let b_sender = Sender::new(
        REVERSE_QUEUE,
        b_principal,
        a_principal,
        b_signing,
        b_encryption,
        a_encryption.public_key(),
    )
    .expect("sender config is valid");
    let prepared = b_sender
        .prepare(
            cofferwire_types::RequestId::from_bytes([1; 16]),
            RECEIPT_MESSAGE,
            &receipt_plaintext,
            Ttl::from_secs(300),
            &mut TestRng(0),
        )
        .expect("receipt encrypts");
    let mut send_transport = ScriptedTransport::new([Action::Respond(Response::Success(
        ResponseBody::Send(SendOutcome::Accepted),
    ))]);
    b_sender
        .send(&prepared, &mut send_transport)
        .expect("receipt SEND succeeds");

    let a_recipient = Recipient::new(
        REVERSE_QUEUE,
        b_principal,
        a_principal,
        a_signing,
        a_encryption,
        b_encryption_public,
    )
    .expect("recipient config is valid");
    let delivery = cofferwire_types::Delivery::new(
        RECEIPT_MESSAGE,
        prepared_payload(&prepared),
        cofferwire_types::Timestamp::from_secs(2_000),
    );
    let mut poll_transport = ScriptedTransport::new([
        Action::Respond(Response::Success(ResponseBody::Fetch(Some(delivery)))),
        Action::Respond(Response::Success(ResponseBody::Ack)),
    ]);
    let mut inbox = Inbox::default();
    let outcome = a_recipient
        .poll(&mut poll_transport, &mut inbox, &mut Ids(1))
        .expect("receipt delivery succeeds");
    assert_eq!(outcome, PollOutcome::Applied(RECEIPT_MESSAGE));
    let decrypted_receipt = inbox.0.get(&RECEIPT_MESSAGE).expect("receipt committed");

    let mut receipts = Receipts::default();
    let (verified, first_outcome) = verify_and_record_applied_receipt(
        &mut receipts,
        b_principal,
        confirmed,
        Some(applied_plaintext),
        decrypted_receipt,
    )
    .expect("receipt verifies against the expected object and content");
    assert_eq!(verified.confirmed, confirmed);
    assert_eq!(first_outcome, ReceiptOutcome::Recorded);

    // A second, independent confirmation of the same object -- for example
    // a resent receipt after an ambiguous ACK -- is a no-op duplicate, not a
    // second application-level effect (CW-RECEIPT-008).
    let (_, second_outcome) = verify_and_record_applied_receipt(
        &mut receipts,
        b_principal,
        confirmed,
        Some(applied_plaintext),
        decrypted_receipt,
    )
    .expect("duplicate receipt still verifies");
    assert_eq!(second_outcome, ReceiptOutcome::AlreadyRecorded);
}

#[test]
fn receipt_confirming_a_different_object_is_rejected_distinctly_from_signature_failure() {
    let (a_signing, _) = device(2);
    let (b_signing, _) = device(3);
    let a_principal = a_signing.principal();
    let b_principal = b_signing.principal();
    let confirmed = ConfirmedObject {
        queue_id: FORWARD_QUEUE,
        sender: a_principal,
        recipient: b_principal,
        message_id: ORIGINAL_MESSAGE,
    };
    let receipt = build_applied_receipt(&b_signing, confirmed, b"content", 1);

    let mut receipts = Receipts::default();
    let wrong_object = ConfirmedObject {
        message_id: MessageId::from_bytes([99; 32]),
        ..confirmed
    };
    assert!(matches!(
        verify_and_record_applied_receipt(&mut receipts, b_principal, wrong_object, None, &receipt),
        Err(ReceiptVerificationError::ObjectMismatch)
    ));

    let wrong_signer = RelaySigningKey::from_seed([4; 32]).principal();
    assert!(matches!(
        verify_and_record_applied_receipt(&mut receipts, wrong_signer, confirmed, None, &receipt),
        Err(ReceiptVerificationError::Crypto(_))
    ));

    assert!(matches!(
        verify_and_record_applied_receipt(
            &mut receipts,
            b_principal,
            confirmed,
            Some(b"different content entirely"),
            &receipt
        ),
        Err(ReceiptVerificationError::ContentMismatch)
    ));
}

#[test]
fn receipt_verification_error_debug_never_contains_plaintext_or_signature() {
    let (a_signing, _) = device(2);
    let (b_signing, _) = device(3);
    let a_principal = a_signing.principal();
    let b_principal = b_signing.principal();
    let confirmed = ConfirmedObject {
        queue_id: FORWARD_QUEUE,
        sender: a_principal,
        recipient: b_principal,
        message_id: ORIGINAL_MESSAGE,
    };
    let applied_plaintext = b"SECRET-APPLIED-CONTENT-MARKER";
    let receipt = build_applied_receipt(&b_signing, confirmed, applied_plaintext, 1);
    let hex = |bytes: &[u8]| {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        })
    };

    let mut receipts = Receipts::default();
    let content_mismatch_error = verify_and_record_applied_receipt(
        &mut receipts,
        b_principal,
        confirmed,
        Some(b"a completely different applied content"),
        &receipt,
    )
    .expect_err("content digest mismatch is rejected");
    let rendered = format!("{content_mismatch_error:?} {content_mismatch_error}");
    assert!(
        !rendered.contains("SECRET-APPLIED-CONTENT-MARKER"),
        "applied content plaintext leaked"
    );
    assert!(!rendered.contains(&hex(&receipt)), "receipt bytes leaked");

    let mut tampered = receipt.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    let crypto_error = verify_and_record_applied_receipt(
        &mut receipts,
        b_principal,
        confirmed,
        Some(applied_plaintext),
        &tampered,
    )
    .expect_err("tampered signature is rejected");
    let rendered = format!("{crypto_error:?} {crypto_error}");
    assert!(
        !rendered.contains("SECRET-APPLIED-CONTENT-MARKER"),
        "applied content plaintext leaked"
    );
    assert!(
        !rendered.contains(&hex(&tampered)),
        "tampered receipt bytes leaked"
    );
    assert!(
        !rendered.contains(&hex(&receipt)),
        "original receipt bytes leaked"
    );
}

/// Extracts the sealed payload from an already-prepared SEND frame, so the
/// test can hand it to a scripted `Fetch` response without a live relay.
fn prepared_payload(prepared: &cofferwire_client::PreparedSend) -> cofferwire_types::Payload {
    let decoded = decode_request(prepared.as_bytes()).expect("prepared frame decodes");
    match decoded.frame().request() {
        cofferwire_types::Request::Send(send) => send.payload().clone(),
        _ => panic!("prepared frame is not a SEND request"),
    }
}
