use std::{
    cell::RefCell,
    collections::{HashSet, VecDeque},
    rc::Rc,
};

use cofferwire_client::{
    ClientError, CommitOutcome, InboxStore, PollOutcome, Recipient, RequestIdSource,
    SendCompletion, Sender, StoreError, Transport, TransportError,
};
use cofferwire_codec::{decode_request, encode_response, ResponseFrame};
use cofferwire_crypto::{seal_message, EncryptionSecretKey, MessageContext, RelaySigningKey};
use cofferwire_types::{
    Command, Delivery, MessageId, Payload, Principal, QueueId, Request, RequestId, Response,
    ResponseBody, SendOutcome, Timestamp, Ttl,
};
use rand_core::{CryptoRng, Error, RngCore};

const QUEUE: QueueId = QueueId::from_bytes([1; 32]);
const MESSAGE: MessageId = MessageId::from_bytes([4; 32]);

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
    WrongRequestId(Response),
    Fail,
}

struct ScriptedTransport {
    actions: VecDeque<Action>,
    requests: Vec<Vec<u8>>,
    events: Rc<RefCell<Vec<&'static str>>>,
}

impl ScriptedTransport {
    fn new(
        actions: impl IntoIterator<Item = Action>,
        events: Rc<RefCell<Vec<&'static str>>>,
    ) -> Self {
        Self {
            actions: actions.into_iter().collect(),
            requests: Vec::new(),
            events,
        }
    }
}

impl Transport for ScriptedTransport {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let decoded = decode_request(request).expect("client emits valid requests");
        let command = decoded.frame().request().command();
        self.events.borrow_mut().push(match command {
            Command::Send => "send",
            Command::Fetch => "fetch",
            Command::Ack => "ack",
            Command::CreateQueue | Command::DeleteQueue => "other",
        });
        self.requests.push(request.to_vec());
        match self.actions.pop_front().expect("scripted action") {
            Action::Respond(response) => Ok(encode_response(&ResponseFrame::new(
                decoded.frame().request_id(),
                response,
            ))),
            Action::WrongRequestId(response) => Ok(encode_response(&ResponseFrame::new(
                RequestId::from_bytes([0xff; 16]),
                response,
            ))),
            Action::Fail => Err(TransportError),
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
struct StoreState {
    committed: HashSet<MessageId>,
    applications: usize,
}

struct DurableStore {
    state: Rc<RefCell<StoreState>>,
    events: Rc<RefCell<Vec<&'static str>>>,
    fail: bool,
}

impl InboxStore for DurableStore {
    fn commit(
        &mut self,
        message_id: MessageId,
        plaintext: &[u8],
    ) -> Result<CommitOutcome, StoreError> {
        self.events.borrow_mut().push("commit");
        if self.fail {
            return Err(StoreError);
        }
        assert_eq!(plaintext, b"family update");
        let mut state = self.state.borrow_mut();
        if state.committed.insert(message_id) {
            state.applications += 1;
            Ok(CommitOutcome::Applied)
        } else {
            Ok(CommitOutcome::AlreadyCommitted)
        }
    }
}

fn signing_keys() -> (RelaySigningKey, RelaySigningKey) {
    (
        RelaySigningKey::from_seed([2; 32]),
        RelaySigningKey::from_seed([3; 32]),
    )
}

fn encryption_keys() -> (EncryptionSecretKey, EncryptionSecretKey) {
    (
        EncryptionSecretKey::derive(&[5; 32]),
        EncryptionSecretKey::derive(&[6; 32]),
    )
}

fn principals() -> (Principal, Principal) {
    let (sender, recipient) = signing_keys();
    (sender.principal(), recipient.principal())
}

fn recipient() -> Recipient {
    let (sender_signing, recipient_signing) = signing_keys();
    let (sender_encryption, recipient_encryption) = encryption_keys();
    Recipient::new(
        QUEUE,
        sender_signing.principal(),
        recipient_signing.principal(),
        recipient_signing,
        recipient_encryption,
        sender_encryption.public_key(),
    )
    .expect("consistent recipient config")
}

fn delivery() -> Delivery {
    let (sender, recipient) = principals();
    let (sender_encryption, recipient_encryption) = encryption_keys();
    let context = MessageContext {
        queue_id: QUEUE,
        sender,
        recipient,
        message_id: MESSAGE,
    };
    let ciphertext = seal_message(
        &sender_encryption,
        recipient_encryption.public_key(),
        context,
        b"family update",
        &mut TestRng(0),
    )
    .expect("test ciphertext");
    Delivery::new(MESSAGE, ciphertext, Timestamp::from_secs(1000))
}

#[test]
fn send_retry_reuses_exact_message_id_ciphertext_request_id_and_signature() {
    let (sender_signing, recipient_signing) = signing_keys();
    let (sender_encryption, recipient_encryption) = encryption_keys();
    let sender = Sender::new(
        QUEUE,
        sender_signing.principal(),
        recipient_signing.principal(),
        sender_signing,
        sender_encryption,
        recipient_encryption.public_key(),
    )
    .expect("consistent sender config");
    let prepared = sender
        .prepare(
            RequestId::from_bytes([8; 16]),
            MESSAGE,
            b"family update",
            Ttl::from_secs(60),
            &mut TestRng(0),
        )
        .expect("prepare succeeds");
    let restored = sender
        .restore(prepared.as_bytes().to_vec())
        .expect("durable state restores");
    assert_eq!(restored, prepared);

    let events = Rc::new(RefCell::new(Vec::new()));
    let mut disconnected = ScriptedTransport::new([Action::Fail], Rc::clone(&events));
    assert!(matches!(
        sender.send(&prepared, &mut disconnected),
        Err(ClientError::Transport(_))
    ));
    let mut retry = ScriptedTransport::new(
        [Action::Respond(Response::Success(ResponseBody::Send(
            SendOutcome::Duplicate,
        )))],
        events,
    );
    assert_eq!(
        sender.send(&restored, &mut retry).expect("retry response"),
        SendCompletion::Duplicate
    );
    assert_eq!(disconnected.requests, retry.requests);
    let decoded = decode_request(&retry.requests[0]).expect("valid prepared SEND");
    assert!(
        matches!(decoded.frame().request(), Request::Send(send) if send.message_id() == MESSAGE)
    );
}

#[test]
fn crash_after_commit_redelivers_without_duplicate_application_then_acks() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let state = Rc::new(RefCell::new(StoreState::default()));
    let mut store = DurableStore {
        state: Rc::clone(&state),
        events: Rc::clone(&events),
        fail: false,
    };

    let fetch_response = Response::Success(ResponseBody::Fetch(Some(delivery())));
    let mut before_crash = ScriptedTransport::new(
        [Action::Respond(fetch_response.clone()), Action::Fail],
        Rc::clone(&events),
    );
    assert!(matches!(
        recipient().poll(&mut before_crash, &mut store, &mut Ids(1)),
        Err(ClientError::Transport(_))
    ));
    assert_eq!(state.borrow().applications, 1);

    let mut after_restart = ScriptedTransport::new(
        [
            Action::Respond(fetch_response),
            Action::Respond(Response::Success(ResponseBody::Ack)),
        ],
        Rc::clone(&events),
    );
    assert_eq!(
        recipient()
            .poll(&mut after_restart, &mut store, &mut Ids(3))
            .expect("redelivery ACK succeeds"),
        PollOutcome::RedeliveryAcknowledged(MESSAGE)
    );
    assert_eq!(state.borrow().applications, 1);
    assert_eq!(
        events.borrow().as_slice(),
        ["fetch", "commit", "ack", "fetch", "commit", "ack"]
    );
}

#[test]
fn authentication_or_store_failure_never_sends_ack() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let state = Rc::new(RefCell::new(StoreState::default()));
    let mut invalid = delivery();
    let mut changed = invalid.payload().as_bytes().to_vec();
    *changed.last_mut().expect("tag byte") ^= 1;
    invalid = Delivery::new(
        invalid.message_id(),
        Payload::new(changed).expect("bounded"),
        invalid.expires_at(),
    );
    let mut transport = ScriptedTransport::new(
        [Action::Respond(Response::Success(ResponseBody::Fetch(
            Some(invalid),
        )))],
        Rc::clone(&events),
    );
    let mut store = DurableStore {
        state: Rc::clone(&state),
        events: Rc::clone(&events),
        fail: false,
    };
    assert!(matches!(
        recipient().poll(&mut transport, &mut store, &mut Ids(1)),
        Err(ClientError::Crypto(_))
    ));
    assert_eq!(transport.requests.len(), 1);
    assert_eq!(state.borrow().applications, 0);

    let mut transport = ScriptedTransport::new(
        [Action::Respond(Response::Success(ResponseBody::Fetch(
            Some(delivery()),
        )))],
        Rc::clone(&events),
    );
    store.fail = true;
    assert!(matches!(
        recipient().poll(&mut transport, &mut store, &mut Ids(3)),
        Err(ClientError::Store(_))
    ));
    assert_eq!(transport.requests.len(), 1);
    assert_eq!(state.borrow().applications, 0);
}

#[test]
fn empty_expired_disconnect_and_out_of_order_paths_are_deterministic() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let state = Rc::new(RefCell::new(StoreState::default()));
    let mut store = DurableStore {
        state,
        events: Rc::clone(&events),
        fail: false,
    };

    let mut empty = ScriptedTransport::new(
        [Action::Respond(Response::Success(ResponseBody::Fetch(
            None,
        )))],
        Rc::clone(&events),
    );
    assert_eq!(
        recipient()
            .poll(&mut empty, &mut store, &mut Ids(1))
            .expect("empty queue"),
        PollOutcome::Empty
    );

    let mut disconnected = ScriptedTransport::new([Action::Fail], Rc::clone(&events));
    assert!(matches!(
        recipient().poll(&mut disconnected, &mut store, &mut Ids(2)),
        Err(ClientError::Transport(_))
    ));

    let mut reordered = ScriptedTransport::new(
        [Action::WrongRequestId(Response::Success(
            ResponseBody::Fetch(None),
        ))],
        events,
    );
    assert!(matches!(
        recipient().poll(&mut reordered, &mut store, &mut Ids(3)),
        Err(ClientError::ResponseRequestIdMismatch)
    ));
}
