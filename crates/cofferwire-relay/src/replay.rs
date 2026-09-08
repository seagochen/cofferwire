//! Shared atomic request-replay transaction machinery.

use cofferwire_types::RequestId;
use rusqlite::{
    params, Connection, ErrorCode, OptionalExtension, Transaction, TransactionBehavior,
};

use crate::durable::{commit, DurableRelayError};
use crate::StorageErrorKind;

/// Exact request and response bytes retained for deterministic replay.
pub type ReplayRecord = (Vec<u8>, Vec<u8>);

/// Outcome of a replay-checked durable command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayExchange {
    /// Response bytes to return, freshly produced or replayed.
    Respond(Vec<u8>),
    /// The request identifier was reused with different request bytes.
    Conflict,
}

#[derive(Clone, Copy)]
pub(crate) enum Namespace {
    Queue,
    Blob,
}

impl Namespace {
    const fn select(self) -> &'static str {
        match self {
            Self::Queue => {
                "SELECT request,response FROM queue_replays WHERE principal=?1 AND request_id=?2"
            }
            Self::Blob => {
                "SELECT request,response FROM blob_replays WHERE capability_id=?1 AND request_id=?2"
            }
        }
    }

    const fn insert(self) -> &'static str {
        match self {
            Self::Queue => {
                "INSERT INTO queue_replays(principal,request_id,request,response) VALUES(?1,?2,?3,?4)"
            }
            Self::Blob => {
                "INSERT INTO blob_replays(capability_id,request_id,request,response) VALUES(?1,?2,?3,?4)"
            }
        }
    }
}

pub(crate) enum EffectError<E> {
    Protocol(E),
    Storage(DurableRelayError),
}

pub(crate) fn lookup(
    connection: &Connection,
    namespace: Namespace,
    subject: &[u8; 32],
    request_id: RequestId,
) -> Result<Option<ReplayRecord>, DurableRelayError> {
    connection
        .query_row(
            namespace.select(),
            params![subject.as_slice(), request_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(DurableRelayError::from)
}

pub(crate) fn exchange<T, E>(
    connection: &mut Connection,
    namespace: Namespace,
    subject: &[u8; 32],
    request_id: RequestId,
    request: &[u8],
    effect: impl FnOnce(&Transaction<'_>) -> Result<T, EffectError<E>>,
    encode: impl FnOnce(Result<T, E>) -> Vec<u8>,
) -> Result<ReplayExchange, DurableRelayError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (response, committed_effect) = match effect(&transaction) {
        Ok(value) => (encode(Ok(value)), true),
        Err(EffectError::Protocol(error)) => (encode(Err(error)), false),
        Err(EffectError::Storage(error)) => return Err(error),
    };
    let transaction = if committed_effect {
        transaction
    } else {
        drop(transaction);
        connection.transaction_with_behavior(TransactionBehavior::Immediate)?
    };
    if insert(
        &transaction,
        namespace,
        subject,
        request_id,
        request,
        &response,
    )? {
        commit(transaction)?;
        return Ok(ReplayExchange::Respond(response));
    }
    drop(transaction);
    match lookup(connection, namespace, subject, request_id)? {
        Some((stored_request, stored_response)) if stored_request == request => {
            Ok(ReplayExchange::Respond(stored_response))
        }
        Some(_) => Ok(ReplayExchange::Conflict),
        None => Err(DurableRelayError::Storage {
            kind: StorageErrorKind::Other,
            source: rusqlite::Error::InvalidParameterName(
                "replay insert conflicted without a stored record".to_owned(),
            ),
        }),
    }
}

fn insert(
    transaction: &Transaction<'_>,
    namespace: Namespace,
    subject: &[u8; 32],
    request_id: RequestId,
    request: &[u8],
    response: &[u8],
) -> Result<bool, DurableRelayError> {
    match transaction.execute(
        namespace.insert(),
        params![
            subject.as_slice(),
            request_id.as_bytes().as_slice(),
            request,
            response
        ],
    ) {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::SqliteFailure(failure, _))
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}
