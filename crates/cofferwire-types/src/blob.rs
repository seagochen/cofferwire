//! Transport-independent types for the `cofferwire-blob/1` profile.

use crate::{Auth, RequestId};

/// Maximum encoded blob frame size.
pub const MAX_BLOB_FRAME_BYTES: usize = 1_049_600;
/// Smallest encrypted plaintext chunk.
pub const MIN_CHUNK_BYTES: usize = 32;
/// Largest encrypted plaintext chunk.
pub const MAX_CHUNK_BYTES: usize = 1_048_576;
/// Largest number of chunks in one manifest.
pub const MAX_CHUNKS: usize = 32_768;
/// Smallest padded plaintext size.
pub const MIN_PADDED_BYTES: u64 = 64;
/// Largest padded plaintext size.
pub const MAX_PADDED_BYTES: u64 = 1_073_741_824;

macro_rules! blob_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Constructs the identifier from its wire bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            /// Returns the exact wire bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

blob_id!(
    UploadId,
    "A fresh identifier for uncommitted staging state."
);
blob_id!(
    BlobId,
    "The SHA-256 identity of an immutable ciphertext manifest."
);
blob_id!(
    CapabilityId,
    "An Ed25519 public key authorizing one blob operation role."
);

/// A validated canonical blob manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobManifest {
    bytes: Vec<u8>,
    object_salt: [u8; 16],
    padded_size: u64,
    chunk_size: u32,
    digests: Vec<[u8; 32]>,
}

/// Why a manifest cannot represent a blob/1 object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobTypeError {
    /// The fixed header, registered identifiers, or exact length is invalid.
    InvalidManifest,
    /// One of the cross-field size limits is invalid.
    LimitOutOfRange,
}

impl std::fmt::Display for BlobTypeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidManifest => formatter.write_str("invalid blob manifest"),
            Self::LimitOutOfRange => formatter.write_str("blob limit out of range"),
        }
    }
}

impl std::error::Error for BlobTypeError {}

impl BlobManifest {
    /// Parses the fixed binary manifest and validates every limit equation.
    ///
    /// # Errors
    ///
    /// Returns a stable structural or limit error before retaining the bytes.
    pub fn parse(bytes: Vec<u8>) -> Result<Self, BlobTypeError> {
        if bytes.len() < 72 || &bytes[..4] != b"CWB1" {
            return Err(BlobTypeError::InvalidManifest);
        }
        let profile = u16::from_be_bytes([bytes[4], bytes[5]]);
        let suite = u16::from_be_bytes([bytes[6], bytes[7]]);
        if profile != 1 || suite != 1 {
            return Err(BlobTypeError::InvalidManifest);
        }
        let mut object_salt = [0; 16];
        object_salt.copy_from_slice(&bytes[8..24]);
        let padded_size = u64::from_be_bytes(
            bytes
                .get(24..32)
                .and_then(|value| value.try_into().ok())
                .ok_or(BlobTypeError::InvalidManifest)?,
        );
        let chunk_size = u32::from_be_bytes(
            bytes
                .get(32..36)
                .and_then(|value| value.try_into().ok())
                .ok_or(BlobTypeError::InvalidManifest)?,
        );
        let chunk_count = u32::from_be_bytes(
            bytes
                .get(36..40)
                .and_then(|value| value.try_into().ok())
                .ok_or(BlobTypeError::InvalidManifest)?,
        );
        let chunk_size_usize = chunk_size as usize;
        let chunk_count_usize = chunk_count as usize;
        let limits_valid = (MIN_CHUNK_BYTES..=MAX_CHUNK_BYTES).contains(&chunk_size_usize)
            && chunk_size.is_power_of_two()
            && (MIN_PADDED_BYTES..=MAX_PADDED_BYTES).contains(&padded_size)
            && padded_size.is_power_of_two()
            && padded_size % u64::from(chunk_size) == 0
            && chunk_count_usize > 0
            && chunk_count_usize <= MAX_CHUNKS
            && padded_size / u64::from(chunk_size) == u64::from(chunk_count);
        if !limits_valid {
            return Err(BlobTypeError::LimitOutOfRange);
        }
        let expected = 40_usize
            .checked_add(
                chunk_count_usize
                    .checked_mul(32)
                    .ok_or(BlobTypeError::LimitOutOfRange)?,
            )
            .ok_or(BlobTypeError::LimitOutOfRange)?;
        if bytes.len() != expected {
            return Err(BlobTypeError::InvalidManifest);
        }
        let digests = bytes[40..]
            .chunks_exact(32)
            .map(|digest| {
                digest
                    .try_into()
                    .map_err(|_| BlobTypeError::InvalidManifest)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            bytes,
            object_salt,
            padded_size,
            chunk_size,
            digests,
        })
    }

    /// Returns the exact canonical manifest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Returns the public object salt.
    #[must_use]
    pub const fn object_salt(&self) -> &[u8; 16] {
        &self.object_salt
    }
    /// Returns the padded plaintext size.
    #[must_use]
    pub const fn padded_size(&self) -> u64 {
        self.padded_size
    }
    /// Returns the plaintext chunk size.
    #[must_use]
    pub const fn chunk_size(&self) -> u32 {
        self.chunk_size
    }
    /// Returns the expected number of chunks.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.digests.len()
    }
    /// Returns the ciphertext digest for `index`.
    #[must_use]
    pub fn digest(&self, index: usize) -> Option<&[u8; 32]> {
        self.digests.get(index)
    }
}

/// Blob command registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BlobCommand {
    BeginUpload = 1,
    PutChunk = 2,
    Commit = 3,
    GetManifest = 4,
    GetChunk = 5,
    Renew = 6,
    Delete = 7,
}

impl BlobCommand {
    /// Returns the registered wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for BlobCommand {
    type Error = BlobTypeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::BeginUpload),
            2 => Ok(Self::PutChunk),
            3 => Ok(Self::Commit),
            4 => Ok(Self::GetManifest),
            5 => Ok(Self::GetChunk),
            6 => Ok(Self::Renew),
            7 => Ok(Self::Delete),
            _ => Err(BlobTypeError::InvalidManifest),
        }
    }
}

/// Blob status registry, independent of queue v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BlobStatus {
    Ok = 0,
    UnsupportedVersion = 1,
    MalformedFrame = 2,
    FrameTooLarge = 3,
    UnknownCommand = 4,
    NotFound = 5,
    Unauthorized = 6,
    IdConflict = 7,
    LimitOutOfRange = 8,
    ChunkConflict = 9,
    Incomplete = 10,
    IdentityMismatch = 11,
    Expired = 12,
    AuthInvalid = 13,
    AuthReplay = 14,
}

impl BlobStatus {
    /// Returns the registered wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
    /// Whether this status represents success.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

impl TryFrom<u8> for BlobStatus {
    type Error = BlobTypeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::UnsupportedVersion),
            2 => Ok(Self::MalformedFrame),
            3 => Ok(Self::FrameTooLarge),
            4 => Ok(Self::UnknownCommand),
            5 => Ok(Self::NotFound),
            6 => Ok(Self::Unauthorized),
            7 => Ok(Self::IdConflict),
            8 => Ok(Self::LimitOutOfRange),
            9 => Ok(Self::ChunkConflict),
            10 => Ok(Self::Incomplete),
            11 => Ok(Self::IdentityMismatch),
            12 => Ok(Self::Expired),
            13 => Ok(Self::AuthInvalid),
            14 => Ok(Self::AuthReplay),
            _ => Err(BlobTypeError::InvalidManifest),
        }
    }
}

/// Four role-separated public capabilities for one availability grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobCapabilities {
    pub upload: CapabilityId,
    pub download: CapabilityId,
    pub renew: CapabilityId,
    pub delete: CapabilityId,
}

/// A blob/1 request body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobRequest {
    BeginUpload {
        upload_id: UploadId,
        capabilities: BlobCapabilities,
        manifest: BlobManifest,
        ttl: u64,
    },
    PutChunk {
        upload_id: UploadId,
        upload_cap: CapabilityId,
        index: u32,
        ciphertext: Vec<u8>,
    },
    Commit {
        upload_id: UploadId,
        upload_cap: CapabilityId,
        blob_id: BlobId,
    },
    GetManifest {
        blob_id: BlobId,
        download_cap: CapabilityId,
    },
    GetChunk {
        blob_id: BlobId,
        download_cap: CapabilityId,
        index: u32,
    },
    Renew {
        blob_id: BlobId,
        renew_cap: CapabilityId,
        ttl: u64,
    },
    Delete {
        blob_id: BlobId,
        delete_cap: CapabilityId,
    },
}

impl BlobRequest {
    /// Returns the request's command.
    #[must_use]
    pub const fn command(&self) -> BlobCommand {
        match self {
            Self::BeginUpload { .. } => BlobCommand::BeginUpload,
            Self::PutChunk { .. } => BlobCommand::PutChunk,
            Self::Commit { .. } => BlobCommand::Commit,
            Self::GetManifest { .. } => BlobCommand::GetManifest,
            Self::GetChunk { .. } => BlobCommand::GetChunk,
            Self::Renew { .. } => BlobCommand::Renew,
            Self::Delete { .. } => BlobCommand::Delete,
        }
    }
    /// Returns the capability that must verify the request proof.
    #[must_use]
    pub const fn capability(&self) -> CapabilityId {
        match self {
            Self::BeginUpload { capabilities, .. } => capabilities.upload,
            Self::PutChunk { upload_cap, .. } | Self::Commit { upload_cap, .. } => *upload_cap,
            Self::GetManifest { download_cap, .. } | Self::GetChunk { download_cap, .. } => {
                *download_cap
            }
            Self::Renew { renew_cap, .. } => *renew_cap,
            Self::Delete { delete_cap, .. } => *delete_cap,
        }
    }
}

/// An authenticated blob request frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobRequestFrame {
    pub request_id: RequestId,
    pub request: BlobRequest,
    pub auth: Auth,
}

/// Result of an idempotent blob staging write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobWriteOutcome {
    /// New staging state or ciphertext was stored.
    Stored,
    /// The exact same state or ciphertext was already stored.
    Duplicate,
}

impl BlobWriteOutcome {
    /// Returns the registered wire outcome.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Stored => 0,
            Self::Duplicate => 1,
        }
    }
}

impl TryFrom<u8> for BlobWriteOutcome {
    type Error = BlobTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Stored),
            1 => Ok(Self::Duplicate),
            _ => Err(BlobTypeError::InvalidManifest),
        }
    }
}

/// Successful blob response bodies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobResponseBody {
    BeginUpload(BlobWriteOutcome),
    PutChunk(BlobWriteOutcome),
    Commit(u64),
    GetManifest(BlobManifest, u64),
    GetChunk(Vec<u8>, u64),
    Renew(u64),
    Delete,
}

/// A blob response including command/status correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobResponse {
    pub command: Option<BlobCommand>,
    pub status: BlobStatus,
    pub body: Option<BlobResponseBody>,
}

/// A complete blob response frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobResponseFrame {
    pub request_id: RequestId,
    pub response: BlobResponse,
}
