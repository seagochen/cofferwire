//! Strict canonical codec for the independent `cofferwire-blob/1` profile.

use crate::cbor::{encode_array, encode_bytes, encode_unsigned, Decoder};
use crate::DecodeError;
use cofferwire_types::blob::{
    BlobCapabilities, BlobCommand, BlobId, BlobManifest, BlobRequest, BlobRequestFrame,
    BlobResponse, BlobResponseBody, BlobResponseFrame, BlobStatus, CapabilityId, UploadId,
    MAX_BLOB_FRAME_BYTES, MAX_CHUNK_BYTES,
};
use cofferwire_types::{Auth, RequestId};

const PREAMBLE_BYTES: usize = 17;

/// A decoded request and the exact bytes covered by its proof.
#[derive(Debug)]
pub struct DecodedBlobRequest<'a> {
    /// Owned semantic frame.
    pub frame: BlobRequestFrame,
    /// Exact `preamble || payload`, excluding auth.
    pub authenticated_bytes: &'a [u8],
}

/// Encodes the bytes authenticated by a blob request proof.
#[must_use]
pub fn encode_blob_authenticated_request(request_id: RequestId, request: &BlobRequest) -> Vec<u8> {
    let mut output = Vec::with_capacity(256);
    output.push(1);
    output.extend_from_slice(request_id.as_bytes());
    encode_array(&mut output, 3);
    encode_unsigned(&mut output, 0);
    encode_unsigned(&mut output, u64::from(request.command().as_u8()));
    encode_request_body(&mut output, request);
    output
}

/// Encodes a complete blob request.
#[must_use]
pub fn encode_blob_request(frame: &BlobRequestFrame) -> Vec<u8> {
    let mut output = encode_blob_authenticated_request(frame.request_id, &frame.request);
    encode_bytes(&mut output, frame.auth.as_bytes());
    output
}

/// Decodes a complete canonical blob request.
///
/// # Errors
///
/// Rejects unsupported versions, non-canonical CBOR, invalid limits, and trailing bytes.
pub fn decode_blob_request(bytes: &[u8]) -> Result<DecodedBlobRequest<'_>, DecodeError> {
    let request_id = preamble(bytes)?;
    let mut decoder = Decoder::new(bytes, PREAMBLE_BYTES);
    decoder.array("blob request payload", 3)?;
    expect(&mut decoder, "blob request direction", 0)?;
    let command_value = decoder.unsigned("blob command")?;
    let command = u8::try_from(command_value)
        .ok()
        .and_then(|value| BlobCommand::try_from(value).ok())
        .ok_or(DecodeError::InvalidValue {
            field: "blob command",
            value: command_value,
        })?;
    let request = decode_request_body(&mut decoder, command)?;
    let authenticated_end = decoder.offset();
    let auth_bytes = decoder.bytes("blob auth", 68)?;
    if auth_bytes.len() != 68 {
        return Err(DecodeError::WrongByteStringLength {
            field: "blob auth",
            expected: 68,
            actual: auth_bytes.len() as u64,
        });
    }
    let auth = Auth::new(auth_bytes.to_vec())?;
    finish(&decoder, bytes)?;
    Ok(DecodedBlobRequest {
        frame: BlobRequestFrame {
            request_id,
            request,
            auth,
        },
        authenticated_bytes: &bytes[..authenticated_end],
    })
}

/// Encodes a complete blob response.
#[must_use]
pub fn encode_blob_response(frame: &BlobResponseFrame) -> Vec<u8> {
    let mut output = Vec::with_capacity(256);
    output.push(1);
    output.extend_from_slice(frame.request_id.as_bytes());
    encode_array(&mut output, 4);
    encode_unsigned(&mut output, 1);
    encode_unsigned(
        &mut output,
        frame
            .response
            .command
            .map_or(0, |command| u64::from(command.as_u8())),
    );
    encode_unsigned(&mut output, u64::from(frame.response.status.as_u8()));
    match &frame.response.body {
        Some(body) if frame.response.status.is_ok() => encode_response_body(&mut output, body),
        _ => encode_array(&mut output, 0),
    }
    output
}

/// Decodes a complete canonical blob response.
///
/// # Errors
///
/// Rejects unknown statuses, response-shape mismatches, and trailing bytes.
pub fn decode_blob_response(bytes: &[u8]) -> Result<BlobResponseFrame, DecodeError> {
    let request_id = preamble(bytes)?;
    let mut decoder = Decoder::new(bytes, PREAMBLE_BYTES);
    decoder.array("blob response payload", 4)?;
    expect(&mut decoder, "blob response direction", 1)?;
    let command_value = decoder.unsigned("blob response command")?;
    let command = if command_value == 0 {
        None
    } else {
        Some(command(command_value)?)
    };
    let status_value = decoder.unsigned("blob status")?;
    let status = u8::try_from(status_value)
        .ok()
        .and_then(|value| BlobStatus::try_from(value).ok())
        .ok_or(DecodeError::InvalidValue {
            field: "blob status",
            value: status_value,
        })?;
    let body = if status.is_ok() {
        let command = command.ok_or(DecodeError::InvalidValue {
            field: "blob response command",
            value: 0,
        })?;
        Some(decode_response_body(&mut decoder, command)?)
    } else {
        decoder.array("blob error body", 0)?;
        None
    };
    finish(&decoder, bytes)?;
    Ok(BlobResponseFrame {
        request_id,
        response: BlobResponse {
            command,
            status,
            body,
        },
    })
}

fn preamble(bytes: &[u8]) -> Result<RequestId, DecodeError> {
    if bytes.len() > MAX_BLOB_FRAME_BYTES {
        return Err(DecodeError::FrameTooLarge {
            actual: bytes.len(),
        });
    }
    let preamble = bytes.get(..PREAMBLE_BYTES).ok_or(DecodeError::Truncated {
        offset: bytes.len(),
    })?;
    if preamble[0] == 0 {
        return Err(DecodeError::ReservedVersion);
    }
    let mut id = [0; 16];
    id.copy_from_slice(&preamble[1..]);
    let request_id = RequestId::from_bytes(id);
    if preamble[0] != 1 {
        return Err(DecodeError::UnsupportedVersion {
            version: preamble[0],
            request_id,
        });
    }
    Ok(request_id)
}

fn finish(decoder: &Decoder<'_>, bytes: &[u8]) -> Result<(), DecodeError> {
    if decoder.offset() == bytes.len() {
        Ok(())
    } else {
        Err(DecodeError::TrailingBytes {
            offset: decoder.offset(),
        })
    }
}

fn expect(
    decoder: &mut Decoder<'_>,
    field: &'static str,
    expected: u64,
) -> Result<(), DecodeError> {
    let value = decoder.unsigned(field)?;
    if value == expected {
        Ok(())
    } else {
        Err(DecodeError::InvalidValue { field, value })
    }
}

fn fixed<const N: usize>(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<[u8; N], DecodeError> {
    let value = decoder.bytes(field, N)?;
    value
        .try_into()
        .map_err(|_| DecodeError::WrongByteStringLength {
            field,
            expected: N,
            actual: value.len() as u64,
        })
}

fn command(value: u64) -> Result<BlobCommand, DecodeError> {
    u8::try_from(value)
        .ok()
        .and_then(|value| BlobCommand::try_from(value).ok())
        .ok_or(DecodeError::InvalidValue {
            field: "blob command",
            value,
        })
}

fn decode_request_body(
    decoder: &mut Decoder<'_>,
    command: BlobCommand,
) -> Result<BlobRequest, DecodeError> {
    Ok(match command {
        BlobCommand::BeginUpload => {
            decoder.array("BEGIN_UPLOAD body", 7)?;
            let upload_id = UploadId::from_bytes(fixed(decoder, "upload-id")?);
            let capabilities = BlobCapabilities {
                upload: CapabilityId::from_bytes(fixed(decoder, "upload-cap")?),
                download: CapabilityId::from_bytes(fixed(decoder, "download-cap")?),
                renew: CapabilityId::from_bytes(fixed(decoder, "renew-cap")?),
                delete: CapabilityId::from_bytes(fixed(decoder, "delete-cap")?),
            };
            let manifest = BlobManifest::parse(decoder.bytes("manifest", 1_048_616)?.to_vec())
                .map_err(|_| DecodeError::InvalidValue {
                    field: "manifest",
                    value: 0,
                })?;
            let ttl = decoder.unsigned("blob ttl")?;
            if ttl == 0 {
                return Err(DecodeError::InvalidValue {
                    field: "blob ttl",
                    value: 0,
                });
            }
            BlobRequest::BeginUpload {
                upload_id,
                capabilities,
                manifest,
                ttl,
            }
        }
        BlobCommand::PutChunk => {
            decoder.array("PUT_CHUNK body", 4)?;
            BlobRequest::PutChunk {
                upload_id: UploadId::from_bytes(fixed(decoder, "upload-id")?),
                upload_cap: CapabilityId::from_bytes(fixed(decoder, "upload-cap")?),
                index: u32::try_from(decoder.unsigned("chunk-index")?).map_err(|_| {
                    DecodeError::InvalidValue {
                        field: "chunk-index",
                        value: u64::MAX,
                    }
                })?,
                ciphertext: decoder
                    .bytes("ciphertext chunk", MAX_CHUNK_BYTES + 16)?
                    .to_vec(),
            }
        }
        BlobCommand::Commit => {
            decoder.array("COMMIT body", 3)?;
            BlobRequest::Commit {
                upload_id: UploadId::from_bytes(fixed(decoder, "upload-id")?),
                upload_cap: CapabilityId::from_bytes(fixed(decoder, "upload-cap")?),
                blob_id: BlobId::from_bytes(fixed(decoder, "blob-id")?),
            }
        }
        BlobCommand::GetManifest => {
            decoder.array("GET_MANIFEST body", 2)?;
            BlobRequest::GetManifest {
                blob_id: BlobId::from_bytes(fixed(decoder, "blob-id")?),
                download_cap: CapabilityId::from_bytes(fixed(decoder, "download-cap")?),
            }
        }
        BlobCommand::GetChunk => {
            decoder.array("GET_CHUNK body", 3)?;
            BlobRequest::GetChunk {
                blob_id: BlobId::from_bytes(fixed(decoder, "blob-id")?),
                download_cap: CapabilityId::from_bytes(fixed(decoder, "download-cap")?),
                index: u32::try_from(decoder.unsigned("chunk-index")?).map_err(|_| {
                    DecodeError::InvalidValue {
                        field: "chunk-index",
                        value: u64::MAX,
                    }
                })?,
            }
        }
        BlobCommand::Renew => {
            decoder.array("RENEW body", 3)?;
            let blob_id = BlobId::from_bytes(fixed(decoder, "blob-id")?);
            let renew_cap = CapabilityId::from_bytes(fixed(decoder, "renew-cap")?);
            let ttl = decoder.unsigned("blob ttl")?;
            if ttl == 0 {
                return Err(DecodeError::InvalidValue {
                    field: "blob ttl",
                    value: 0,
                });
            }
            BlobRequest::Renew {
                blob_id,
                renew_cap,
                ttl,
            }
        }
        BlobCommand::Delete => {
            decoder.array("DELETE body", 2)?;
            BlobRequest::Delete {
                blob_id: BlobId::from_bytes(fixed(decoder, "blob-id")?),
                delete_cap: CapabilityId::from_bytes(fixed(decoder, "delete-cap")?),
            }
        }
    })
}

fn decode_response_body(
    decoder: &mut Decoder<'_>,
    command: BlobCommand,
) -> Result<BlobResponseBody, DecodeError> {
    Ok(match command {
        BlobCommand::BeginUpload => {
            decoder.array("BEGIN_UPLOAD response", 1)?;
            BlobResponseBody::BeginUpload(outcome(decoder)?)
        }
        BlobCommand::PutChunk => {
            decoder.array("PUT_CHUNK response", 1)?;
            BlobResponseBody::PutChunk(outcome(decoder)?)
        }
        BlobCommand::Commit => {
            decoder.array("COMMIT response", 1)?;
            BlobResponseBody::Commit(decoder.unsigned("expires-at")?)
        }
        BlobCommand::GetManifest => {
            decoder.array("GET_MANIFEST response", 2)?;
            let manifest = BlobManifest::parse(decoder.bytes("manifest", 1_048_616)?.to_vec())
                .map_err(|_| DecodeError::InvalidValue {
                    field: "manifest",
                    value: 0,
                })?;
            BlobResponseBody::GetManifest(manifest, decoder.unsigned("expires-at")?)
        }
        BlobCommand::GetChunk => {
            decoder.array("GET_CHUNK response", 2)?;
            let chunk = decoder
                .bytes("ciphertext chunk", MAX_CHUNK_BYTES + 16)?
                .to_vec();
            BlobResponseBody::GetChunk(chunk, decoder.unsigned("expires-at")?)
        }
        BlobCommand::Renew => {
            decoder.array("RENEW response", 1)?;
            BlobResponseBody::Renew(decoder.unsigned("expires-at")?)
        }
        BlobCommand::Delete => {
            decoder.array("DELETE response", 0)?;
            BlobResponseBody::Delete
        }
    })
}

fn outcome(decoder: &mut Decoder<'_>) -> Result<u8, DecodeError> {
    let value = decoder.unsigned("blob outcome")?;
    if value <= 1 {
        u8::try_from(value).map_err(|_| DecodeError::InvalidValue {
            field: "blob outcome",
            value,
        })
    } else {
        Err(DecodeError::InvalidValue {
            field: "blob outcome",
            value,
        })
    }
}

fn encode_request_body(output: &mut Vec<u8>, request: &BlobRequest) {
    match request {
        BlobRequest::BeginUpload {
            upload_id,
            capabilities,
            manifest,
            ttl,
        } => {
            encode_array(output, 7);
            encode_bytes(output, upload_id.as_bytes());
            encode_bytes(output, capabilities.upload.as_bytes());
            encode_bytes(output, capabilities.download.as_bytes());
            encode_bytes(output, capabilities.renew.as_bytes());
            encode_bytes(output, capabilities.delete.as_bytes());
            encode_bytes(output, manifest.as_bytes());
            encode_unsigned(output, *ttl);
        }
        BlobRequest::PutChunk {
            upload_id,
            upload_cap,
            index,
            ciphertext,
        } => {
            encode_array(output, 4);
            encode_bytes(output, upload_id.as_bytes());
            encode_bytes(output, upload_cap.as_bytes());
            encode_unsigned(output, u64::from(*index));
            encode_bytes(output, ciphertext);
        }
        BlobRequest::Commit {
            upload_id,
            upload_cap,
            blob_id,
        } => {
            encode_array(output, 3);
            encode_bytes(output, upload_id.as_bytes());
            encode_bytes(output, upload_cap.as_bytes());
            encode_bytes(output, blob_id.as_bytes());
        }
        BlobRequest::GetManifest {
            blob_id,
            download_cap,
        } => {
            encode_array(output, 2);
            encode_bytes(output, blob_id.as_bytes());
            encode_bytes(output, download_cap.as_bytes());
        }
        BlobRequest::GetChunk {
            blob_id,
            download_cap,
            index,
        } => {
            encode_array(output, 3);
            encode_bytes(output, blob_id.as_bytes());
            encode_bytes(output, download_cap.as_bytes());
            encode_unsigned(output, u64::from(*index));
        }
        BlobRequest::Renew {
            blob_id,
            renew_cap,
            ttl,
        } => {
            encode_array(output, 3);
            encode_bytes(output, blob_id.as_bytes());
            encode_bytes(output, renew_cap.as_bytes());
            encode_unsigned(output, *ttl);
        }
        BlobRequest::Delete {
            blob_id,
            delete_cap,
        } => {
            encode_array(output, 2);
            encode_bytes(output, blob_id.as_bytes());
            encode_bytes(output, delete_cap.as_bytes());
        }
    }
}

fn encode_response_body(output: &mut Vec<u8>, body: &BlobResponseBody) {
    match body {
        BlobResponseBody::BeginUpload(value) | BlobResponseBody::PutChunk(value) => {
            encode_array(output, 1);
            encode_unsigned(output, u64::from(*value));
        }
        BlobResponseBody::Commit(expiry) | BlobResponseBody::Renew(expiry) => {
            encode_array(output, 1);
            encode_unsigned(output, *expiry);
        }
        BlobResponseBody::GetManifest(manifest, expiry) => {
            encode_array(output, 2);
            encode_bytes(output, manifest.as_bytes());
            encode_unsigned(output, *expiry);
        }
        BlobResponseBody::GetChunk(chunk, expiry) => {
            encode_array(output, 2);
            encode_bytes(output, chunk);
            encode_unsigned(output, *expiry);
        }
        BlobResponseBody::Delete => encode_array(output, 0),
    }
}
