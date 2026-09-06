"""Independent implementation of the frozen Cofferwire queue-v1 protocol."""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

VERSION = 1
MAX_FRAME_BYTES = 65_536
MAX_AUTH_BYTES = 1_024
MAX_MESSAGE_BYTES = 64_374
AUTH_DOMAIN = b"cofferwire relay request v1\0"
HPKE_INFO_DOMAIN = b"cofferwire hpke info v1\0"
HPKE_AAD_DOMAIN = b"cofferwire hpke aad v1\0"
PROFILE_ID = 1
ED25519_ID = 1
KEM_ID = 0x20
KDF_ID = 1
AEAD_ID = 3

CREATE_QUEUE, SEND, FETCH, ACK, DELETE_QUEUE = range(1, 6)
(
    OK,
    UNSUPPORTED_VERSION,
    MALFORMED_FRAME,
    FRAME_TOO_LARGE,
    UNKNOWN_COMMAND,
    QUEUE_NOT_FOUND,
    UNAUTHORIZED,
    QUEUE_ID_CONFLICT,
    MESSAGE_ID_CONFLICT,
    MESSAGE_TOO_LARGE,
    QUEUE_FULL,
    EXPIRY_OVERFLOW,
    ACK_MISMATCH,
    NOT_DELIVERED,
    AUTH_INVALID,
    LIMIT_OUT_OF_RANGE,
    AUTH_REPLAY,
) = range(17)


class ProtocolError(ValueError):
    """A public protocol failure represented by a stable response status."""

    def __init__(self, status: int):
        super().__init__(f"protocol status {status}")
        self.status = status


def _argument(major: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("unsigned value required")
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + struct.pack(">I", value)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([(major << 5) | 27]) + struct.pack(">Q", value)
    raise ValueError("CBOR integer exceeds uint64")


def cbor(value: int | bytes | Sequence[object]) -> bytes:
    if isinstance(value, int):
        return _argument(0, value)
    if isinstance(value, bytes):
        return _argument(2, len(value)) + value
    if isinstance(value, (list, tuple)):
        return _argument(4, len(value)) + b"".join(cbor(item) for item in value)
    raise TypeError(f"unsupported CBOR value {type(value)!r}")


class Decoder:
    def __init__(self, data: bytes, offset: int = 0):
        self.data = data
        self.offset = offset

    def _head(self, expected_major: int) -> int:
        if self.offset >= len(self.data):
            raise ValueError("truncated CBOR")
        initial = self.data[self.offset]
        self.offset += 1
        major, additional = initial >> 5, initial & 31
        if major != expected_major or additional >= 28:
            raise ValueError("forbidden CBOR type")
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        if additional < 24:
            return additional
        width = widths[additional]
        end = self.offset + width
        if end > len(self.data):
            raise ValueError("truncated CBOR argument")
        value = int.from_bytes(self.data[self.offset:end], "big")
        self.offset = end
        minimum = {1: 24, 2: 256, 4: 65_536, 8: 4_294_967_296}[width]
        if value < minimum:
            raise ValueError("non-canonical CBOR argument")
        return value

    def uint(self) -> int:
        return self._head(0)

    def byte_string(self, maximum: int = MAX_FRAME_BYTES) -> bytes:
        length = self._head(2)
        if length > maximum or self.offset + length > len(self.data):
            raise ValueError("invalid byte string length")
        result = self.data[self.offset : self.offset + length]
        self.offset += length
        return result

    def array(self, length: int | None = None) -> list[object]:
        actual = self._head(4)
        if length is not None and actual != length:
            raise ValueError("wrong array length")
        return [self.item() for _ in range(actual)]

    def item(self) -> object:
        if self.offset >= len(self.data):
            raise ValueError("truncated CBOR item")
        major = self.data[self.offset] >> 5
        if major == 0:
            return self.uint()
        if major == 2:
            return self.byte_string()
        if major == 4:
            return self.array()
        raise ValueError("forbidden CBOR item")


def _id(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("identifier must be 32 bytes")
    return value


def _validate_body(command: int, body: object) -> list[object]:
    if not isinstance(body, list):
        raise ValueError("body must be an array")
    sizes = {CREATE_QUEUE: 5, SEND: 5, FETCH: 2, ACK: 3, DELETE_QUEUE: 2}
    if command not in sizes:
        raise ProtocolError(UNKNOWN_COMMAND)
    if len(body) != sizes[command]:
        raise ValueError("wrong command body length")
    if command == CREATE_QUEUE:
        _id(body[0]); _id(body[1]); _id(body[2])
        if not all(isinstance(item, int) for item in body[3:]):
            raise ValueError("limits must be integers")
    elif command == SEND:
        _id(body[0]); _id(body[1]); _id(body[2])
        if not isinstance(body[3], bytes) or len(body[3]) > MAX_MESSAGE_BYTES:
            raise ValueError("invalid message payload")
        if not isinstance(body[4], int):
            raise ValueError("ttl must be an integer")
    else:
        _id(body[0]); _id(body[1])
        if command == ACK:
            _id(body[2])
    return body


@dataclass(frozen=True)
class RequestFrame:
    request_id: bytes
    command: int
    body: list[object]
    auth: bytes
    authenticated: bytes
    encoded: bytes


def decode_request(frame: bytes) -> RequestFrame:
    if len(frame) > MAX_FRAME_BYTES:
        raise ProtocolError(FRAME_TOO_LARGE)
    if len(frame) < 17:
        raise ValueError("truncated preamble")
    if frame[0] != VERSION:
        raise ProtocolError(UNSUPPORTED_VERSION)
    decoder = Decoder(frame, 17)
    payload = decoder.array(3)
    if payload[0] != 0 or not isinstance(payload[1], int):
        raise ValueError("invalid request discriminator")
    command = payload[1]
    body = _validate_body(command, payload[2])
    authenticated_end = decoder.offset
    auth = decoder.byte_string(MAX_AUTH_BYTES)
    if decoder.offset != len(frame):
        raise ValueError("trailing frame bytes")
    return RequestFrame(
        frame[1:17], command, body, auth, frame[:authenticated_end], frame
    )


def encode_response(request_id: bytes, command: int, status: int, body: list[object]) -> bytes:
    if len(request_id) != 16 or not 0 <= status <= AUTH_REPLAY:
        raise ValueError("invalid response metadata")
    if status != OK and body:
        raise ValueError("error responses have empty bodies")
    return bytes([VERSION]) + request_id + cbor([1, command, status, body])


def decode_response(frame: bytes) -> tuple[bytes, int, int, list[object]]:
    if len(frame) > MAX_FRAME_BYTES or len(frame) < 17 or frame[0] != VERSION:
        raise ValueError("invalid response preamble")
    decoder = Decoder(frame, 17)
    payload = decoder.array(4)
    if decoder.offset != len(frame) or payload[0] != 1:
        raise ValueError("invalid response")
    command, status, body = payload[1:]
    if not isinstance(command, int) or not isinstance(status, int) or not isinstance(body, list):
        raise ValueError("invalid response fields")
    if not 0 <= status <= AUTH_REPLAY or (status != OK and body):
        raise ValueError("invalid response status/body")
    return frame[1:17], command, status, body


def public_key(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def encode_request(seed: bytes, request_id: bytes, command: int, body: list[object]) -> bytes:
    if len(seed) != 32 or len(request_id) != 16:
        raise ValueError("wrong key or request ID length")
    authenticated = bytes([VERSION]) + request_id + cbor([0, command, body])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(AUTH_DOMAIN + authenticated)
    return authenticated + cbor(struct.pack(">HH", PROFILE_ID, ED25519_ID) + signature)


def verify_request(request: RequestFrame, principal: bytes) -> None:
    if len(request.auth) != 68 or request.auth[:4] != struct.pack(">HH", 1, 1):
        raise ProtocolError(AUTH_INVALID)
    try:
        Ed25519PublicKey.from_public_bytes(principal).verify(
            request.auth[4:], AUTH_DOMAIN + request.authenticated
        )
    except (ValueError, TypeError):
        raise ProtocolError(AUTH_INVALID) from None
    except Exception as error:
        raise ProtocolError(AUTH_INVALID) from error


class Client:
    """Raw queue-v1 client whose calls cover every registered command."""

    def __init__(self, exchange: Callable[[bytes, int], bytes]):
        self.exchange = exchange

    def call(
        self,
        seed: bytes,
        request_id: bytes,
        command: int,
        body: list[object],
        now: int,
    ) -> tuple[int, list[object], bytes]:
        frame = encode_request(seed, request_id, command, body)
        response = self.exchange(frame, now)
        echoed, echoed_command, status, response_body = decode_response(response)
        if echoed != request_id or echoed_command != command:
            raise ValueError("response correlation mismatch")
        return status, response_body, frame


class Relay:
    """SQLite-backed independent queue-v1 relay."""

    def __init__(self, database: str | Path = ":memory:"):
        self.connection = sqlite3.connect(str(database), isolation_level=None)
        self.connection.execute("PRAGMA journal_mode=DELETE")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS queues (
              queue BLOB PRIMARY KEY, sender BLOB NOT NULL, recipient BLOB NOT NULL,
              max_messages INTEGER NOT NULL, max_bytes INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT, queue BLOB NOT NULL,
              message BLOB NOT NULL, payload BLOB NOT NULL, expires INTEGER NOT NULL,
              delivered INTEGER NOT NULL DEFAULT 0, UNIQUE(queue, message)
            );
            CREATE TABLE IF NOT EXISTS replays (
              principal BLOB NOT NULL, request_id BLOB NOT NULL, frame BLOB NOT NULL,
              response BLOB NOT NULL, PRIMARY KEY(principal, request_id)
            );
            PRAGMA user_version=1;
            """
        )

    def close(self) -> None:
        self.connection.close()

    def exchange(self, frame: bytes, now: int) -> bytes:
        request_id = frame[1:17] if len(frame) >= 17 else bytes(16)
        if len(frame) >= 17 and frame[0] != VERSION:
            return encode_response(request_id, 0, UNSUPPORTED_VERSION, [])
        try:
            request = decode_request(frame)
            principal = _id(request.body[1])
            verify_request(request, principal)
        except ProtocolError as error:
            command = 0
            try:
                command = request.command  # type: ignore[possibly-undefined]
            except UnboundLocalError:
                pass
            return encode_response(request_id, command, error.status, [])
        except (ValueError, TypeError):
            return encode_response(request_id, 0, MALFORMED_FRAME, [])

        self.connection.execute("BEGIN IMMEDIATE")
        try:
            replay = self.connection.execute(
                "SELECT frame, response FROM replays WHERE principal=? AND request_id=?",
                (principal, request.request_id),
            ).fetchone()
            if replay:
                self.connection.rollback()
                if hmac.compare_digest(replay[0], frame):
                    return replay[1]
                return encode_response(request.request_id, request.command, AUTH_REPLAY, [])
            status, body = self._execute(request, now, principal)
            response = encode_response(request.request_id, request.command, status, body)
            self.connection.execute(
                "INSERT INTO replays(principal, request_id, frame, response) VALUES(?,?,?,?)",
                (principal, request.request_id, frame, response),
            )
            self.connection.commit()
            return response
        except Exception:
            self.connection.rollback()
            raise

    def _queue(self, queue: bytes) -> tuple[bytes, bytes, int, int] | None:
        return self.connection.execute(
            "SELECT sender, recipient, max_messages, max_bytes FROM queues WHERE queue=?",
            (queue,),
        ).fetchone()

    def _prune(self, queue: bytes, now: int) -> None:
        self.connection.execute(
            "DELETE FROM messages WHERE queue=? AND expires<=?", (queue, now)
        )

    def _execute(
        self, request: RequestFrame, now: int, principal: bytes
    ) -> tuple[int, list[object]]:
        body, command = request.body, request.command
        queue = _id(body[0])
        config = self._queue(queue)
        if command == CREATE_QUEUE:
            max_messages, max_bytes = body[3], body[4]
            if max_messages < 1 or max_bytes < 1 or max_bytes > MAX_MESSAGE_BYTES:
                return LIMIT_OUT_OF_RANGE, []
            wanted = (principal, _id(body[2]), max_messages, max_bytes)
            if config is None:
                self.connection.execute(
                    "INSERT INTO queues VALUES(?,?,?,?,?)", (queue, *wanted)
                )
                return OK, [0]
            return (OK, [1]) if config == wanted else (QUEUE_ID_CONFLICT, [])
        if config is None:
            return QUEUE_NOT_FOUND, []
        sender, recipient, max_messages, max_bytes = config
        required = sender if command == SEND else recipient
        if principal != required:
            return UNAUTHORIZED, []
        if command == SEND:
            self._prune(queue, now)
            message, payload, ttl = _id(body[2]), body[3], body[4]
            existing = self.connection.execute(
                "SELECT payload FROM messages WHERE queue=? AND message=?", (queue, message)
            ).fetchone()
            if existing:
                return (OK, [1]) if existing[0] == payload else (MESSAGE_ID_CONFLICT, [])
            if len(payload) > max_bytes:
                return MESSAGE_TOO_LARGE, []
            count = self.connection.execute(
                "SELECT count(*) FROM messages WHERE queue=?", (queue,)
            ).fetchone()[0]
            if count >= max_messages:
                return QUEUE_FULL, []
            if ttl < 1:
                return LIMIT_OUT_OF_RANGE, []
            if now > 0xFFFFFFFFFFFFFFFF - ttl:
                return EXPIRY_OVERFLOW, []
            self.connection.execute(
                "INSERT INTO messages(queue,message,payload,expires) VALUES(?,?,?,?)",
                (queue, message, payload, now + ttl),
            )
            return OK, [0]
        if command == FETCH:
            self._prune(queue, now)
            row = self.connection.execute(
                "SELECT sequence,message,payload,expires FROM messages "
                "WHERE queue=? ORDER BY sequence LIMIT 1",
                (queue,),
            ).fetchone()
            if row is None:
                return OK, [0]
            self.connection.execute(
                "UPDATE messages SET delivered=1 WHERE sequence=?", (row[0],)
            )
            return OK, [1, row[1], row[2], row[3]]
        if command == ACK:
            self._prune(queue, now)
            row = self.connection.execute(
                "SELECT sequence,message,delivered FROM messages "
                "WHERE queue=? ORDER BY sequence LIMIT 1",
                (queue,),
            ).fetchone()
            if row is None or row[1] != _id(body[2]):
                return ACK_MISMATCH, []
            if not row[2]:
                return NOT_DELIVERED, []
            self.connection.execute("DELETE FROM messages WHERE sequence=?", (row[0],))
            return OK, []
        if command == DELETE_QUEUE:
            self.connection.execute("DELETE FROM messages WHERE queue=?", (queue,))
            self.connection.execute("DELETE FROM queues WHERE queue=?", (queue,))
            return OK, []
        return UNKNOWN_COMMAND, []


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


def _labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def _labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled = struct.pack(">H", length) + b"HPKE-v1" + suite + label + info
    return _hkdf_expand(prk, labeled, length)


def _derive_x25519(ikm: bytes) -> X25519PrivateKey:
    suite = b"KEM" + struct.pack(">H", KEM_ID)
    dkp_prk = _labeled_extract(suite, b"", b"dkp_prk", ikm)
    secret = _labeled_expand(suite, dkp_prk, b"sk", b"", 32)
    return X25519PrivateKey.from_private_bytes(secret)


def _raw_public(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _context(domain: bytes, queue: bytes, sender: bytes, recipient: bytes, message: bytes) -> bytes:
    algorithms = struct.pack(">HHHH", PROFILE_ID, KEM_ID, KDF_ID, AEAD_ID)
    return domain + algorithms + queue + sender + recipient + message


def hpke_open_vector(
    recipient_ikm: bytes,
    sender_ikm: bytes,
    queue: bytes,
    sender: bytes,
    recipient: bytes,
    message: bytes,
    payload: bytes,
) -> bytes:
    """Open the fixed RFC 9180 Auth-mode profile used by the public vector."""
    if payload[:8] != struct.pack(">HHHH", PROFILE_ID, KEM_ID, KDF_ID, AEAD_ID):
        raise ValueError("wrong HPKE profile")
    sender_key, recipient_key = _derive_x25519(sender_ikm), _derive_x25519(recipient_ikm)
    enc = payload[8:40]
    enc_public = X25519PublicKey.from_public_bytes(enc)
    dh = recipient_key.exchange(enc_public) + recipient_key.exchange(sender_key.public_key())
    kem_suite = b"KEM" + struct.pack(">H", KEM_ID)
    kem_context = enc + _raw_public(recipient_key) + _raw_public(sender_key)
    eae_prk = _labeled_extract(kem_suite, b"", b"eae_prk", dh)
    shared = _labeled_expand(kem_suite, eae_prk, b"shared_secret", kem_context, 32)
    info = _context(HPKE_INFO_DOMAIN, queue, sender, recipient, message)
    aad = _context(HPKE_AAD_DOMAIN, queue, sender, recipient, message)
    hpke_suite = b"HPKE" + struct.pack(">HHH", KEM_ID, KDF_ID, AEAD_ID)
    psk_hash = _labeled_extract(hpke_suite, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(hpke_suite, b"", b"info_hash", info)
    schedule_context = b"\x02" + psk_hash + info_hash
    secret = _labeled_extract(hpke_suite, shared, b"secret", b"")
    key = _labeled_expand(hpke_suite, secret, b"key", schedule_context, 32)
    nonce = _labeled_expand(hpke_suite, secret, b"base_nonce", schedule_context, 12)
    return ChaCha20Poly1305(key).decrypt(nonce, payload[40:], aad)


def line_relay(database: str) -> int:
    relay = Relay(database)
    try:
        for line in sys.stdin:
            now_text, frame_hex = line.strip().split(" ", 1)
            response = relay.exchange(bytes.fromhex(frame_hex), int(now_text))
            print(response.hex(), flush=True)
    finally:
        relay.close()
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "line-relay":
        raise SystemExit(line_relay(sys.argv[2]))
    raise SystemExit("usage: cofferwire_v1.py line-relay DATABASE")
