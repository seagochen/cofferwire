import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TRACE_CATALOG = json.loads((ROOT / "vectors" / "queue-v1-traces.json").read_text())
sys.path.insert(0, str(ROOT / "independent" / "python"))

import cofferwire_v1 as cw  # noqa: E402
from cryptography.exceptions import InvalidSignature, InvalidTag  # noqa: E402


class QueueScenario:
    def __init__(self, exchange, restart=None):
        self.client = cw.Client(exchange)
        self.restart = restart
        self.sender_seed = bytes([0x31]) * 32
        self.recipient_seed = bytes([0x32]) * 32
        self.sender = cw.public_key(self.sender_seed)
        self.recipient = cw.public_key(self.recipient_seed)
        self.queue = bytes([0x41]) * 32
        self.message = bytes([0x51]) * 32
        self.second_message = bytes([0x52]) * 32
        self.next_id = 1

    def request_id(self):
        value = self.next_id.to_bytes(16, "big")
        self.next_id += 1
        return value

    def run(self):
        assert [case["id"] for case in TRACE_CATALOG["cases"]] == [
            f"QV1-TRACE-{number:03}" for number in range(1, 9)
        ]
        status, body, _ = self.client.call(
            self.sender_seed,
            self.request_id(),
            cw.CREATE_QUEUE,
            [self.queue, self.sender, self.recipient, 2, 1024],
            1_000,
        )
        assert (status, body) == (cw.OK, [0])
        send_id = self.request_id()
        status, body, frame = self.client.call(
            self.sender_seed,
            send_id,
            cw.SEND,
            [self.queue, self.sender, self.message, b"opaque ciphertext", 60],
            1_000,
        )
        assert (status, body) == (cw.OK, [0])
        status, body, retried = self.client.call(
            self.sender_seed,
            send_id,
            cw.SEND,
            [self.queue, self.sender, self.message, b"opaque ciphertext", 60],
            1_000,
        )
        assert frame == retried and (status, body) == (cw.OK, [0])
        status, body, _ = self.client.call(
            self.sender_seed,
            self.request_id(),
            cw.SEND,
            [self.queue, self.sender, self.second_message, b"second ciphertext", 60],
            1_000,
        )
        assert (status, body) == (cw.OK, [0])
        if self.restart is not None:
            self.restart()
        fetch_id = self.request_id()
        status, first, _ = self.client.call(
            self.recipient_seed,
            fetch_id,
            cw.FETCH,
            [self.queue, self.recipient],
            1_001,
        )
        assert status == cw.OK and first[0] == 1 and first[1] == self.message
        status, redelivery, _ = self.client.call(
            self.recipient_seed,
            self.request_id(),
            cw.FETCH,
            [self.queue, self.recipient],
            1_001,
        )
        assert status == cw.OK and redelivery == first
        status, body, _ = self.client.call(
            self.recipient_seed,
            self.request_id(),
            cw.ACK,
            [self.queue, self.recipient, self.message],
            1_001,
        )
        assert (status, body) == (cw.OK, [])
        status, second, _ = self.client.call(
            self.recipient_seed,
            self.request_id(),
            cw.FETCH,
            [self.queue, self.recipient],
            1_001,
        )
        assert status == cw.OK and second[0] == 1 and second[1] == self.second_message
        status, body, _ = self.client.call(
            self.recipient_seed,
            self.request_id(),
            cw.ACK,
            [self.queue, self.recipient, self.second_message],
            1_001,
        )
        assert (status, body) == (cw.OK, [])
        status, body, _ = self.client.call(
            self.recipient_seed,
            self.request_id(),
            cw.FETCH,
            [self.queue, self.recipient],
            1_001,
        )
        assert (status, body) == (cw.OK, [0])
        status, body, _ = self.client.call(
            self.recipient_seed,
            self.request_id(),
            cw.DELETE_QUEUE,
            [self.queue, self.recipient],
            1_001,
        )
        assert (status, body) == (cw.OK, [])


def run_failure_scenario(exchange):
    sender_seed = bytes([0x61]) * 32
    sender = cw.public_key(sender_seed)
    recipient = cw.public_key(bytes([0x62]) * 32)
    queue = bytes([0x63]) * 32
    request_id = (100).to_bytes(16, "big")
    create = cw.encode_request(
        sender_seed,
        request_id,
        cw.CREATE_QUEUE,
        [queue, sender, recipient, 2, 1024],
    )
    assert cw.decode_response(exchange(create, 1_000))[2:] == (cw.OK, [0])
    conflict = cw.encode_request(
        sender_seed,
        request_id,
        cw.CREATE_QUEUE,
        [queue, sender, recipient, 3, 1024],
    )
    assert cw.decode_response(exchange(conflict, 1_000))[2] == cw.AUTH_REPLAY
    invalid = bytearray(
        cw.encode_request(
            sender_seed,
            (101).to_bytes(16, "big"),
            cw.SEND,
            [queue, sender, bytes([0x64]) * 32, b"opaque", 60],
        )
    )
    invalid[-1] ^= 1
    assert cw.decode_response(exchange(bytes(invalid), 1_000))[2] == cw.AUTH_INVALID
    malformed = b"\x01" + bytes(16) + b"\xff"
    assert cw.decode_response(exchange(malformed, 1_000))[2] == cw.MALFORMED_FRAME
    unsupported = b"\x02" + bytes([0xAA]) * 16 + b"future"
    response = cw.decode_response(exchange(unsupported, 1_000))
    assert response == (bytes([0xAA]) * 16, 0, cw.UNSUPPORTED_VERSION, [])


class IndependentImplementationTests(unittest.TestCase):
    def test_public_codec_and_crypto_vectors(self):
        codec = json.loads((ROOT / "vectors" / "codec-v1.json").read_text())
        request = bytes.fromhex(codec["positive"][0]["frame_hex"])
        decoded = cw.decode_request(request)
        self.assertEqual(cw.encode_request.__module__, "cofferwire_v1")
        self.assertEqual(decoded.encoded, request)
        response = bytes.fromhex(codec["positive"][1]["frame_hex"])
        self.assertEqual(cw.decode_response(response)[1:], (cw.SEND, cw.OK, [0]))
        for negative in codec["negative"]:
            with self.assertRaises(ValueError, msg=negative["name"]):
                cw.Decoder(bytes.fromhex(negative["item_hex"])).item()

        crypto = json.loads((ROOT / "vectors" / "crypto-v1.json").read_text())
        authenticated = bytes.fromhex(crypto["relay_authenticated_bytes_hex"])
        expected_auth = bytes.fromhex(crypto["relay_auth_hex"])
        signature = cw.Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32).sign(
            cw.AUTH_DOMAIN + authenticated
        )
        self.assertEqual(expected_auth, b"\0\1\0\1" + signature)
        verifier = cw.Ed25519PublicKey.from_public_bytes(cw.public_key(bytes([7]) * 32))
        for offset in range(len(authenticated)):
            changed = bytearray(authenticated)
            changed[offset] ^= 1
            with self.assertRaises(InvalidSignature):
                verifier.verify(expected_auth[4:], cw.AUTH_DOMAIN + bytes(changed))
        downgraded = bytearray(expected_auth)
        downgraded[1] = 2
        self.assertNotEqual(downgraded[:4], b"\0\1\0\1")
        plaintext = cw.hpke_open_vector(
            bytes([0x66]) * 32,
            bytes([0x55]) * 32,
            bytes([0x11]) * 32,
            bytes([0x22]) * 32,
            bytes([0x33]) * 32,
            bytes([0x44]) * 32,
            bytes.fromhex(crypto["hpke_payload_hex"]),
        )
        self.assertEqual(plaintext, b"family update")
        hpke_payload = bytes.fromhex(crypto["hpke_payload_hex"])
        for offset in range(len(hpke_payload)):
            changed = bytearray(hpke_payload)
            changed[offset] ^= 1
            with self.assertRaises((ValueError, InvalidTag)):
                cw.hpke_open_vector(
                    bytes([0x66]) * 32,
                    bytes([0x55]) * 32,
                    bytes([0x11]) * 32,
                    bytes([0x22]) * 32,
                    bytes([0x33]) * 32,
                    bytes([0x44]) * 32,
                    bytes(changed),
                )
        for changed_context in [
            (bytes([9]) * 32, bytes([0x22]) * 32, bytes([0x33]) * 32, bytes([0x44]) * 32),
            (bytes([0x11]) * 32, bytes([9]) * 32, bytes([0x33]) * 32, bytes([0x44]) * 32),
            (bytes([0x11]) * 32, bytes([0x22]) * 32, bytes([9]) * 32, bytes([0x44]) * 32),
            (bytes([0x11]) * 32, bytes([0x22]) * 32, bytes([0x33]) * 32, bytes([9]) * 32),
        ]:
            with self.assertRaises(InvalidTag):
                cw.hpke_open_vector(
                    bytes([0x66]) * 32,
                    bytes([0x55]) * 32,
                    *changed_context,
                    hpke_payload,
                )

    def test_independent_client_and_relay_full_lifecycle(self):
        relay = cw.Relay()
        try:
            QueueScenario(relay.exchange).run()
        finally:
            relay.close()

    def test_auth_replay_malformed_and_version_rejection(self):
        relay = cw.Relay()
        try:
            run_failure_scenario(relay.exchange)
        finally:
            relay.close()

    def test_sqlite_state_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "relay.sqlite"
            first = cw.Relay(database)
            scenario = QueueScenario(first.exchange)
            scenario.client.call(
                scenario.sender_seed,
                scenario.request_id(),
                cw.CREATE_QUEUE,
                [scenario.queue, scenario.sender, scenario.recipient, 2, 1024],
                1_000,
            )
            scenario.client.call(
                scenario.sender_seed,
                scenario.request_id(),
                cw.SEND,
                [scenario.queue, scenario.sender, scenario.message, b"durable", 60],
                1_000,
            )
            first.close()
            reopened = cw.Relay(database)
            status, body, _ = cw.Client(reopened.exchange).call(
                scenario.recipient_seed,
                scenario.request_id(),
                cw.FETCH,
                [scenario.queue, scenario.recipient],
                1_001,
            )
            self.assertEqual(status, cw.OK)
            self.assertEqual(body[1:3], [scenario.message, b"durable"])
            reopened.close()


class RustLineRelay:
    def __init__(self):
        self.executable = os.environ.get(
            "COFFERWIRE_RUST_LINE_RELAY",
            str(ROOT / "target" / "debug" / "cofferwire-line-relay"),
        )
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "relay.sqlite"
        self._start()

    def _start(self):
        self.process = subprocess.Popen(
            [self.executable, str(self.database)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )

    def exchange(self, frame, now):
        self.process.stdin.write(f"{now} {frame.hex()}\n")
        self.process.stdin.flush()
        return bytes.fromhex(self.process.stdout.readline().strip())

    def restart(self):
        self.process.stdin.close()
        self.process.wait(timeout=10)
        self.process.stdout.close()
        self._start()

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=10)
        self.process.stdout.close()
        self.temp.cleanup()


@unittest.skipUnless(os.environ.get("COFFERWIRE_MATRIX"), "run by interop matrix")
class CrossImplementationTests(unittest.TestCase):
    def test_independent_client_to_rust_relay(self):
        relay = RustLineRelay()
        try:
            QueueScenario(relay.exchange, relay.restart).run()
            run_failure_scenario(relay.exchange)
        finally:
            relay.close()


if __name__ == "__main__":
    unittest.main()
