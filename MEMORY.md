# Project Memory

This file records stable project facts and accepted architecture decisions. It does not track task status or contain credentials.

## Architecture decisions

- The initial interoperable profile carries small asynchronous messages only; encrypted blob delivery is deferred to a later profile.
- Every receiving device uses an independent receive queue. The relay does not model global users or perform account-level device fan-out.
- Relays are availability services outside the end-to-end trust boundary. They store opaque payloads and are not trusted with plaintext, application authorship or correct delivery history.
- Relay ACK authorizes deletion only after the recipient authenticates and durably stores the application message. Application receipts are separate end-to-end messages.
- Protocol semantics remain independent of HTTPS, WebSocket or any other transport binding.

## Toolchain baseline

- The Rust workspace targets Rust 1.84 with edition 2021.
- `cofferwire-relay` contains both the in-memory reference state machine and the SQLite-backed transactional implementation.
