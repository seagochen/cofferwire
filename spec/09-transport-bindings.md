# Transport Bindings (Draft)

This document binds the transport-independent v1 envelope to the reference
network daemon. It does not add fields, reinterpret statuses or make connection
identity part of authentication or queue semantics.

## Common rules

- **CW-TRANSPORT-001:** One transport request carries exactly one complete
  request frame from `05-wire-format.md` and produces at most one complete
  response frame. Transports MUST NOT prepend a length, identifier or metadata
  inside the protocol frame.
- **CW-TRANSPORT-002:** Relay authentication covers the exact decoded protocol
  bytes. TLS connection identity, HTTP headers and WebSocket connection state
  are not inputs to the authentication proof.
- **CW-TRANSPORT-003:** A connection may end before its response is observed.
  Once a successful durable command commits, disconnecting MUST NOT roll it
  back. A client retries the same persisted request frame on any connection.

## HTTPS

- The endpoint is `POST /v1/frame` over TLS.
- The request and successful response use `Content-Type:
  application/cofferwire`; each body is the exact protocol frame.
- A body larger than 65,536 bytes is rejected with HTTP 413 before complete
  buffering. Unsupported media types are rejected with HTTP 415.
- HTTP 200 means that the body is a protocol response, including protocol error
  statuses. HTTP 408 and 503 are transport failures and carry no protocol frame.

## WebSocket

- The endpoint is `GET /v1/ws` over the same TLS listener and advertises the
  `cofferwire.v1` subprotocol.
- Each binary message is exactly one protocol frame and each response is one
  binary message. Text messages terminate the session.
- The daemon accepts no binary message or underlying frame larger than 65,536
  bytes. Connection loss never changes an accepted queue command.

## Baseline resource policy

The reference daemon accepts at most 256 simultaneous TLS connections, admits
at most 64 commands concurrently across HTTPS and WebSocket, and allows at most
128 live WebSocket sessions. Excess connections are closed; excess work receives
HTTP 503 or has its WebSocket session terminated. An HTTPS request has a
10-second deadline; an idle WebSocket session has a 60-second deadline. SQLite
writer-lock waiting remains independently bounded at 250 milliseconds by
`CW-STORE-007`.

The daemon samples Unix time in whole seconds once for each authenticated
command and supplies that immutable value to the durable queue transaction.
