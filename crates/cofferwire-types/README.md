# cofferwire-types

Transport-independent protocol types for Cofferwire's v1 wire contract, as
fixed by [`spec/05-wire-format.md`](../../spec/05-wire-format.md).

This crate has no dependency on SQLite, HTTP, WebSocket or any relay
storage engine. It defines bounded identifiers, the opaque message and
`auth` byte strings, TTL and timestamp scalars, the `Version`, `Command`
and `Status` wire enumerations, and request/response types for every v1
command and error. Every constructor validates its invariants immediately, so a
value that exists as this crate's public API can always be encoded; a
codec, client or relay daemon built on top of these types inherits one
shared definition of "valid" instead of redefining validation, defaults
and error semantics independently.

`Payload` and `Auth` carry potentially large or sensitive bytes; both
implement `Debug` without printing their contents.
