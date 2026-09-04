# cofferwire-codec

Deterministic encoder and strict, allocation-bounded decoder for the Cofferwire
v1 frame format. The implementation deliberately supports only the canonical
CBOR subset in `spec/05-wire-format.md`; it is not a general-purpose CBOR codec.

`decode_request` exposes the exact borrowed `preamble || payload` byte range so
authentication never depends on decoding and re-encoding attacker input.
