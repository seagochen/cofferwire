# cofferwire-crypto

The fixed Cofferwire v1 cryptographic profile:

- Ed25519 strict verification for relay-command authentication;
- RFC 9180 authenticated HPKE with X25519/HKDF-SHA-256/
  ChaCha20-Poly1305 for end-to-end message protection.

See `spec/04-cryptographic-profile.md` for the exact wire syntax, domain
separation, associated data, limits and security boundaries.
