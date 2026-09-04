# cofferwire-client

Transport-independent sender and recipient state machines. `Transport` moves a
single opaque frame and `InboxStore` defines the local durability boundary, so
retry, decryption, deduplication, durable commit and relay ACK ordering do not
leak into HTTPS, WebSocket or UI code.
