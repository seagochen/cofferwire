# cofferwired

`cofferwired` is the baseline durable relay daemon. It exposes the exact v1
protocol frame through HTTPS and WebSocket while keeping TLS and connection
state outside the authenticated envelope.

Run it with a bind address, SQLite path, PEM certificate and PEM private key:

```console
cargo run -p cofferwired -- 127.0.0.1:8443 relay.sqlite cert.pem key.pem
```

Endpoints:

- `POST /v1/frame` with `Content-Type: application/cofferwire`;
- `GET /v1/ws` with WebSocket subprotocol `cofferwire.v1`;
- `GET /healthz` for a process liveness check.

The daemon is a reference implementation, not a production deployment guide.
Certificate issuance, process supervision, database backup, metrics and
deployment-specific traffic controls remain operator responsibilities.
