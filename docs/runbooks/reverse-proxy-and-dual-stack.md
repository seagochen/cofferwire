# Runbook: Reverse Proxies and Dual-Stack Deployment

## Reverse proxies

`cofferwired` always terminates its own TLS: `apps/cofferwired/src/main.rs`
builds a `RustlsAcceptor` from `CERTIFICATE_PEM`/`PRIVATE_KEY_PEM` and there
is no plaintext-HTTP listener mode. A reverse proxy placed in front of it
must therefore do one of:

- **TCP/TLS passthrough** (for example HAProxy in `tcp` mode, or SNI-based
  routing): the proxy forwards the raw TLS bytes to `cofferwired` untouched,
  which still terminates TLS itself.
- **TLS bridging**: the proxy terminates the client's TLS connection and
  opens its own, separate TLS connection to `cofferwired`. This means two
  independent TLS handshakes, not one extended end-to-end connection.

A proxy that terminates TLS and forwards plaintext HTTP to `cofferwired` is
not supported; there is no listener that accepts it.

Either supported shape is safe with respect to protocol authentication:
`CW-TRANSPORT-002` already establishes that relay-command authentication
covers only the exact decoded protocol bytes, never TLS connection identity,
HTTP headers, or WebSocket connection state. A proxy in front therefore
cannot weaken authentication, and the per-credential rate limiter
(`CW-SECURITY-002`) keys on the protocol-level queue principal or blob
capability carried inside the authenticated request, not on the proxy's
source address, so proxying or connection multiplexing does not change which
credential a request is charged against.

What a proxy *does* change is connection-level admission accounting:
`MAX_CONNECTIONS`, `MAX_WEBSOCKET_CONNECTIONS` and `MAX_CONCURRENT_COMMANDS`
(`docs/conformance/operational-limits-v1.json`) all count connections and
in-flight commands as `cofferwired` itself sees them. A proxy that
multiplexes many client connections onto a smaller pool of upstream
connections to `cofferwired` changes the effective client-facing admission
behavior compared to clients connecting directly; size the proxy's upstream
connection pool with these limits in mind rather than assuming a 1:1
mapping from client connections to the daemon's own bounds.

## Dual-stack (IPv4 + IPv6) and multiple listeners

`cofferwired`'s `BIND_ADDRESS` argument is a single `std::net::SocketAddr`
(`apps/cofferwired/src/main.rs`); the daemon does not itself decide dual-
stack behavior. The tested and supported shape -- one process, one
`DATABASE_PATH`, matching every fault-injection and durability test in this
repository -- is:

- Bind one `SocketAddr` per process. Binding an IPv6 wildcard address (for
  example `[::]:8443`) accepts both IPv4 and IPv6 clients on most Linux
  configurations, because the OS socket defaults to dual-stack unless
  `IPV6_V6ONLY` is set; verify this against the target platform's actual
  socket defaults before relying on it, since `cofferwired` does not set or
  clear that option itself.
- If dual-stack sysctls are unavailable or disabled, terminate both address
  families at a reverse proxy (see above) that forwards to a single
  `cofferwired` process over one `SocketAddr`, rather than running the
  daemon itself on two addresses.

Running two independent `cofferwired` processes concurrently against the
same `DATABASE_PATH` (for example, one bound to an IPv4 address and one to
an IPv6 address, to avoid relying on OS dual-stack sockets) is not exercised
by this repository's fault-injection suite. SQLite's own file locking is
designed for multi-process access, but this project has not validated that
shape against its crash-recovery and durability tests, which all assume a
single writer process. Do not run multiple live `cofferwired` processes
against one database file without independently validating that
configuration first; prefer the single-process, single-`SocketAddr`
deployment above.
