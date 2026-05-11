# Changelog

All notable changes to SMRP are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.0] — 2026-05-10

First tagged release. The protocol is research-grade and **not production-ready**.

### Security

- **Authenticated FIN / FIN_ACK** — both teardown packets now carry a 16-byte
  Poly1305 MAC (same HKDF-derived control-packet keys used for ACK/RESET/PING/PONG).
  Injected FIN packets from off-path attackers are silently rejected.
- **Transcript hash in HELLO_ACK** — the server now signs
  `session_id || server_eph_pub || SHA-256(client_hello_payload)` instead of
  `session_id || server_eph_pub`. This binds the HELLO_ACK to the specific HELLO
  it responds to, preventing a server from replaying its own HELLO_ACK against a
  different client HELLO (protocol version bumped to 0x03).
- **KEEPALIVE_ACK rate-limit** — the receive path now sends at most one
  KEEPALIVE_ACK per second per connection, preventing KEEPALIVE-amplification
  from unauthenticated probes.

### Added

- `crypto::sha256()` — SHA-256 helper used for the transcript hash.
- `docs/STATE_MACHINE.md` — full client/server state machine with ASCII diagrams
  and an authenticated-packet-types table.
- `smrp-core/examples/client.rs` — minimal connect/send/recv/close example.
- `smrp-core/examples/server.rs` — minimal echo-server example.
- `hex` and `tracing-subscriber` dev-dependencies for the examples.

### Changed

- Protocol version on the wire: `0x02` → `0x03` (wire-breaking; all peers must
  be upgraded together).
- `SmrpListener::shutdown()` — no longer sends unauthenticated raw FIN UDP
  packets. Unaccepted connections in the accept queue are closed via
  `SmrpConnection::close()` (authenticated FIN); accepted connections receive a
  `Shutdown` signal that triggers authenticated FIN from `recv_inner`.
- `SmrpConfig::initial_ssthresh` — the slow-start threshold is now configurable
  (was hardcoded to 64); default unchanged.
- `handle_key_update` — fixed ordering bug: `EphemeralKeypair::agree()` now runs
  before `KEY_UPDATE_ACK` is sent, so both sides install identical keys.

### Removed

- `shutdown_fin()` internal helper (replaced by the per-connection close path).
- `peer_addr` field from `SessionEntry` (was only needed for the now-removed
  unauthenticated shutdown FIN).
- `socket` field from `SmrpListener` (was only needed for shutdown FIN sends).

---

## Known Limitations (as of 0.1.0)

- No certificate infrastructure; keys distributed out-of-band or TOFU.
- KEEPALIVE probes are unauthenticated (any host can probe; rate-limited ACK
  mitigates amplification risk).
- No fragmentation; payloads > 1 280 bytes must be split by the caller.
- DATA packets received during `request_key_update()` are discarded.
- Not audited — cryptographic usage has not been reviewed by a third party.
