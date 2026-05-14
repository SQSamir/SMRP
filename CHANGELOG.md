# Changelog

All notable changes to SMRP are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased] — protocol version 0x05

### Security

- **KEEPALIVE Poly1305 authentication** — both KEEPALIVE and KEEPALIVE_ACK now
  carry a 16-byte Poly1305 MAC. A dedicated `KeepaliveAuth` struct (shared via
  `Arc<Mutex<_>>` with the keepalive background task) holds the send key and a
  separate nonce counter starting at `1u64 << 48`, avoiding any collision with
  the main `ctrl_send_seq` counter. Spoofed KEEPALIVE packets are rejected by
  MAC verification. Key material in `KeepaliveAuth` is updated on every key
  rotation via `install_rekey_keys`.
- **Key update DATA buffering** — the responder now saves the pre-rotation recv
  key (`pre_rekey_recv_key_bytes`) after sending `KEY_UPDATE_ACK`. DATA packets
  that arrive encrypted with the old key (in-flight before the initiator received
  `KEY_UPDATE_ACK`) are decrypted and buffered in `buffered_rekey_data`, then
  drained into the deliver queue after key installation completes. This prevents
  silent packet loss at rotation boundaries.

### Added

- **ECN recv-side CE detection** (`transport::recv_one_ecn`) — on Unix, uses
  `IP_RECVTOS` / `IPV6_RECVTCLASS` socket options to receive TOS/TCLASS as
  ancillary data via `recvmsg(2)`. When the CE codepoint (`0b11`) is detected,
  `SmrpConnection::react_to_ecn_ce()` fires an immediate RFC 3168 §6.1.2 cwnd
  halving: `ssthresh = max(cwnd/2, 2)`, `cwnd = ssthresh`.
- **ECN outgoing ECT(0)** (`transport::apply_ecn_socket_option`) — sets
  `IP_TOS` (IPv4) or `IPV6_TCLASS` (IPv6) to `ECT(0)=0x02` via `setsockopt`.
  Both options are `#[cfg(unix)]`-gated and silently ignored on failure.
- **PMTUD probe loop** — `maybe_run_pmtud()` sends oversized sealed DATA probes
  periodically (`pmtud_probe_interval`, default 5 s). ACK → step up by
  `PMTUD_STEP` (128 bytes); 4×RTT timeout → step down by `PMTUD_STEP`, floored
  at `MIN_PMTUD_PAYLOAD` (512 bytes). The current `effective_payload` starts at
  `MAX_PAYLOAD`.
- **Message fragmentation** — `send()` automatically splits payloads larger than
  `effective_payload` into up to 255 fragments using the `FRAGMENT` flag and
  `frag_id` / `frag_index` / `frag_count` header fields. The receiver reassembles
  transparently via `FragmentAssembly`.
- **Selective acknowledgement (SACK)** — `SackAck` (0x0F) carries out-of-order
  received ranges; sender skips sequences present in its `sacked: BTreeSet<u64>`
  when the retransmit task fires. Controlled by `SmrpConfig::max_sack_blocks`
  (default: 16).
- **Connection migration** — `PATH_CHALLENGE` (0x10) / `PATH_RESPONSE` (0x11)
  packet types. On a matching nonce echo, `peer_addr` is updated to the new
  address. Controlled by `SmrpConfig::migration_enabled` (default: `true`).
- **Multiplexed streams** — `stream_id` (u16) header field routes non-zero
  streams to per-stream `mpsc` channels in `stream_txs`. Controlled by
  `SmrpConfig::max_streams` (default: 256).
- **Send pacing** — token-bucket pacer in `send()` spreads bursts evenly across
  the RTT. Controlled by `SmrpConfig::pacing_enabled` (default: `true`).
- **`recv_window` header field** — receiver advertises remaining reorder-buffer
  capacity in packets; sender uses `min(cwnd, peer_recv_window)` as the effective
  flight window.
- **New `SmrpConfig` fields:** `max_sack_blocks` (16), `pmtud_enabled` (true),
  `pmtud_probe_interval` (5 s), `pacing_enabled` (true), `ecn_enabled` (false),
  `max_streams` (256), `migration_enabled` (true).
- **New error codes:** `StreamClosed` (0x0B), `TooManyStreams` (0x0C).
- **New flag bits:** `FRAGMENT` (bit 2, 0x04), `ECT` (bit 3, 0x08), `CE` (bit 4,
  0x10) with corresponding `Flags::fragment()`, `Flags::ect()`, `Flags::ce()` methods.
- `libc = "0.2"` added as a `[target.'cfg(unix)'.dependencies]` dependency.

### Changed

- Protocol version on the wire: `0x03` → `0x05` (wire-breaking; all peers must
  be upgraded together).
- Header bytes 42–53: previously all-zero reserved padding; now carry `frag_id`
  (u16), `frag_index` (u8), `frag_count` (u8), `recv_window` (u16), `stream_id`
  (u16), and 4 reserved bytes.
- `transport::recv_raw` return type changed to `(SmrpHeader, Vec<u8>, SocketAddr, bool)`
  where `bool` is `ce_marked` (always `false` on non-Unix).
- `SessionMsg::Packet` now carries 4 fields (header, payload, addr, ce_marked).
- AIMD on-loss reaction now also triggers when `ce_marked && ecn_enabled`, matching
  ECN CE semantics from RFC 3168 §6.1.2.
- `docs/STATE_MACHINE.md` updated: KEEPALIVE row changed from "no" to
  "Poly1305 MAC" in the authenticated-packet-types table.
- `docs/SPEC.md` updated to v1.0: all new sections added (§8.9–§8.13, §16, §17);
  constants table, config table, packet type table, flags table, error table all
  updated to reflect current code.

### Fixed

- Fixed 9 Rust 1.95 CI clippy errors introduced with the ECN recv-side commit:
  `borrow_as_ptr` (4 occurrences in `recvmsg`/`CMSG_*` calls), `cast_sign_loss`
  (`ssize_t as usize` → `.cast_unsigned()`), `needless_continue` (2 match arms),
  `collapsible_match` (2 `PacketType::KeepaliveAck` arms in `recv_inner` and
  `process_one_packet`).

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

## Known Limitations (as of unreleased)

- No certificate infrastructure; keys distributed out-of-band or TOFU.
- `&mut self` API — `send()` and `recv()` cannot run concurrently without a task
  split.
- Key update sequencing constraint — retransmit buffer must be empty before
  `request_key_update()`; DATA packets received during the wait are discarded.
- ECN is opt-in (`ecn_enabled: false` by default) and requires OS support.
- Not audited — cryptographic usage has not been reviewed by a third party.
