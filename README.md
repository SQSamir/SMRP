# SMRP — Secure Minimal Reliable Protocol

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021--edition-orange.svg)](https://www.rust-lang.org/)
[![Status: Research](https://img.shields.io/badge/status-research-blue.svg)]()

SMRP is a research-grade encrypted reliable transport protocol built on UDP.
It provides mutual authentication, forward secrecy, and replay protection with
a minimal, auditable implementation in safe Rust.

> **Not production-ready.** SMRP is a learning and research project.
> It has not been audited. Do not use it to protect sensitive data.

---

## Features

- **X25519 ephemeral key exchange** — fresh keys every session, forward secrecy
- **ChaCha20-Poly1305 AEAD** — authenticated encryption for every data packet
- **HKDF-SHA-256 key derivation** — independent send/receive keys per direction
- **Ed25519 handshake signatures** — mutual authentication without a PKI
- **RFC 6479 anti-replay window** — 128-packet sliding window, two-phase DoS-safe design
- **Reliable delivery** — per-packet retransmit buffer; Jacobson/Karels RTT estimator; exponential backoff; Karn's algorithm
- **Ordered delivery** — out-of-order DATA packets are buffered and delivered to the application in send order
- **AIMD congestion control** — slow-start + AIMD congestion avoidance; `send()` backpressures when the congestion window is full; `initial_ssthresh` configurable via `SmrpConfig`
- **ECN support** — outgoing packets marked ECT(0) via `IP_TOS`/`IPV6_TCLASS`; incoming CE marks trigger immediate AIMD cwnd halving (RFC 3168 §6.1.2); controlled by `SmrpConfig::ecn_enabled`
- **PMTUD** — probe-based path MTU discovery; `effective_payload` steps up on ACK and down on probe timeout; controlled by `SmrpConfig::pmtud_enabled`
- **Send pacing** — token-bucket pacer spreads bursts across the RTT to reduce queue build-up; controlled by `SmrpConfig::pacing_enabled`
- **Message fragmentation** — payloads larger than `MAX_PAYLOAD` are automatically split into up to 255 fragments and reassembled transparently by the receiver (FRAGMENT flag, `frag_id` / `frag_index` / `frag_count` header fields)
- **SACK** — `SackAck` (0x0F) carries selective acknowledgement ranges; sender skips retransmitting already-received sequences
- **In-band key update** — `request_key_update()` rotates session keys mid-stream via X25519 + HKDF without a full re-handshake; Ed25519 identity pinning prevents impersonation; pre-rotation recv key is held to decrypt in-flight DATA
- **HKDF-derived nonce prefixes** — four independent 4-byte prefixes (data-c2s/s2c, ctrl-c2s/s2c) eliminate client-controlled nonce input; full 54-byte header as DATA AEAD additional data
- **Authenticated control packets** — ACK, KEEPALIVE, KEEPALIVE_ACK, FIN, FIN_ACK, RESET, PING, PONG carry a 16-byte Poly1305 MAC tag; prevents injection of fake packets
- **KEEPALIVE_ACK rate-limit** — at most one KEEPALIVE_ACK per second per connection; prevents amplification
- **Connection migration** — `PATH_CHALLENGE` / `PATH_RESPONSE` let a peer prove reachability at a new address; `peer_addr` is updated only after a confirmed round-trip; controlled by `SmrpConfig::migration_enabled`
- **Multiplexed streams** — DATA packets carry a `stream_id` (u16) field; non-zero stream IDs are routed to per-stream `mpsc` channels; up to `SmrpConfig::max_streams` (default 256) concurrent streams per session
- **Server identity pinning** — `connect_with_pinned_server_key()` verifies the server's Ed25519 fingerprint after the handshake; TOFU-compatible
- **RESET / PING / PONG** — immediate abort, RTT probing (echoes `timestamp_us` for clock-free RTT measurement)
- **Persistent signing identity** — Ed25519 PKCS#8 `to_pkcs8` / `from_pkcs8`; `bind_with_config_and_key` for stable server fingerprint
- **Graceful teardown** — FIN / FIN_ACK exchange; configurable `fin_ack_timeout`
- **Keepalive probes** — authenticated KEEPALIVE / KEEPALIVE_ACK every 15 s when idle (configurable)
- **Dead session eviction** — sessions with no traffic for 45 s are freed automatically
- **HELLO rate limiting** — 10 HELLO/IP/s; excess silently dropped before any crypto
- **HELLO timestamp validation** — rejects stale or future handshake packets (±30 s)
- **MAX_SESSIONS enforcement** — hard cap with ERROR reply to the client
- **Configurable runtime parameters** — `SmrpConfig` controls all timeouts, limits, and retransmission behaviour
- **Operational metrics** — `SmrpMetrics` exposes 13 atomic counters + snapshot API
- **Graceful listener shutdown** — sends authenticated FIN packets to all connected peers
- **connect() / recv() timeouts** — never block forever; caller-configurable deadlines
- **Async-first API** — built on Tokio, per-handshake concurrency
- **Tiny on-wire footprint** — 54-byte fixed header, max 1 350-byte packet

---

## Cryptographic Suite

| Primitive         | Algorithm         | Library                                    |
|-------------------|-------------------|--------------------------------------------|
| Key agreement     | X25519            | [ring](https://github.com/briansmith/ring) |
| Symmetric cipher  | ChaCha20-Poly1305 | ring                                       |
| Key derivation    | HKDF-SHA-256      | ring                                       |
| Handshake signing | Ed25519           | ring                                       |

---

## Packet Format

All integers are big-endian.

```
Offset  Size  Field
------  ----  -----
0       4     Magic = 0x534D5250 ("SMRP")
4       1     Version = 0x05
5       1     Packet Type
6       1     Flags  (bit 0 = FIN, bit 1 = KEY_UPDATE_REQUESTED,
               bit 2 = FRAGMENT, bit 3 = ECT, bit 4 = CE)
7       1     Reserved (must be 0x00)
8       8     Session ID
16      8     Sequence Number
24      8     ACK Number  (cumulative ack for the reverse direction)
32      8     Timestamp µs  (sender clock, µs since Unix epoch)
40      2     Payload Length
42      2     frag_id      (fragmentation message ID; 0 when not fragmented)
44      1     frag_index   (0-based fragment position within message)
45      1     frag_count   (total fragments in message; 0 when not fragmented)
46      2     recv_window  (receiver's remaining buffer space in packets)
48      2     stream_id    (logical stream identifier; 0 = default stream)
50      4     Reserved (must be 0x00)
--- header total: 54 bytes ---
54      N     Encrypted payload  (ChaCha20-Poly1305 ciphertext)
54+N    16    Poly1305 authentication tag
```

| Field      | Size     | Notes                         |
|------------|----------|-------------------------------|
| Header     | 54 bytes | Fixed, always present         |
| Payload    | 0–1280 B | AEAD ciphertext               |
| Auth tag   | 16 bytes | Poly1305, appended to payload |
| Max packet | 1350 B   | Fits in IPv6 min MTU (1280 B) |

### Packet Types

| Wire | Name           | Description                                         | Auth          |
|------|----------------|-----------------------------------------------------|---------------|
| 0x01 | HELLO          | Handshake initiation                                | Ed25519 sig   |
| 0x02 | HELLO_ACK      | Handshake response                                  | Ed25519 sig + transcript hash |
| 0x03 | DATA           | Application data (encrypted)                        | ChaCha20-Poly1305 AEAD |
| 0x04 | ACK            | Cumulative acknowledgement                          | Poly1305 MAC  |
| 0x05 | KEEPALIVE      | Liveness probe                                      | Poly1305 MAC  |
| 0x06 | KEEPALIVE_ACK  | Keepalive response                                  | Poly1305 MAC  |
| 0x07 | KEY_UPDATE     | In-band rekeying initiation                         | Ed25519 sig   |
| 0x08 | KEY_UPDATE_ACK | Rekeying acknowledgement                            | Ed25519 sig   |
| 0x09 | FIN            | Graceful teardown                                   | Poly1305 MAC  |
| 0x0A | ERROR          | Protocol error notification                         | none          |
| 0x0B | FIN_ACK        | Acknowledge FIN                                     | Poly1305 MAC  |
| 0x0C | RESET          | Immediate abort                                     | Poly1305 MAC  |
| 0x0D | PING           | RTT measurement request                             | Poly1305 MAC  |
| 0x0E | PONG           | RTT measurement response                            | Poly1305 MAC  |
| 0x0F | SACK_ACK       | Selective acknowledgement with gap ranges           | Poly1305 MAC  |
| 0x10 | PATH_CHALLENGE | Connection migration: challenge peer at new address | none (nonce)  |
| 0x11 | PATH_RESPONSE  | Connection migration: echo challenge nonce          | none (nonce)  |

---

## Quick Start

### Prerequisites

- Rust 1.75+ (`rustup update stable`)

### Build

```sh
git clone https://github.com/SQSamir/smrp
cd smrp
cargo build --release --workspace
```

### Run the echo server

```sh
cargo run --release -p smrp-server
# Listening on 0.0.0.0:9000 by default
# Custom address: cargo run -p smrp-server -- 0.0.0.0:8888
```

### Send a message

```sh
cargo run --release -p smrp-cli -- 127.0.0.1:9000 "hello world"
```

Expected output:

```
INFO connected  peer=127.0.0.1:9000 session=a1b2c3d4e5f60708
INFO → sent: "hello world"
INFO ← reply: "hello world"
INFO done
```

---

## Embedding SMRP in Your Application

### Minimal usage (default config)

```rust
use smrp_core::conn::{SmrpConnection, SmrpListener};

// Server — accept loop
let mut listener = SmrpListener::bind("0.0.0.0:9000").await?;
while let Some(mut conn) = listener.accept().await {
    tokio::spawn(async move {
        while let Ok(Some(data)) = conn.recv().await {
            conn.send(&data).await.ok(); // echo
        }
    });
}

// Client — connect() times out after 10 s, recv() after 60 s
let mut conn = SmrpConnection::connect("127.0.0.1:9000").await?;
conn.send(b"hello").await?;
let reply = conn.recv().await?;   // Ok(Some(plaintext bytes))
conn.close().await?;              // sends FIN, waits for FIN_ACK
```

### Custom config and metrics

```rust
use smrp_core::{
    config::SmrpConfig,
    conn::{SmrpConnection, SmrpListener},
};
use std::{sync::Arc, time::Duration};

let cfg = Arc::new(SmrpConfig {
    keepalive_interval:   Duration::from_secs(5),
    session_dead_timeout: Duration::from_secs(15),
    max_sessions:         1_000,
    recv_timeout:         Duration::from_secs(30),
    max_retransmits:      8,
    rto_initial:          Duration::from_millis(100),
    ecn_enabled:          true,   // enable ECN CE reaction
    pmtud_enabled:        true,   // enable path MTU probing
    pacing_enabled:       true,   // enable token-bucket send pacing
    ..SmrpConfig::default()
});

let mut listener = SmrpListener::bind_with_config("0.0.0.0:9000", cfg.clone()).await?;
let metrics = listener.metrics();

// Read a snapshot any time
let snap = metrics.snapshot();
println!("active={} total={} retransmits={} auth_failures={}",
    snap.sessions_active, snap.sessions_total,
    snap.packets_retransmitted, snap.auth_failures);
```

### Client with pinned server key

```rust
use smrp_core::conn::SmrpConnection;

// `pinned` is the server's 32-byte Ed25519 public key obtained out-of-band.
let pinned: [u8; 32] = /* loaded from config or first-use TOFU */ [0u8; 32];
let mut conn = SmrpConnection::connect_with_pinned_server_key("127.0.0.1:9000", &pinned).await?;
// Returns AuthenticationFailure if the server's key doesn't match pinned.
```

### Persistent server identity

```rust
use smrp_core::{config::SmrpConfig, conn::SmrpListener, crypto::SigningKey};
use std::{fs, path::Path, sync::Arc};

const KEY_FILE: &str = "smrp_server.key";

let sign_key = if Path::new(KEY_FILE).exists() {
    SigningKey::from_pkcs8(&fs::read(KEY_FILE)?)?
} else {
    let key = SigningKey::generate()?;
    fs::write(KEY_FILE, key.to_pkcs8())?;
    key
};
println!("identity: {}", hex::encode(sign_key.public_key_bytes()));

let mut listener = SmrpListener::bind_with_config_and_key(
    "0.0.0.0:9000", Arc::new(SmrpConfig::default()), sign_key,
).await?;
```

### Graceful shutdown

```rust
// Sends authenticated FIN to all connected peers, then stops accepting
listener.shutdown().await;
```

---

## Workspace Layout

```
smrp/
├── smrp-core/          # Library: crypto, handshake, transport, high-level API
│   ├── src/
│   │   ├── conn.rs       # SmrpConnection / SmrpListener — retransmit, ECN, PMTUD,
│   │   │                 #   pacing, fragmentation, SACK, migration, streams
│   │   ├── config.rs     # SmrpConfig — timeouts, limits, retransmission/ECN/PMTUD tuning
│   │   ├── constants.rs  # Compile-time wire constants
│   │   ├── crypto.rs     # X25519, ChaCha20-Poly1305, HKDF, Ed25519, SHA-256
│   │   ├── error.rs      # SmrpError enum + wire codes
│   │   ├── handshake.rs  # Client/server handshake logic, key derivation, transcript hash
│   │   ├── metrics.rs    # SmrpMetrics atomic counters + MetricsSnapshot
│   │   ├── packet.rs     # Header parse/serialize, PacketType, Flags
│   │   ├── replay.rs     # RFC 6479 anti-replay window
│   │   ├── session.rs    # SessionId, SessionState, Session
│   │   └── transport.rs  # Raw UDP send/recv; ECN recv (recvmsg + CMSG ancillary data)
│   ├── examples/
│   │   ├── client.rs     # Minimal connect / send / recv / close example
│   │   └── server.rs     # Minimal echo-server example
│   └── fuzz/             # cargo-fuzz targets (requires nightly)
│       └── fuzz_targets/
│           ├── fuzz_packet_parse.rs   # Arbitrary bytes → header parser
│           ├── fuzz_hello_payload.rs  # Valid header + fuzz payload
│           └── fuzz_replay_window.rs  # Arbitrary (seq, action) pairs
├── smrp-server/        # Binary: echo server with persistent signing key
├── smrp-cli/           # Binary: command-line client
├── docs/
│   ├── SPEC.md         # Full protocol specification (v1.0)
│   └── STATE_MACHINE.md # Client/server state machine diagrams
├── CHANGELOG.md
└── LICENSE
```

---

## Running Tests

```sh
cargo test --workspace
```

**90 tests** across all modules (88 unit + 2 doc-tests):

| Module      | Tests | Coverage                                                          |
|-------------|-------|-------------------------------------------------------------------|
| `constants` | 4     | Size arithmetic, magic bytes                                      |
| `error`     | 5     | Wire-code round-trip, all 13 variants                             |
| `packet`    | 19    | Parse/serialize, all 17 packet types, all 5 flag bits             |
| `session`   | 3     | SessionId equality, state copy                                    |
| `replay`    | 11    | In-order, replay, out-of-order, two-phase, window slide           |
| `conn`      | 23    | Round-trip, concurrency, max payload, timeouts, FIN/FIN_ACK,      |
|             |       | metrics, custom config, shutdown, no-accept-after-shutdown,       |
|             |       | retransmit-buffer drain, PKCS8 roundtrip, persistent key bind,    |
|             |       | ordered delivery, congestion window backpressure, key rotation,   |
|             |       | pinned-key accept, pinned-key reject,                             |
|             |       | max-retransmits session death, configurable ssthresh,             |
|             |       | fragmented payload roundtrip, fragment count limit                |
| `vectors`   | 23    | X25519 DH symmetry, HKDF determinism/domain-sep, nonce prefix     |
|             |       | isolation, `make_nonce` layout, ChaCha20-Poly1305 seal/open/      |
|             |       | tamper/wrong-AAD/wrong-nonce, Ed25519 sign/verify/tamper/pkcs8    |
| doc-tests   | 2     | API examples compile and run                                      |

### Running Fuzz Targets

Requires Rust nightly and `cargo-fuzz`:

```sh
rustup install nightly
cargo install cargo-fuzz
cd smrp-core

# Fuzz the packet header parser
cargo +nightly fuzz run fuzz_packet_parse

# Fuzz HELLO payload parsing and signature verification
cargo +nightly fuzz run fuzz_hello_payload

# Fuzz the RFC 6479 anti-replay sliding window
cargo +nightly fuzz run fuzz_replay_window
```

---

## Security Properties

| Property                  | Mechanism                                              |
|---------------------------|--------------------------------------------------------|
| Confidentiality           | ChaCha20-Poly1305 per packet                           |
| Integrity                 | Poly1305 auth tag, AEAD                                |
| Mutual authentication     | Ed25519 signatures; HELLO_ACK transcript-bound to client HELLO via SHA-256 |
| Forward secrecy           | Ephemeral X25519 key exchange per session              |
| Sub-session forward secrecy | `request_key_update()` rotates keys without re-handshake |
| Replay protection         | RFC 6479 sliding window (128 packets), two-phase       |
| Key separation            | HKDF derives independent c→s and s→c keys             |
| Nonce uniqueness          | HKDF-derived 4-byte prefix ‖ seq_u64_be; separate prefixes per direction and domain (data/ctrl) |
| AAD coverage              | Full 54-byte header (timestamp_us zeroed) for DATA; full header for ctrl |
| HELLO replay defence      | ±30 s timestamp validation on all HELLO packets        |
| DoS — HELLO flood         | 10 HELLO/IP/s rate limit before any crypto runs        |
| DoS — session exhaustion  | MAX_SESSIONS hard cap with ERROR reply                 |
| Dead session cleanup      | Idle sessions evicted automatically after 45 s         |
| Server identity pinning   | Persistent Ed25519 key via PKCS#8; `connect_with_pinned_server_key()` enforces fingerprint |
| Control packet integrity  | ACK, KEEPALIVE, KEEPALIVE_ACK, FIN, FIN_ACK, RESET, PING, PONG carry Poly1305 MAC; injected fakes rejected |
| KEEPALIVE amplification   | KEEPALIVE_ACK rate-limited to 1/second per connection  |
| ECN congestion signalling | CE marks from IP layer trigger immediate cwnd halving (RFC 3168) |
| Reliable delivery         | Per-packet retransmit buffer; Jacobson/Karels RTO      |
| Ordered delivery          | Reorder buffer delivers application data in send order |
| Congestion control        | AIMD slow-start + congestion avoidance; ECN CE reaction; PMTUD; cwnd backpressure |
| Fragmentation             | Large messages split transparently; reassembled on receipt |
| SACK                      | Selective ACK avoids unnecessary retransmits           |

### Known Limitations

- No certificate infrastructure — signing keys distributed out-of-band or TOFU; no revocation
- `&mut self` API — `send()` and `recv()` both take `&mut self`; concurrent send+recv requires a task split around the connection
- Key update sequencing constraint — retransmit buffer must be empty before `request_key_update()`; additionally, DATA packets received during `request_key_update()` are discarded (the call blocks `recv_inner` while waiting for `KEY_UPDATE_ACK`)
- Nonce prefix is 4 bytes (32 bits), derived from the session key via HKDF; prefix collision probability is negligible within a single session's key lifetime
- ECN is opt-in (`ecn_enabled: false` by default) and requires OS support; silently disabled if the socket option is unavailable
- **Not audited** — cryptographic usage has not been reviewed by a third party

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE).
