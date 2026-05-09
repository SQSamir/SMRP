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
- **RESET / PING / PONG** — immediate abort, RTT probing (echoes timestamp_us for clock-free RTT measurement)
- **Persistent signing identity** — Ed25519 PKCS#8 `to_pkcs8` / `from_pkcs8`; `bind_with_config_and_key` for stable server fingerprint
- **Graceful teardown** — FIN / FIN_ACK exchange; configurable `fin_ack_timeout`
- **Keepalive probes** — KEEPALIVE / KEEPALIVE_ACK every 15 s when idle (configurable)
- **Dead session eviction** — sessions with no traffic for 45 s are freed automatically
- **HELLO rate limiting** — 10 HELLO/IP/s; excess silently dropped before any crypto
- **HELLO timestamp validation** — rejects stale or future handshake packets (±30 s)
- **MAX_SESSIONS enforcement** — hard cap with ERROR reply to the client
- **Configurable runtime parameters** — `SmrpConfig` controls all timeouts, limits, and retransmission behaviour
- **Operational metrics** — `SmrpMetrics` exposes 13 atomic counters + snapshot API
- **Graceful listener shutdown** — sends real FIN packets to all connected peers
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
4       1     Version = 0x01
5       1     Packet Type
6       1     Flags  (bit 0 = FIN, bit 1 = KEY_UPDATE_REQUESTED)
7       1     Reserved (must be 0x00)
8       8     Session ID
16      8     Sequence Number
24      8     ACK Number  (cumulative ack for the reverse direction)
32      8     Timestamp µs  (sender clock, µs since Unix epoch)
40      2     Payload Length
42      12    Reserved / padding (must be 0x00)
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

| Wire | Name           | Description                                | Status      |
|------|----------------|--------------------------------------------|-------------|
| 0x01 | HELLO          | Handshake initiation                       | Implemented |
| 0x02 | HELLO_ACK      | Handshake response                         | Implemented |
| 0x03 | DATA           | Application data (encrypted)               | Implemented |
| 0x04 | ACK            | Cumulative acknowledgement                 | Implemented |
| 0x05 | KEEPALIVE      | Liveness probe                             | Implemented |
| 0x06 | KEEPALIVE_ACK  | Keepalive response                         | Implemented |
| 0x07 | KEY_UPDATE     | In-band rekeying initiation                | Planned     |
| 0x08 | KEY_UPDATE_ACK | Rekeying acknowledgement                   | Planned     |
| 0x09 | FIN            | Graceful teardown                          | Implemented |
| 0x0A | ERROR          | Protocol error notification                | Implemented |
| 0x0B | FIN_ACK        | Acknowledge FIN                            | Implemented |
| 0x0C | RESET          | Immediate abort                            | Implemented |
| 0x0D | PING           | RTT measurement request                    | Implemented |
| 0x0E | PONG           | RTT measurement response                   | Implemented |

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
// Sends FIN to all connected peers, then stops accepting
listener.shutdown().await;
```

---

## Workspace Layout

```
smrp/
├── smrp-core/          # Library: crypto, handshake, transport, high-level API
│   ├── src/
│   │   ├── conn.rs       # SmrpConnection / SmrpListener — retransmit, RESET, PING/PONG
│   │   ├── config.rs     # SmrpConfig — timeouts, limits, retransmission tuning
│   │   ├── constants.rs  # Compile-time wire constants
│   │   ├── crypto.rs     # X25519, ChaCha20-Poly1305, HKDF, Ed25519 + PKCS8 persistence
│   │   ├── error.rs      # SmrpError enum + wire codes
│   │   ├── handshake.rs  # Client/server handshake logic, key derivation
│   │   ├── metrics.rs    # SmrpMetrics atomic counters + MetricsSnapshot
│   │   ├── packet.rs     # Header parse/serialize, PacketType, Flags
│   │   ├── replay.rs     # RFC 6479 anti-replay window
│   │   ├── session.rs    # SessionId, SessionState, Session
│   │   └── transport.rs  # Raw UDP send/recv (Windows ICMP-safe)
│   └── fuzz/             # cargo-fuzz targets (requires nightly)
│       └── fuzz_targets/
│           ├── fuzz_packet_parse.rs   # Arbitrary bytes → header parser
│           ├── fuzz_hello_payload.rs  # Valid header + fuzz payload
│           └── fuzz_replay_window.rs  # Arbitrary (seq, action) pairs
├── smrp-server/        # Binary: echo server with persistent signing key
├── smrp-cli/           # Binary: command-line client
├── docs/
│   └── SPEC.md         # Full protocol specification (v0.4)
└── LICENSE
```

---

## Running Tests

```sh
cargo test --workspace
```

**54 tests** across all modules:

| Module      | Tests | Coverage                                                          |
|-------------|-------|-------------------------------------------------------------------|
| `constants` | 4     | Size arithmetic, magic bytes                                      |
| `error`     | 5     | Wire-code round-trip, all 11 variants                             |
| `packet`    | 13    | Parse/serialize, all 14 packet types, flag bits                   |
| `session`   | 3     | SessionId equality, state copy                                    |
| `replay`    | 11    | In-order, replay, out-of-order, two-phase, window slide           |
| `conn`      | 14    | Round-trip, concurrency, max payload, timeouts, FIN/FIN_ACK,      |
|             |       | metrics, custom config, shutdown, no-accept-after-shutdown,       |
|             |       | retransmit-buffer drain, PKCS8 roundtrip, persistent key bind     |
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
| Mutual authentication     | Ed25519 signatures over session ID + ephemeral pubkey  |
| Forward secrecy           | Ephemeral X25519 key exchange per session              |
| Replay protection         | RFC 6479 sliding window (128 packets), two-phase       |
| Key separation            | HKDF derives independent c→s and s→c keys             |
| Nonce uniqueness          | session_id[0..4] ‖ seq_u64_be — unique per packet     |
| AAD coverage              | session_id ‖ seq committed into every AEAD tag         |
| HELLO replay defence      | ±30 s timestamp validation on all HELLO packets        |
| DoS — HELLO flood         | 10 HELLO/IP/s rate limit before any crypto runs        |
| DoS — session exhaustion  | MAX_SESSIONS hard cap with ERROR reply                 |
| Dead session cleanup      | Idle sessions evicted automatically after 45 s         |
| Server identity pinning   | Persistent Ed25519 key via PKCS#8; stable fingerprint  |
| Reliable delivery         | Per-packet retransmit buffer; Jacobson/Karels RTO      |

### Known Limitations

- No certificate infrastructure — signing keys distributed out-of-band or TOFU; no revocation
- No congestion control — fire-and-forget; can saturate links
- No fragmentation — payloads over 1 280 bytes must be split by the caller
- In-band key update (KEY_UPDATE / KEY_UPDATE_ACK) defined in spec, not yet implemented
- Nonce uses only 32 bits of session ID entropy; full 64-bit session IDs are preferred at extreme session counts
- **Not audited** — cryptographic usage has not been reviewed by a third party

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE).
