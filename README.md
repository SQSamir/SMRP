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
- **RFC 6479 anti-replay window** — 128-bit sliding window, two-phase DoS-safe design
- **ACK + FIN/FIN_ACK teardown** — graceful session lifecycle
- **Keepalive probes** — idle sessions send KEEPALIVE every 15 s
- **HELLO rate limiting** — 10 HELLO/IP/s; excess silently dropped before any crypto
- **HELLO timestamp validation** — rejects stale handshake packets (±30 s clock skew)
- **MAX_SESSIONS enforcement** — hard cap with ERROR reply to the client
- **connect() / recv() timeouts** — never block forever; caller-configurable deadlines
- **Async-first API** — built on Tokio, per-handshake concurrency
- **Tiny on-wire footprint** — 54-byte fixed header, max 1 350-byte packet

---

## Cryptographic Suite

| Primitive          | Algorithm          | Library        |
|--------------------|--------------------|----------------|
| Key agreement      | X25519             | [ring](https://github.com/briansmith/ring) |
| Symmetric cipher   | ChaCha20-Poly1305  | ring           |
| Key derivation     | HKDF-SHA-256       | ring           |
| Handshake signing  | Ed25519            | ring           |

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
7       1     Reserved
8       8     Session ID
16      8     Sequence Number
24      8     ACK Number  (cumulative ack for the reverse direction)
32      8     Timestamp µs
40      2     Payload Length
42      12    Reserved / padding
--- header total: 54 bytes ---
54      N     Encrypted payload  (ChaCha20-Poly1305 ciphertext)
54+N    16    Poly1305 authentication tag
```

| Field      | Size     | Notes                           |
|------------|----------|---------------------------------|
| Header     | 54 bytes | Fixed, always present           |
| Payload    | 0–1280 B | AEAD ciphertext                 |
| Auth tag   | 16 bytes | Poly1305, appended to payload   |
| Max packet | 1350 B   | Fits in IPv6 min MTU (1280 B)   |

### Packet Types

| Wire | Name           | Description                              |
|------|----------------|------------------------------------------|
| 0x01 | HELLO          | Handshake initiation                     |
| 0x02 | HELLO_ACK      | Handshake response                       |
| 0x03 | DATA           | Application data (encrypted)             |
| 0x04 | ACK            | Cumulative acknowledgement               |
| 0x05 | KEEPALIVE      | Liveness probe                           |
| 0x06 | KEEPALIVE_ACK  | Keepalive response                       |
| 0x07 | KEY_UPDATE     | In-band rekeying initiation              |
| 0x08 | KEY_UPDATE_ACK | Rekeying acknowledgement                 |
| 0x09 | FIN            | Graceful teardown                        |
| 0x0A | ERROR          | Protocol error notification              |
| 0x0B | FIN_ACK        | Acknowledge FIN                          |
| 0x0C | RESET          | Immediate abort *(planned)*              |
| 0x0D | PING           | RTT measurement *(planned)*              |
| 0x0E | PONG           | RTT response *(planned)*                 |

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

```rust
use smrp_core::conn::{SmrpConnection, SmrpListener};

// Server
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
let reply = conn.recv().await?;          // Ok(Some(plaintext))
conn.close().await?;                     // sends FIN, waits for FIN_ACK
```

---

## Workspace Layout

```
smrp/
├── smrp-core/          # Library: crypto, handshake, transport, high-level API
│   └── src/
│       ├── conn.rs     # SmrpConnection / SmrpListener public API
│       ├── constants.rs
│       ├── crypto.rs   # X25519, ChaCha20-Poly1305, HKDF, Ed25519
│       ├── error.rs
│       ├── handshake.rs
│       ├── packet.rs   # Header parse/serialize, PacketType, Flags
│       ├── replay.rs   # RFC 6479 anti-replay window
│       ├── session.rs
│       └── transport.rs
├── smrp-server/        # Binary: reference echo server
├── smrp-cli/           # Binary: command-line client
├── proto/python/       # Python prototype / interop reference
├── docs/
│   └── SPEC.md         # Full protocol specification (v0.2)
└── LICENSE
```

---

## Running Tests

```sh
cargo test --workspace
```

**45 tests** across all modules:

| Module      | Tests | Coverage                                                    |
|-------------|-------|-------------------------------------------------------------|
| `constants` | 4     | Size arithmetic, magic bytes                                |
| `error`     | 5     | Wire-code round-trip, all 11 variants                       |
| `packet`    | 13    | Parse/serialize, all packet types, flag bits                |
| `session`   | 3     | SessionId equality, state copy                              |
| `replay`    | 11    | In-order, replay, out-of-order, two-phase, window slide     |
| `conn`      | 8     | Round-trip, concurrency, max payload, timeouts, FIN/FIN_ACK |
| doc-tests   | 2     | API examples compile and run                                |

---

## Security Properties

| Property               | Mechanism                                             |
|------------------------|-------------------------------------------------------|
| Confidentiality        | ChaCha20-Poly1305 per packet                          |
| Integrity              | Poly1305 auth tag, AEAD                               |
| Mutual authentication  | Ed25519 signatures over session ID + ephemeral pubkey |
| Forward secrecy        | Ephemeral X25519 key exchange per session             |
| Replay protection      | RFC 6479 sliding window (128 packets), two-phase      |
| Key separation         | HKDF derives independent c→s and s→c keys            |
| HELLO replay defence   | ±30 s timestamp validation on all HELLO packets       |
| DoS — HELLO flood      | 10 HELLO/IP/s rate limit before any crypto runs       |
| DoS — session exhaustion | MAX_SESSIONS hard cap with ERROR reply              |

### Known Limitations

- No certificate infrastructure — signing keys distributed out-of-band or TOFU
- No congestion control or retransmission (UDP, fire-and-forget by design)
- No fragmentation — payloads over 1280 bytes must be split by the caller
- In-band key update (KEY_UPDATE) defined in spec, not yet implemented
- RESET and PING packet types wired up, handling not yet implemented
- **Not audited**

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE).
