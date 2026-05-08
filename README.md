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
- **RFC 6479 anti-replay window** — 128-bit sliding window, two-phase design
- **Async-first API** — built on Tokio, zero-cost abstractions
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

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Magic (0x534D5250)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version (1)  |  Packet Type  |     Flags     |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Session ID (8 bytes)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (8 bytes)                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Timestamp µs (8 bytes)                     |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Payload Length (4 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Error Code  |                  Reserved (9)                 |
|               |                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Encrypted Payload (0–1280 bytes)                    |
|           + 16-byte Poly1305 authentication tag               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field          | Size     | Notes                            |
|----------------|----------|----------------------------------|
| Header         | 54 bytes | Fixed, always present            |
| Payload        | 0–1280 B | ChaCha20 ciphertext              |
| Auth tag       | 16 bytes | Poly1305, appended to payload    |
| Max packet     | 1350 B   | Fits in IPv6 minimum MTU (1280)  |

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
# Pass a custom address: cargo run -p smrp-server -- 0.0.0.0:8888
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

// Client
let mut conn = SmrpConnection::connect("127.0.0.1:9000").await?;
conn.send(b"hello").await?;
let reply = conn.recv().await?; // Some(b"hello")
conn.close().await?;
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
│       ├── packet.rs
│       ├── replay.rs   # RFC 6479 anti-replay window
│       ├── session.rs
│       └── transport.rs
├── smrp-server/        # Binary: reference echo server
├── smrp-cli/           # Binary: command-line client
├── proto/python/       # Python prototype / interop reference
├── docs/
│   └── SPEC.md         # Full protocol specification
└── LICENSE
```

---

## Running Tests

```sh
cargo test --workspace
```

The replay-window module has 11 unit tests covering in-order delivery,
duplicate rejection, out-of-order acceptance, and two-phase DoS resistance.

---

## Security Properties

| Property              | Mechanism                                    |
|-----------------------|----------------------------------------------|
| Confidentiality       | ChaCha20-Poly1305 per packet                 |
| Integrity             | Poly1305 auth tag, AEAD                      |
| Mutual authentication | Ed25519 signatures over session ID + eph pub |
| Forward secrecy       | Ephemeral X25519 key exchange                |
| Replay protection     | RFC 6479 sliding window (128 packets)        |
| Key separation        | HKDF derives independent c→s and s→c keys   |

### Known Limitations

- No certificate infrastructure — identity is per-key, not per-name
- No congestion control or retransmission (UDP, fire-and-forget)
- No fragmentation — payloads over 1280 bytes must be split by the caller
- Single-threaded handshake processing per session
- **Not audited**

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE).
