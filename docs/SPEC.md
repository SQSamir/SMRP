# SMRP Protocol Specification

**Version:** 0.1  
**Status:** Draft  
**Authors:** Samir Gasimov

---

## 1. Introduction

SMRP (Secure Minimal Reliable Protocol) is a research-grade transport protocol
that provides encrypted, mutually authenticated, replay-protected communication
over UDP.

Design goals:

- Minimal on-wire overhead (54-byte fixed header)
- Strong cryptographic guarantees using modern primitives only
- Auditable implementation — no custom crypto, rely on `ring`
- Async-first implementation with Tokio

Non-goals: congestion control, retransmission, fragmentation, PKI.

---

## 2. Terminology

- **Session** — a logical connection identified by an 8-byte session ID
- **c2s** — client-to-server direction
- **s2c** — server-to-client direction
- **AAD** — Additional Authenticated Data (not encrypted, but authenticated)
- **eph** — ephemeral (generated fresh per session, discarded after handshake)

---

## 3. Packet Format

All integers are big-endian.

```
Offset  Size  Field
------  ----  -----
0       4     Magic = 0x534D5250 ("SMRP")
4       1     Version = 0x01
5       1     Packet Type (see §4)
6       1     Flags (see §5)
7       1     Reserved (must be 0x00)
8       8     Session ID
16      8     Sequence Number (monotonically increasing per direction)
24      8     Timestamp (microseconds since Unix epoch)
32      4     Payload Length (bytes of payload following the header)
36      1     Error Code (0x00 = no error; see §6)
37      9     Reserved (must be 0x00)
46      8     Reserved
--- total header: 54 bytes ---
54      N     Encrypted Payload (N = Payload Length)
54+N    16    Poly1305 Authentication Tag
```

Maximum payload: 1280 bytes.  
Maximum on-wire packet: 54 + 1280 + 16 = **1350 bytes**.

---

## 4. Packet Types

| Value | Name       | Direction   | Description                              |
|-------|------------|-------------|------------------------------------------|
| 0x01  | HELLO      | C→S, S→C    | Handshake initiation / response          |
| 0x02  | HELLO_ACK  | S→C         | Server handshake acknowledgement         |
| 0x03  | DATA       | C↔S         | Application data (encrypted)             |
| 0x04  | ACK        | C↔S         | Cumulative acknowledgement               |
| 0x05  | FIN        | C↔S         | Graceful session teardown                |
| 0x06  | FIN_ACK    | C↔S         | Acknowledge FIN                          |
| 0x07  | KEEPALIVE  | C↔S         | Keepalive (no payload)                   |
| 0x08  | ERROR      | C↔S         | Error notification                       |
| 0x09  | RESET      | C↔S         | Immediate session reset                  |
| 0x0A  | PING       | C↔S         | RTT measurement                          |

---

## 5. Flags

| Bit | Mask | Name        | Meaning                        |
|-----|------|-------------|--------------------------------|
| 0   | 0x01 | ENCRYPTED   | Payload is AEAD-encrypted      |
| 1   | 0x02 | COMPRESSED  | Reserved, not implemented      |
| 2   | 0x04 | FRAGMENTED  | Reserved, not implemented      |
| 3–7 | —    | Reserved    | Must be 0                      |

---

## 6. Error Codes

| Value | Name                 | Meaning                              |
|-------|----------------------|--------------------------------------|
| 0x00  | None                 | No error                             |
| 0x01  | MalformedHeader      | Header parse failure                 |
| 0x02  | InvalidVersion       | Unsupported protocol version         |
| 0x03  | AuthenticationFailed | AEAD tag verification failed         |
| 0x04  | ReplayDetected       | Sequence number already seen         |
| 0x05  | SessionNotFound      | Unknown session ID                   |
| 0x06  | HandshakeFailed      | Handshake could not complete         |
| 0x07  | PayloadTooLarge      | Payload exceeds MAX_PAYLOAD          |
| 0x08  | InvalidPacketType    | Unrecognised packet type field       |
| 0x09  | Timeout              | Session timed out                    |
| 0x0A  | InternalError        | Unexpected internal error            |

---

## 7. Handshake

### 7.1 Overview

```
Client                              Server
  |                                    |
  |--- HELLO (eph_pub, sign_pub, sig) -->|
  |                                    |   verify sig
  |                                    |   generate server eph keypair
  |<-- HELLO (eph_pub, sign_pub, sig) ---|
  |   verify sig                       |
  |   derive session keys              |   derive session keys
  |<-- HELLO_ACK (encrypted) ----------|
  |                                    |
  |=== DATA (encrypted) =============> |
```

### 7.2 HELLO Payload (128 bytes)

```
Offset  Size  Field
0       32    Ephemeral X25519 public key
32      32    Ed25519 signing public key
64      64    Ed25519 signature over (session_id[8] || eph_pub[32])
```

Both sides sign and verify this payload. This provides mutual authentication:
each side proves possession of the private signing key corresponding to the
advertised signing public key.

### 7.3 Key Derivation

After ECDH agreement on the shared secret:

```
shared_secret = X25519(eph_priv, peer_eph_pub)   # 32 bytes

c2s_key = HKDF-SHA256(ikm=shared_secret, salt=session_id, info="smrp-c2s-key")[0..32]
s2c_key = HKDF-SHA256(ikm=shared_secret, salt=session_id, info="smrp-s2c-key")[0..32]
```

Client sends with `c2s_key`, receives with `s2c_key`.  
Server sends with `s2c_key`, receives with `c2s_key`.

### 7.4 Session ID

The 8-byte session ID is generated by the client using a cryptographically
secure random number generator and sent in the HELLO packet header. The server
uses the same session ID for all subsequent packets of the session.

---

## 8. Data Transfer

### 8.1 Encryption

Each DATA packet payload is encrypted with ChaCha20-Poly1305:

```
nonce  = session_id[0..4] || seq.to_be_bytes()   # 12 bytes
aad    = session_id[0..8] || seq.to_be_bytes()   # 16 bytes
(ciphertext, tag) = ChaCha20Poly1305.seal(key, nonce, plaintext, aad)
```

The auth tag (16 bytes) is appended immediately after the ciphertext.

### 8.2 Sequence Numbers

Sequence numbers are unsigned 64-bit integers, starting at 0, incrementing by 1
per packet per direction. They are included in the header unencrypted and also
mixed into both the nonce and AAD.

---

## 9. Anti-Replay Window

SMRP uses an RFC 6479 style sliding window to reject duplicate and replayed
packets.

- Window size: 128 packets (128-bit integer bitmask)
- Packets arrive out of order within the window are accepted
- Packets older than `highest_seq - 128` are unconditionally rejected
- Two-phase design: `can_accept()` check before AEAD; `mark_seen()` only after
  AEAD authentication succeeds — prevents a forged packet from permanently
  blocking replay of the genuine packet at that sequence number

---

## 10. Session Teardown

A sender issues a FIN packet (no payload, sequence number incremented). The
receiver acknowledges with FIN_ACK. Either side may send FIN at any time.
After sending FIN and receiving FIN_ACK, the session state is released.

---

## 11. Keepalive

If no DATA or ACK packet is sent within `KEEPALIVE_INTERVAL` (15 seconds),
the sender emits a KEEPALIVE packet (no payload). If no packet is received
for 3 × `KEEPALIVE_INTERVAL` the session is considered dead and torn down.

---

## 12. Constants Reference

| Constant              | Value       |
|-----------------------|-------------|
| SMRP_MAGIC            | 0x534D5250  |
| SMRP_VERSION          | 0x01        |
| HEADER_LEN            | 54 bytes    |
| MAX_PAYLOAD           | 1280 bytes  |
| AUTH_TAG_LEN          | 16 bytes    |
| MAX_PACKET            | 1350 bytes  |
| SESSION_ID_LEN        | 8 bytes     |
| NONCE_LEN             | 12 bytes    |
| REPLAY_WINDOW_SIZE    | 128 packets |
| KEEPALIVE_INTERVAL    | 15 seconds  |
| MAX_SESSIONS          | 100 000     |

---

## 13. Security Considerations

### Threat Model

- Active network attacker (can inject, replay, reorder, drop packets)
- Passive attacker (can observe all traffic)
- Compromised ephemeral keys (forward secrecy limits blast radius)

### Forward Secrecy

Ephemeral X25519 keypairs are generated per-session and discarded immediately
after key derivation. Past sessions cannot be decrypted even if long-term
signing keys are later compromised.

### Replay

The 128-packet sliding window rejects replayed packets. Sequence numbers are
authenticated via AEAD AAD, preventing sequence-number manipulation.

### Known Weaknesses

- No certificate infrastructure — caller must distribute signing public keys
  out of band or accept TOFU (trust on first use)
- Timing side-channels in ring are assumed handled by the ring crate; no
  additional mitigations are applied
- No DoS rate-limiting — a flood of HELLO packets will exhaust session slots

---

*End of Specification*
