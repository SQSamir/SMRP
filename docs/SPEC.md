# SMRP Protocol Specification

**Version:** 0.2  
**Status:** Draft  
**Authors:** Samir Gasimov

> **Changelog v0.1→v0.2:** Corrected header layout to include `ack_number`
> field; corrected packet-type wire values; corrected flag bit definitions;
> corrected error-code table; added KeepaliveAck, KeyUpdate, KeyUpdateAck;
> marked FIN_ACK, Reset, Ping as planned.

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

All integers are **big-endian**.

```
Offset  Size  Field
------  ----  -----
0       4     Magic = 0x534D5250 ("SMRP")
4       1     Version = 0x01
5       1     Packet Type  (see §4)
6       1     Flags        (see §5)
7       1     Reserved (must be 0x00)
8       8     Session ID
16      8     Sequence Number — monotonically increasing per sender direction
24      8     ACK Number    — highest contiguous sequence number received from peer
32      8     Timestamp     — microseconds since Unix epoch (sender clock)
40      2     Payload Length — bytes of encrypted payload following the header
42      12    Reserved / padding (must be 0x00)
--- total header: 54 bytes ---
54      N     Encrypted Payload (N = Payload Length, 0 ≤ N ≤ 1 280)
54+N    16    Poly1305 Authentication Tag
```

Maximum payload: **1 280 bytes**.  
Maximum on-wire packet: 54 + 1 280 + 16 = **1 350 bytes**.

### 3.1 Packet diagram

```
 0       4       8       12      16      20      24
 +-------+---+---+---+---+-------+-------+-------+
 | Magic |Ver|Typ|Flg|Rsv|    Session ID (8)      |
 +-------+---+---+---+---+-------+-------+-------+
 |          Sequence Number (8)                   |
 +-------+-------+-------+-------+-------+-------+
 |           ACK Number (8)                       |
 +-------+-------+-------+-------+-------+-------+
 |           Timestamp µs (8)                     |
 +---+---+-------+-------+-------+-------+-------+
 |PLen(2)|          Reserved / Padding (12)       |
 +-------+-------+-------+-------+-------+-------+
 |  Encrypted Payload (0–1280 bytes)              |
 |  + 16-byte Poly1305 authentication tag         |
 +-------+-------+-------+-------+-------+-------+
```

---

## 4. Packet Types

| Wire | Name          | Direction | Description                                    |
|------|---------------|-----------|------------------------------------------------|
| 0x01 | HELLO         | C→S       | Handshake initiation — carries eph pub key     |
| 0x02 | HELLO_ACK     | S→C       | Handshake response — carries server eph pub key |
| 0x03 | DATA          | C↔S       | Application data (AEAD-encrypted)              |
| 0x04 | ACK           | C↔S       | Cumulative acknowledgement (no payload)        |
| 0x05 | KEEPALIVE     | C↔S       | Liveness probe when session is idle            |
| 0x06 | KEEPALIVE_ACK | C↔S       | Response to KEEPALIVE                          |
| 0x07 | KEY_UPDATE    | C↔S       | Initiate in-band rekeying (forward secrecy)    |
| 0x08 | KEY_UPDATE_ACK| C↔S       | Acknowledge completion of KEY_UPDATE           |
| 0x09 | FIN           | C↔S       | Graceful session teardown                      |
| 0x0A | ERROR         | C↔S       | Signal a protocol error to the peer            |
| 0x0B | FIN_ACK       | C↔S       | Acknowledge FIN *(planned)*                    |
| 0x0C | RESET         | C↔S       | Immediate session abort *(planned)*            |
| 0x0D | PING          | C↔S       | RTT measurement request *(planned)*            |
| 0x0E | PONG          | C↔S       | RTT measurement response *(planned)*           |

---

## 5. Flags

| Bit | Mask | Name                 | Meaning                                       |
|-----|------|----------------------|-----------------------------------------------|
| 0   | 0x01 | FIN                  | Set in FIN packets to signal teardown         |
| 1   | 0x02 | KEY_UPDATE_REQUESTED | Sender wants to begin a KEY_UPDATE exchange   |
| 2–7 | —    | Reserved             | Must be 0                                     |

---

## 6. Error Codes

Carried in ERROR packets (payload byte 0) and surfaced via `SmrpError`.

| Wire | Rust variant          | Meaning                                       |
|------|-----------------------|-----------------------------------------------|
| 0x00 | NoError               | No error; sentinel in ACK packets             |
| 0x01 | MalformedHeader       | Header parse failure or truncation            |
| 0x02 | InvalidMagic          | Magic bytes ≠ 0x534D5250                      |
| 0x03 | UnsupportedVersion    | Version byte not recognised                   |
| 0x04 | AuthenticationFailure | AEAD tag verification failed                  |
| 0x05 | UnknownSession        | Session ID not found in server state          |
| 0x06 | ReplayDetected        | Sequence number outside or already in window  |
| 0x07 | HandshakeTimeout      | HELLO_ACK not received within timeout         |
| 0x08 | SessionLimitExceeded  | Server is at MAX_SESSIONS capacity            |
| 0x09 | PayloadTooLarge       | Payload length exceeds MAX_PAYLOAD            |
| 0x0A | InternalError         | Unexpected internal failure                   |

---

## 7. Handshake

### 7.1 State Machine

```
Client                              Server
  │ [CLOSED]                          │ [LISTENING]
  │                                   │
  │── HELLO ─────────────────────────>│ verify Ed25519 sig
  │   [HELLO_SENT]                    │ generate server eph keypair
  │                                   │ derive session keys
  │<─ HELLO_ACK ──────────────────────│ [ESTABLISHED]
  │   verify Ed25519 sig              │
  │   derive session keys             │
  │   [ESTABLISHED]                   │
  │                                   │
  │══ DATA ══════════════════════════>│
  │<═ DATA ═══════════════════════════│
```

### 7.2 HELLO / HELLO_ACK Payload (128 bytes, unencrypted)

```
Offset  Size  Field
0       32    Ephemeral X25519 public key
32      32    Ed25519 signing public key
64      64    Ed25519 signature over (session_id[8] ‖ eph_pub[32])
```

Both sides sign and verify. This provides mutual authentication without a PKI:
each party proves possession of the signing private key.

### 7.3 Key Derivation

```
shared_secret = X25519(eph_priv_local, eph_pub_peer)          # 32 bytes

c2s_key = HKDF-SHA256(ikm=shared, salt=session_id, info="smrp-v1-c2s")[0..32]
s2c_key = HKDF-SHA256(ikm=shared, salt=session_id, info="smrp-v1-s2c")[0..32]
```

Client sends with `c2s_key`, receives with `s2c_key`.  
Server sends with `s2c_key`, receives with `c2s_key`.

### 7.4 Session ID

8-byte cryptographically random value generated by the client, carried in every
packet header. HELLO packets from an unknown session ID are treated as new
connection requests.

### 7.5 HELLO Timestamp Validation

Server rejects HELLO packets whose `timestamp_us` header field is more than
**30 seconds** in the past or future relative to the server's clock. This
limits the replay window for HELLO packets to 60 seconds.

---

## 8. Data Transfer

### 8.1 Encryption

Each DATA packet payload is encrypted with ChaCha20-Poly1305:

```
nonce = session_id[0..4] ‖ seq_be[8]            # 12 bytes
aad   = session_id[0..8] ‖ seq_be[8]            # 16 bytes
(ciphertext ‖ tag) = ChaCha20Poly1305.seal(send_key, nonce, plaintext, aad)
```

The 16-byte Poly1305 tag is appended immediately after the ciphertext.

### 8.2 Sequence Numbers

Unsigned 64-bit, zero-based, incrementing by 1 per DATA packet per direction.
Included in the header unencrypted and committed into both nonce and AAD so any
tampering is detected.

### 8.3 ACK

After receiving a DATA packet the receiver sends an ACK with
`ack_number = sequence_number` of the DATA just processed and no payload. The
sender's `ack_number` field in DATA packets carries the cumulative ACK for the
reverse direction.

---

## 9. Anti-Replay Window

RFC 6479 sliding window, 128-bit bitmask.

- Window size: **128 packets**
- Packets within the window but with a bit already set → `ReplayDetected`
- Packets more than 127 below the highest seen → `ReplayDetected`
- **Two-phase design**: `can_accept(seq)` check before AEAD open;
  `mark_seen(seq)` only after successful AEAD — prevents window poisoning by
  forged packets with a valid-looking sequence number.

---

## 10. Session Teardown

### Active close (initiator)

1. Initiator sends FIN (`seq=N`, FIN flag set)
2. Peer replies with FIN_ACK (`ack_number=N`)
3. Initiator may then release session state

### Passive close (responder)

On FIN receipt, peer sends FIN_ACK and transitions to CLOSED.

Both sides must respond to FIN within `KEEPALIVE_INTERVAL` × 3 or the session
is force-torn-down without FIN_ACK.

---

## 11. Keepalive and Session Eviction

If no DATA, ACK, or any other packet is sent for `KEEPALIVE_INTERVAL` (15 s),
the sender MUST emit a KEEPALIVE (no payload).

The peer MUST reply with KEEPALIVE_ACK.

If no packet is received for `3 × KEEPALIVE_INTERVAL` (45 s) the session is
considered dead and all state is released without sending FIN.

---

## 12. In-Band Key Update

To achieve periodic forward secrecy without a full re-handshake:

1. Either side sets the `KEY_UPDATE_REQUESTED` flag in any DATA or ACK packet.
2. Peer responds with a KEY_UPDATE packet carrying a fresh ephemeral public key.
3. Initiator replies with KEY_UPDATE_ACK carrying its fresh ephemeral public key.
4. Both sides derive new `send_key` / `recv_key` via the same HKDF process,
   using the new shared secret and a new salt derived from the current session
   state. Old keys are discarded.

*(Implementation: planned)*

---

## 13. Constants Reference

| Constant              | Value       |
|-----------------------|-------------|
| SMRP_MAGIC            | 0x534D5250  |
| SMRP_VERSION          | 0x01        |
| HEADER_LEN            | 54 bytes    |
| MAX_PAYLOAD           | 1 280 bytes |
| AUTH_TAG_LEN          | 16 bytes    |
| MAX_PACKET            | 1 350 bytes |
| SESSION_ID_LEN        | 8 bytes     |
| NONCE_LEN             | 12 bytes    |
| REPLAY_WINDOW_SIZE    | 128 packets |
| KEEPALIVE_INTERVAL    | 15 seconds  |
| SESSION_DEAD_TIMEOUT  | 45 seconds  |
| HELLO_CLOCK_SKEW_SECS | 30 seconds  |
| MAX_SESSIONS          | 100 000     |

---

## 14. Security Considerations

### Threat Model

- Active network attacker (inject, replay, reorder, drop packets)
- Passive attacker (observe all traffic)
- Compromised long-term signing keys (forward secrecy via ephemeral keys)

### Forward Secrecy

Ephemeral X25519 keypairs are generated per-session and discarded immediately
after key derivation. In-band key update (§12) extends this to sub-session
granularity.

### Replay Protection

Two-layer defence:
1. HELLO timestamp validation (§7.5) — limits HELLO replay to ±30 s window
2. DATA sequence-number window (§9) — rejects any replayed DATA packet

### DoS Mitigations

- HELLO rate limiting: max 10 HELLO packets per source IP per second; excess
  silently dropped before any crypto is performed
- Half-open session limit: sessions in HANDSHAKING state count against a
  separate, lower limit (1 000) so a HELLO flood cannot exhaust the full
  MAX_SESSIONS quota
- MAX_SESSIONS hard cap: HELLO beyond the limit is rejected with an ERROR
  packet (SessionLimitExceeded)

### Known Weaknesses

- No certificate infrastructure — signing keys distributed out-of-band or TOFU
- No fragmentation — callers must split payloads over MAX_PAYLOAD themselves
- No congestion control — unreliable transport by design

---

*End of Specification v0.2*
