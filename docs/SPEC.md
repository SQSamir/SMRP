# SMRP Protocol Specification

**Version:** 0.6  
**Status:** Draft  
**Authors:** Samir Gasimov

> **Changelog v0.5→v0.6:** In-band key update implemented (§12) — `KEY_UPDATE`
> and `KEY_UPDATE_ACK` are now fully handled; `request_key_update()` API added;
> Ed25519 identity pinning enforced on rekey; `smrp-v1-rekey-c2s` /
> `smrp-v1-rekey-s2c` HKDF info strings defined; known weaknesses updated.
>
> **Changelog v0.4→v0.5:** Ordered in-order delivery implemented (§8.5) —
> out-of-order DATA packets are buffered and delivered to the application in
> send order; AIMD congestion control implemented (§8.6) — slow-start + AIMD
> congestion avoidance; `send()` backpressures when the congestion window is
> full; updated §13.2 with two new config fields (`initial_cwnd`,
> `recv_buf_limit`); updated §15.1 (SmrpConfig); removed "No congestion
> control" from Known Weaknesses.
>
> **Changelog v0.3→v0.4:** Retransmission implemented (§8.4) — removed from
> Known Weaknesses; RESET, PING, PONG marked as implemented; added persistent
> Ed25519 signing key API (§15.5); updated §13.2 with four new retransmission
> config fields; updated §15 (SmrpConfig, SmrpMetrics, SmrpListener) to reflect
> new API; corrected §8.3 ACK semantics to document retransmit-drain behaviour.

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

Non-goals: fragmentation, PKI, full TCP-like flow control.

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

| Wire | Name           | Direction | Description                                    | Status      |
|------|----------------|-----------|------------------------------------------------|-------------|
| 0x01 | HELLO          | C→S       | Handshake initiation — carries eph pub key     | Implemented |
| 0x02 | HELLO_ACK      | S→C       | Handshake response — carries server eph pub key| Implemented |
| 0x03 | DATA           | C↔S       | Application data (AEAD-encrypted)              | Implemented |
| 0x04 | ACK            | C↔S       | Cumulative acknowledgement (no payload)        | Implemented |
| 0x05 | KEEPALIVE      | C↔S       | Liveness probe when session is idle            | Implemented |
| 0x06 | KEEPALIVE_ACK  | C↔S       | Response to KEEPALIVE                          | Implemented |
| 0x07 | KEY_UPDATE     | C↔S       | Initiate in-band rekeying (forward secrecy)    | Implemented |
| 0x08 | KEY_UPDATE_ACK | C↔S       | Acknowledge completion of KEY_UPDATE           | Implemented |
| 0x09 | FIN            | C↔S       | Graceful session teardown                      | Implemented |
| 0x0A | ERROR          | C↔S       | Signal a protocol error to the peer            | Implemented |
| 0x0B | FIN_ACK        | C↔S       | Acknowledge FIN; completes graceful teardown   | Implemented |
| 0x0C | RESET          | C↔S       | Immediate session abort (no acknowledgement)   | Implemented |
| 0x0D | PING           | C↔S       | RTT measurement request                        | Implemented |
| 0x0E | PONG           | C↔S       | RTT measurement response                       | Implemented |

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

Wire codes 0x0B and above decode to `InternalError`.

---

## 7. Handshake

### 7.1 State Machine

The `SessionState` enum defines the following states:

```
Init → HelloSent ──────────────────────────────────────────────────┐
Init → HelloReceived ──────────────────────────────────────────┐   │
                                                               ↓   ↓
                                                          Established
                                                               │
                                                    ┌──────────┼──────────┐
                                                    ↓          ↓          ↓
                                                 KeyUpdate  Closing    Error
                                                              ↓
                                                           Closed
```

On-wire handshake exchange:

```
Client                              Server
  │ [Init]                            │ [Listening]
  │                                   │
  │── HELLO ─────────────────────────>│ verify Ed25519 sig
  │   [HelloSent]                     │ generate server eph keypair
  │                                   │ derive session keys
  │<─ HELLO_ACK ──────────────────────│ [Established]
  │   verify Ed25519 sig              │
  │   derive session keys             │
  │   [Established]                   │
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

The signature covers `session_id || eph_pub` (40 bytes total), binding the
ephemeral key to the session and preventing cross-session key transplant attacks.

### 7.3 Key Derivation

```
shared_secret = X25519(eph_priv_local, eph_pub_peer)          # 32 bytes

c2s_key = HKDF-SHA256(ikm=shared, salt=session_id, info="smrp-v1-c2s")[0..32]
s2c_key = HKDF-SHA256(ikm=shared, salt=session_id, info="smrp-v1-s2c")[0..32]
```

Client sends with `c2s_key`, receives with `s2c_key`.  
Server sends with `s2c_key`, receives with `c2s_key`.

The session ID acts as the HKDF salt, meaning two sessions with different IDs
but the same ephemeral key material derive completely different keys.

### 7.4 Session ID

8-byte cryptographically random value generated by the client, carried in every
packet header. HELLO packets from an unknown session ID are treated as new
connection requests.

### 7.5 HELLO Timestamp Validation

Server rejects HELLO packets whose `timestamp_us` header field is more than
**30 seconds** in the past or future relative to the server's clock
(configurable via `SmrpConfig::hello_clock_skew`). This limits the replay
window for HELLO packets to ± `hello_clock_skew`.

---

## 8. Data Transfer

### 8.1 Encryption

Each DATA packet payload is encrypted with ChaCha20-Poly1305:

```
nonce = session_id[0..4] ‖ seq_be[8]            # 12 bytes total
aad   = session_id[0..8] ‖ seq_be[8]            # 16 bytes total
(ciphertext ‖ tag) = ChaCha20Poly1305.seal(send_key, nonce, plaintext, aad)
```

The 16-byte Poly1305 tag is appended immediately after the ciphertext.

The nonce embeds the first 4 bytes of the session ID and the full 8-byte
sequence number, ensuring nonce uniqueness across sessions and packets.

The AAD commits the full session ID and sequence number into the authenticated
data, so any header tampering (session ID spoofing, sequence number reordering)
is detected by the AEAD verification.

### 8.2 Sequence Numbers

Unsigned 64-bit, starting at 1 (first DATA packet has seq=1), incrementing by 1
per DATA packet per direction. Carried unencrypted in the header and committed
into both nonce and AAD so any tampering is detected. The sequence number space
is effectively unbounded at typical data rates.

### 8.3 ACK

After receiving a DATA packet the receiver sends an ACK with
`ack_number = sequence_number` of the DATA just processed and no payload. The
sender's `ack_number` field in DATA packets carries the cumulative ACK for the
reverse direction. On receipt of an ACK the matching entry is removed from the
sender's retransmit buffer (see §8.4).

**Courtesy ACK on replay detection:** If the replay window rejects a DATA packet
(sequence number already seen), the receiver still sends an ACK. This handles
the common case where the peer did not receive the first ACK and is retransmitting.

### 8.4 Retransmission

SMRP implements per-packet reliable delivery using a retransmit buffer keyed by
sequence number.

**Algorithm:**

1. When `send()` is called, the DATA packet (header + encrypted ciphertext) is
   inserted into an in-memory retransmit buffer.
2. A background retransmit task wakes every `rto_min` (default: 50 ms) and
   inspects each pending entry.
3. If `elapsed ≥ RTO`, the packet is re-sent with a refreshed `timestamp_us`
   and the retry counter is incremented.
4. After each retransmit cycle the RTO is doubled (exponential backoff), capped
   at `rto_max`.
5. If an entry's retry counter reaches `max_retransmits`, the session is
   declared dead and `recv()` returns `Ok(None)`.
6. When an ACK is received, the corresponding entry is removed from the buffer.

**RTT Estimation (Jacobson/Karels):**

```
α = 1/8  (SRTT smoothing factor)
β = 1/4  (RTTVAR smoothing factor)

RTTVAR = (1-β)·RTTVAR + β·|SRTT - Ri|
SRTT   = (1-α)·SRTT   + α·Ri
RTO    = SRTT + 4·RTTVAR   (clamped to [rto_min, rto_max])
```

**Karn's algorithm:** RTT samples are only taken from DATA packets with
`retries == 0` (first transmission). Retransmitted packets are excluded because
it is ambiguous whether an ACK was triggered by the original or the retransmit.

**Retransmission config fields** (all in `SmrpConfig`):

| Field            | Default | Meaning                                          |
|------------------|---------|--------------------------------------------------|
| `max_retransmits`| 5       | Max retries per packet before session is dead    |
| `rto_initial`    | 200 ms  | Starting RTO before any RTT samples              |
| `rto_min`        | 50 ms   | Floor for RTO and retransmit-task check interval |
| `rto_max`        | 30 s    | Ceiling for exponential backoff                  |

### 8.5 Ordered Delivery

Even though SMRP runs over UDP, the application always receives DATA in the
order the sender originally sent them.

**Implementation:**

1. The receiver maintains a reorder buffer (`BTreeMap<seq, plaintext>`) of
   capacity `recv_buf_limit` (default: 256).
2. Every authenticated DATA packet is ACKed immediately so the sender can
   advance its retransmit buffer and congestion window.
3. The decrypted payload is inserted into the reorder buffer keyed by its
   sequence number.
4. The receiver then drains contiguous entries starting from `next_deliver_seq`
   into an in-order delivery queue.
5. `recv()` returns entries from the delivery queue before pulling new packets
   from the network, guaranteeing in-order application delivery.
6. Out-of-order packets that arrive more than `recv_buf_limit` ahead of the
   current delivery head are silently dropped; the peer will retransmit them.

### 8.6 AIMD Congestion Control

SMRP uses a simplified TCP-style AIMD algorithm to limit the number of
unacknowledged DATA packets in flight.

**Congestion window (cwnd):**

- Initial value: `initial_cwnd` (default: 4 packets)
- During **slow-start** (`cwnd < ssthresh`): increment cwnd by 1 for each ACK
  received.
- During **congestion avoidance** (`cwnd ≥ ssthresh`): increment cwnd by 1 when
  a full window of ACKs has been received (i.e., every `cwnd` ACKs add 1).
- On **retransmit** (packet loss signal): `ssthresh = max(cwnd/2, 2)`,
  `cwnd = 1` — re-enter slow-start.

**Backpressure:**

`send()` blocks asynchronously when `pending_acks ≥ cwnd`. It registers a
`Notify` listener *before* checking the window size to avoid the lost-wake
race: if an ACK arrives between the check and the await, the notification is
captured and `send()` returns immediately on the next iteration.

**API constraint:** Because `send()` and `recv()` both require `&mut self`,
they cannot run concurrently on the same connection. ACKs are only processed
inside `recv_inner`. Callers that need to send more than `initial_cwnd`
messages without interleaved `recv()` calls will deadlock. In those cases
use a task-based split where one task sends and another receives.

**Congestion control config fields:**

| Field            | Default | Meaning                                       |
|------------------|---------|-----------------------------------------------|
| `initial_cwnd`   | 4       | Starting congestion window (packets in flight)|
| `recv_buf_limit` | 256     | Max out-of-order packets in reorder buffer    |

### 8.7 RESET

On receipt of a RESET packet the session is closed immediately. No FIN_ACK is
exchanged. `recv()` returns `Ok(None)`. The sender of RESET does not wait for
any acknowledgement.

### 8.8 PING / PONG

PING is a one-way RTT probe. The receiver replies with PONG, echoing the PING's
`timestamp_us` into its own `timestamp_us` field and the PING's `sequence_number`
into `ack_number`. The original sender subtracts the echoed timestamp from its
current clock to compute the round-trip time without requiring clock
synchronisation.

The PONG RTT sample is fed into the same Jacobson/Karels estimator as DATA ACKs.

---

## 9. Anti-Replay Window

RFC 6479 sliding window, 128-bit bitmask.

- Window size: **128 packets**
- Packets within the window but with a bit already set → `ReplayDetected`
- Packets more than 127 below the highest seen → `ReplayDetected`
- **Two-phase design**: `can_accept(seq)` is called *before* AEAD decryption;
  `mark_seen(seq)` is called *only after* successful AEAD open.

The two-phase design prevents a DoS where an attacker injects forged packets
with a valid sequence number, causing the window slot to be consumed before the
legitimate packet arrives. A failed AEAD open does not advance the window.

---

## 10. Session Teardown

### Active close (initiator)

1. Initiator sends FIN (`seq=N`, FIN flag set in flags byte)
2. Peer replies with FIN_ACK (`ack_number=N`)
3. Initiator releases session state

The initiator waits for FIN_ACK for at most `fin_ack_timeout` (default: 5 s,
configurable via `SmrpConfig`). If no FIN_ACK arrives within this window, the
session state is released unilaterally.

### Passive close (responder)

On receiving FIN, the peer sends FIN_ACK immediately and transitions to `Closed`.

---

## 11. Keepalive and Session Eviction

### Keepalive probes

If no packet has been *received* from the peer for `keepalive_interval` (default
15 s, configurable), the local side sends a KEEPALIVE (no encrypted payload).
The peer MUST reply with KEEPALIVE_ACK.

The keepalive timer is driven by the time since the last *received* packet,
not the last sent packet, so one-sided senders still detect peer failures.

### Dead session eviction

If no packet has been received from the peer for `session_dead_timeout` (default
45 s, configurable; should be ≥ 3 × `keepalive_interval`), the session is
declared dead:

- The `recv()` call returns `Ok(None)` to the application.
- The session is removed from the server's session map.
- The `sessions_active` metric is decremented.
- The `sessions_evicted_dead` metric is incremented.

No FIN is sent on eviction — the peer is assumed unreachable.

---

## 12. In-Band Key Update

*(Status: Implemented — packet types 0x07/0x08 fully handled; API: `request_key_update()`)*

Either party may initiate a key update at any time to rotate session keys without
a full re-handshake, providing sub-session forward secrecy.

### 12.1 Protocol Flow

```
Initiator                          Responder
  │                                    │
  │── KEY_UPDATE (eph_pub_i, sig) ────>│  verify sig
  │   seq = rekey_counter              │  generate eph keypair r
  │                                    │  send KEY_UPDATE_ACK
  │<── KEY_UPDATE_ACK (eph_pub_r, sig) │  derive and install new keys
  │    seq = rekey_counter             │
  │  verify sig                        │
  │  derive and install new keys       │
```

### 12.2 Payload Layout (128 bytes, unencrypted)

```
Offset  Size  Field
0       32    New ephemeral X25519 public key
32      32    Ed25519 signing public key (pinned from handshake)
64      64    Ed25519 signature over (session_id[8] ‖ new_eph_pub[32] ‖ rekey_counter_be[8])
```

The signature binds the new ephemeral key to the session ID and a monotonically
increasing `rekey_counter`, preventing replay of old `KEY_UPDATE` messages.

### 12.3 Key Derivation

```
shared_secret = X25519(local_eph_priv, peer_eph_pub)

salt = session_id[8] ‖ rekey_counter_be[8]

c2s = HKDF-SHA256(shared_secret, salt, "smrp-v1-rekey-c2s")
s2c = HKDF-SHA256(shared_secret, salt, "smrp-v1-rekey-s2c")
```

Client: `send_key = c2s`, `recv_key = s2c`  
Server: `send_key = s2c`, `recv_key = c2s`

The client/server asymmetry established during the initial handshake is preserved
across all subsequent rekeys.

### 12.4 Identity Pinning

The Ed25519 signing public key in the payload must match the key pinned during
the handshake. A `KEY_UPDATE` payload carrying a different signing key is
rejected as an `AuthenticationFailure`, preventing identity substitution attacks.

### 12.5 API and Sequencing Constraint

```rust
// Blocks until KEY_UPDATE_ACK is received and new keys are installed.
async fn request_key_update(&mut self) -> Result<(), SmrpError>
```

`request_key_update()` blocks internally until the full exchange completes.
All `send()` calls after it return will use the rotated keys.

**Prerequisite:** The retransmit buffer must be empty before calling
`request_key_update()`. Any packets still in the buffer will be retransmitted
after the key switch using the old ciphertext, which the peer (now holding new
keys) will reject as an authentication failure, causing the session to be
declared dead. Ensure all sent data has been acknowledged — typically by calling
`recv()` until all expected replies are received.

---

## 13. Constants Reference

### 13.1 Compile-time constants (`constants.rs`)

These are fixed at compile time and never change at runtime.

| Constant         | Value       | Notes                                      |
|------------------|-------------|--------------------------------------------|
| SMRP_MAGIC       | 0x534D5250  | ASCII "SMRP" big-endian                    |
| SMRP_VERSION     | 0x01        | Wire version byte                          |
| HEADER_LEN       | 54 bytes    | Fixed packet header size                   |
| MAX_PAYLOAD      | 1 280 bytes | Maximum plaintext application payload      |
| AUTH_TAG_LEN     | 16 bytes    | Poly1305 tag appended to every ciphertext  |
| MAX_PACKET       | 1 350 bytes | MAX_PAYLOAD + HEADER_LEN + AUTH_TAG_LEN    |
| SESSION_ID_LEN   | 8 bytes     | Session identifier size                    |
| NONCE_LEN        | 12 bytes    | ChaCha20-Poly1305 nonce size               |
| REPLAY_WINDOW    | 128 packets | RFC 6479 sliding window size               |

### 13.2 Runtime-configurable defaults (`SmrpConfig`)

These defaults can be overridden per listener or connection via `SmrpConfig`.
See §15.1 for the full API.

| Parameter               | Default    | Notes                                          |
|-------------------------|------------|------------------------------------------------|
| keepalive_interval      | 15 s       | How often to send KEEPALIVE when idle          |
| session_dead_timeout    | 45 s       | Evict session if no traffic for this long      |
| hello_clock_skew        | 30 s       | Max clock difference for HELLO timestamp check |
| hello_rate_limit        | 10 / IP/s  | HELLO rate limit before any crypto             |
| max_sessions            | 100 000    | Hard cap on concurrent sessions                |
| connect_timeout         | 10 s       | Timeout for SmrpConnection::connect()          |
| recv_timeout            | 60 s       | Default timeout for SmrpConnection::recv()     |
| fin_ack_timeout         | 5 s        | How long close() waits for FIN_ACK             |
| session_channel_capacity| 256 pkts   | Per-session in-flight packet buffer            |
| accept_queue_capacity   | 64 conns   | New-connection queue depth at SmrpListener     |
| max_retransmits         | 5          | Max retransmit attempts before session dead    |
| rto_initial             | 200 ms     | Initial retransmission timeout                 |
| rto_min                 | 50 ms      | Minimum RTO (also retransmit-task interval)    |
| rto_max                 | 30 s       | Maximum RTO (exponential backoff ceiling)      |
| initial_cwnd            | 4 pkts     | Starting congestion window (see §8.6)          |
| recv_buf_limit          | 256 pkts   | Max out-of-order packets in reorder buffer     |

---

## 14. Security Considerations

### Threat Model

- Active network attacker (inject, replay, reorder, drop packets)
- Passive attacker (observe all traffic)
- Compromised long-term signing keys (forward secrecy via ephemeral keys)

### Forward Secrecy

Ephemeral X25519 keypairs are generated per-session and discarded immediately
after key derivation. Compromise of long-term signing keys after session
establishment does not expose past session traffic.

In-band key update (§12) will extend this to sub-session granularity when
implemented.

### Replay Protection

Two-layer defence:

1. **HELLO timestamp validation (§7.5)** — limits HELLO replay to a 60-second
   window (±30 s from server clock, configurable)
2. **DATA sequence-number window (§9)** — rejects any replayed DATA packet
   using an RFC 6479 sliding window; two-phase design prevents window poisoning

### DoS Mitigations

| Mechanism              | Detail                                               |
|------------------------|------------------------------------------------------|
| HELLO rate limiting    | 10 HELLO/IP/s (configurable); excess dropped before any crypto runs |
| HELLO timestamp check  | Stale/future HELLOs rejected before signature verification |
| MAX_SESSIONS hard cap  | HELLOs beyond `max_sessions` receive ERROR(SessionLimitExceeded) |
| Dead session eviction  | Sessions with no traffic for `session_dead_timeout` are freed automatically |

### Known Weaknesses

- **No certificate infrastructure** — signing keys distributed out-of-band or
  TOFU; no revocation
- **No fragmentation** — callers must split payloads over MAX_PAYLOAD themselves
- **Basic congestion control only** — AIMD is implemented (§8.6) but there is
  no ECN, pacing, or bandwidth estimation; the `&mut self` API means send and
  recv cannot run concurrently on one connection (see §8.6 API constraint)
- **KEY_UPDATE sequential constraint** — `request_key_update()` requires the
  retransmit buffer to be empty; in-flight packets at rekey time will cause
  session death. Callers must drain pending ACKs before initiating a rekey.
- **Nonce entropy** — the 12-byte nonce uses only 32 bits of session ID entropy;
  within a session nonce uniqueness is guaranteed by the 64-bit sequence number,
  but cross-session collision probability should be considered at very high
  session counts
- **Not audited** — cryptographic usage has not been reviewed by a third party

---

## 15. Implementation API

### 15.1 SmrpConfig

```rust
pub struct SmrpConfig {
    pub keepalive_interval:       Duration,  // default: 15 s
    pub session_dead_timeout:     Duration,  // default: 45 s
    pub hello_clock_skew:         Duration,  // default: 30 s
    pub hello_rate_limit:         u32,       // default: 10 / IP / s
    pub max_sessions:             usize,     // default: 100 000
    pub connect_timeout:          Duration,  // default: 10 s
    pub recv_timeout:             Duration,  // default: 60 s
    pub fin_ack_timeout:          Duration,  // default: 5 s
    pub session_channel_capacity: usize,     // default: 256
    pub accept_queue_capacity:    usize,     // default: 64
    pub max_retransmits:          u32,       // default: 5
    pub rto_initial:              Duration,  // default: 200 ms
    pub rto_min:                  Duration,  // default: 50 ms
    pub rto_max:                  Duration,  // default: 30 s
    pub initial_cwnd:             usize,     // default: 4
    pub recv_buf_limit:           usize,     // default: 256
}

impl Default for SmrpConfig { ... }
```

Pass an `Arc<SmrpConfig>` to `SmrpListener::bind_with_config` or
`SmrpConnection::connect_with_config` to override defaults.

### 15.2 SmrpMetrics

Atomic counters exposed by `SmrpListener::metrics()`:

```rust
pub struct SmrpMetrics {
    // Session lifecycle (sessions_active is a gauge; all others are counters)
    pub sessions_active:          AtomicU64,
    pub sessions_total:           AtomicU64,
    pub sessions_evicted_dead:    AtomicU64,

    // HELLO rejection (counted before any crypto)
    pub hello_drops_rate_limit:   AtomicU64,
    pub hello_drops_clock_skew:   AtomicU64,
    pub hello_drops_capacity:     AtomicU64,

    // Data plane
    pub packets_sent:             AtomicU64,
    pub packets_received:         AtomicU64,
    pub bytes_sent:               AtomicU64,  // plaintext bytes
    pub bytes_received:           AtomicU64,  // plaintext bytes
    pub packets_retransmitted:    AtomicU64,

    // Security events
    pub auth_failures:            AtomicU64,
    pub replay_detections:        AtomicU64,
}
```

Use `SmrpMetrics::snapshot()` for a `MetricsSnapshot` (plain `u64` fields)
suitable for dashboards and logging. Individual fields may be read directly
via `load(Ordering::Relaxed)` for cheap one-shot reads.

### 15.3 SmrpListener

```rust
// Bind with default config
async fn bind(addr: &str) -> Result<SmrpListener, SmrpError>

// Bind with custom config (generates a fresh ephemeral signing key)
async fn bind_with_config(addr: &str, cfg: Arc<SmrpConfig>) -> Result<SmrpListener, SmrpError>

// Bind with a persistent caller-supplied Ed25519 signing key
async fn bind_with_config_and_key(
    addr: &str, cfg: Arc<SmrpConfig>, sign_key: SigningKey,
) -> Result<SmrpListener, SmrpError>

// Accept the next incoming connection (returns None after shutdown)
async fn accept(&mut self) -> Option<SmrpConnection>

// Returns the bound local address
fn local_addr(&self) -> SocketAddr

// Returns the shared metrics handle
fn metrics(&self) -> Arc<SmrpMetrics>

// Returns the active config
fn config(&self) -> Arc<SmrpConfig>

// Graceful shutdown: sends FIN to all connected peers, stops accepting
async fn shutdown(self)
```

### 15.4 SmrpConnection

```rust
// Connect with default config (10 s connect_timeout)
async fn connect(server_addr: &str) -> Result<SmrpConnection, SmrpError>

// Connect with custom config
async fn connect_with_config(server_addr: &str, cfg: Arc<SmrpConfig>)
    -> Result<SmrpConnection, SmrpError>

// Send application data (must be ≤ MAX_PAYLOAD bytes)
async fn send(&mut self, data: &[u8]) -> Result<(), SmrpError>

// Receive next message (uses cfg.recv_timeout; returns None on FIN or dead session)
async fn recv(&mut self) -> Result<Option<Vec<u8>>, SmrpError>

// Receive with a caller-supplied deadline
async fn recv_timeout(&mut self, deadline: Duration) -> Result<Option<Vec<u8>>, SmrpError>

// Graceful close: sends FIN, waits fin_ack_timeout for FIN_ACK
async fn close(self) -> Result<(), SmrpError>

// Returns peer's UDP socket address
fn peer_addr(&self) -> SocketAddr

// Returns raw 8-byte session ID
fn session_id(&self) -> &[u8; 8]
```

### 15.5 SigningKey — Persistent Identity

`SigningKey` (in `smrp_core::crypto`) wraps an Ed25519 key pair with PKCS#8
DER serialisation support.

```rust
// Generate a fresh Ed25519 key pair
fn generate() -> Result<SigningKey, SmrpError>

// Load from PKCS#8 DER bytes (e.g., bytes previously read from disk)
fn from_pkcs8(bytes: &[u8]) -> Result<SigningKey, SmrpError>

// Return the raw PKCS#8 DER bytes for persisting to disk
fn to_pkcs8(&self) -> &[u8]

// Return the 32-byte Ed25519 public key (fingerprint)
fn public_key_bytes(&self) -> &[u8; 32]
```

**Recommended server pattern:**

```rust
const KEY_FILE: &str = "smrp_server.key";

let sign_key = if Path::new(KEY_FILE).exists() {
    let bytes = fs::read(KEY_FILE)?;
    SigningKey::from_pkcs8(&bytes)?
} else {
    let key = SigningKey::generate()?;
    fs::write(KEY_FILE, key.to_pkcs8())?;
    key
};
// Display hex fingerprint so operators can pin the server identity
println!("identity: {}", hex::encode(sign_key.public_key_bytes()));

let listener = SmrpListener::bind_with_config_and_key(addr, cfg, sign_key).await?;
```

Clients performing key pinning should store the server's 32-byte public key
on first connection (TOFU) and reject any future handshake that presents a
different key.

---

### 15.6 SmrpConnection — Key Update API

```rust
// Initiate in-band key rotation (blocks until KEY_UPDATE_ACK received).
// All send() calls after this return use the new session keys.
async fn request_key_update(&mut self) -> Result<(), SmrpError>
```

See §12 for the full protocol description and sequencing requirements.

*End of Specification v0.6*
