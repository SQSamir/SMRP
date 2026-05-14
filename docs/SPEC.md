# SMRP Protocol Specification

**Version:** 1.0  
**Status:** Draft  
**Authors:** Samir Gasimov  
**Wire version byte:** `0x05`

> **Changelog v0.9→1.0 (wire-breaking; version byte `0x05`):**
> Protocol version bumped to `0x05`.
> **Header extended (bytes 42–53):** the twelve previously-reserved bytes now
> carry `frag_id` (u16), `frag_index` (u8), `frag_count` (u8), `recv_window`
> (u16), `stream_id` (u16), and 4 reserved bytes.
> **Fragmentation (§8.9):** payloads larger than `MAX_PAYLOAD` are split
> automatically using the `FRAGMENT` flag and `frag_*` fields; reassembled
> transparently by the receiver.
> **SACK (§8.10):** `SackAck` (0x0F) carries selective ACK ranges; sender
> skips already-received sequences on retransmit.
> **ECN recv-side (§8.11):** `IP_RECVTOS` / `IPV6_RECVTCLASS` socket options
> deliver the TOS/TCLASS byte as ancillary data; CE mark triggers immediate
> cwnd halving (RFC 3168 §6.1.2).
> **ECN outgoing (§8.11):** `IP_TOS` / `IPV6_TCLASS` set to `ECT(0)=0x02`
> on the sending socket; controlled by `SmrpConfig::ecn_enabled`.
> **PMTUD (§8.12):** probe-based path MTU discovery; `effective_payload` steps
> up on ACK and down on 4×RTT timeout; controlled by `SmrpConfig::pmtud_enabled`.
> **Send pacing (§8.13):** token-bucket pacer in `send()`; controlled by
> `SmrpConfig::pacing_enabled`.
> **KEEPALIVE authentication:** both KEEPALIVE and KEEPALIVE_ACK now carry a
> 16-byte Poly1305 MAC. The keepalive task holds a dedicated `KeepaliveAuth`
> shared via `Arc<Mutex<_>>` with a nonce counter starting at `1u64 << 48` to
> avoid collision with the main `ctrl_send_seq` counter.
> **Key update DATA buffering (§12.6):** responder saves the pre-rotation recv
> key so DATA encrypted with the old key (in-flight when initiator received
> `KEY_UPDATE_ACK`) can still be decrypted and delivered.
> **recv_window field:** receiver advertises remaining buffer capacity in
> packets; sender respects `min(cwnd, peer_recv_window)`.
> **Multiplexed streams (§16):** DATA packets carry a `stream_id` (u16); non-
> zero IDs routed to per-stream channels.
> **Connection migration (§17):** `PATH_CHALLENGE` (0x10) / `PATH_RESPONSE`
> (0x11) allow session migration to a new peer address.
> **New config fields:** `max_sack_blocks`, `pmtud_enabled`,
> `pmtud_probe_interval`, `pacing_enabled`, `ecn_enabled`, `max_streams`,
> `migration_enabled`.
> **New error codes:** `StreamClosed` (0x0B), `TooManyStreams` (0x0C).
> **New flag bits:** `FRAGMENT` (bit 2), `ECT` (bit 3), `CE` (bit 4).
>
> **Changelog v0.8→v0.9 (wire-breaking; version byte `0x03`):**
> Authenticated FIN / FIN_ACK (Poly1305 MAC). HELLO_ACK transcript hash
> (`session_id || server_eph_pub || SHA-256(HELLO_payload)`). KEEPALIVE_ACK
> rate-limit (1/s/connection). `crypto::sha256()` added. `docs/STATE_MACHINE.md`
> added. Examples `client.rs` / `server.rs` added.
>
> **Changelog v0.7→v0.8 (non-wire-breaking):**
> Bug fix: `handle_key_update` now performs X25519 `agree()` before sending
> `KEY_UPDATE_ACK`. `initial_ssthresh` added to `SmrpConfig`.
>
> **Changelog v0.6→v0.7 (wire-breaking; version byte `0x02`):**
> HKDF-derived nonce prefixes (§7.3). Authenticated control packets (§8.7).
> `connect_with_pinned_server_key()` API (§15.6). Test vectors (§16 old).
>
> **Changelog v0.5→v0.6:** In-band key update (§12) fully implemented.
>
> **Changelog v0.4→v0.5:** Ordered delivery (§8.5), AIMD congestion control (§8.6).
>
> **Changelog v0.3→v0.4:** Retransmission (§8.4), RESET, PING, PONG, persistent Ed25519 signing key.

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

Non-goals: PKI, full TCP-like flow control, production hardening.

---

## 2. Terminology

- **Session** — a logical connection identified by an 8-byte session ID
- **c2s** — client-to-server direction
- **s2c** — server-to-client direction
- **AAD** — Additional Authenticated Data (not encrypted, but authenticated)
- **eph** — ephemeral (generated fresh per session, discarded after handshake)
- **CE** — ECN Congestion Experienced codepoint (IP TOS bits `0b11`)
- **ECT** — ECN-Capable Transport codepoint (IP TOS bits `0b10`)

---

## 3. Packet Format

All integers are **big-endian**.

```
Offset  Size  Field
------  ----  -----
0       4     Magic = 0x534D5250 ("SMRP")
4       1     Version = 0x05
5       1     Packet Type  (see §4)
6       1     Flags        (see §5)
7       1     Reserved (must be 0x00)
8       8     Session ID
16      8     Sequence Number — monotonically increasing per sender direction
24      8     ACK Number    — highest contiguous sequence number received from peer
32      8     Timestamp     — microseconds since Unix epoch (sender clock)
40      2     Payload Length — bytes of encrypted payload following the header
42      2     frag_id       — fragmentation message ID (0 when not fragmented)
44      1     frag_index    — 0-based fragment position (0 when not fragmented)
45      1     frag_count    — total fragments in message (0 when not fragmented)
46      2     recv_window   — receiver's remaining buffer space in packets
48      2     stream_id     — logical stream identifier; 0 = default stream
50      4     Reserved (must be 0x00)
--- total header: 54 bytes ---
54      N     Encrypted Payload (N = Payload Length, 0 ≤ N ≤ 1 280)
54+N    16    Poly1305 Authentication Tag
```

Maximum payload: **1 280 bytes**.  
Maximum on-wire packet: 54 + 1 280 + 16 = **1 350 bytes**.

### 3.1 Packet diagram

```
 0       4       8      12      16      20      24
 +-------+---+---+---+---+-------+-------+-------+
 | Magic |Ver|Typ|Flg|Rsv|    Session ID (8)      |
 +-------+---+---+---+---+-------+-------+-------+
 |          Sequence Number (8)                   |
 +-------+-------+-------+-------+-------+-------+
 |           ACK Number (8)                       |
 +-------+-------+-------+-------+-------+-------+
 |           Timestamp µs (8)                     |
 +---+---+-------+---+---+---+---+---+---+-------+
 |PLen(2)|frag_id(2) |fi(1)|fc(1)|rcvwnd(2)|sid(2)|
 +-------+-------+-------+-------+-------+-------+
 |      Reserved (4)     |                        |
 +-------+-------+-------+                        +
 |  Encrypted Payload (0–1280 bytes)              |
 |  + 16-byte Poly1305 authentication tag         |
 +-------+-------+-------+-------+-------+-------+
```
`fi` = `frag_index`, `fc` = `frag_count`, `rcvwnd` = `recv_window`, `sid` = `stream_id`.

---

## 4. Packet Types

| Wire | Name           | Direction | Description                                       | Auth                   |
|------|----------------|-----------|---------------------------------------------------|------------------------|
| 0x01 | HELLO          | C→S       | Handshake initiation — carries eph pub key        | Ed25519 sig            |
| 0x02 | HELLO_ACK      | S→C       | Handshake response — carries server eph pub key   | Ed25519 sig + SHA-256  |
| 0x03 | DATA           | C↔S       | Application data (AEAD-encrypted)                 | ChaCha20-Poly1305 AEAD |
| 0x04 | ACK            | C↔S       | Cumulative acknowledgement (no payload)           | Poly1305 MAC           |
| 0x05 | KEEPALIVE      | C↔S       | Liveness probe when session is idle               | Poly1305 MAC           |
| 0x06 | KEEPALIVE_ACK  | C↔S       | Response to KEEPALIVE                             | Poly1305 MAC           |
| 0x07 | KEY_UPDATE     | C↔S       | Initiate in-band rekeying (forward secrecy)       | Ed25519 sig            |
| 0x08 | KEY_UPDATE_ACK | C↔S       | Acknowledge completion of KEY_UPDATE              | Ed25519 sig            |
| 0x09 | FIN            | C↔S       | Graceful session teardown                         | Poly1305 MAC           |
| 0x0A | ERROR          | C↔S       | Signal a protocol error to the peer               | none                   |
| 0x0B | FIN_ACK        | C↔S       | Acknowledge FIN; completes graceful teardown      | Poly1305 MAC           |
| 0x0C | RESET          | C↔S       | Immediate session abort (no acknowledgement)      | Poly1305 MAC           |
| 0x0D | PING           | C↔S       | RTT measurement request                           | Poly1305 MAC           |
| 0x0E | PONG           | C↔S       | RTT measurement response                          | Poly1305 MAC           |
| 0x0F | SACK_ACK       | C↔S       | Selective acknowledgement with out-of-order ranges| Poly1305 MAC           |
| 0x10 | PATH_CHALLENGE | C↔S       | Connection migration: challenge peer at new addr  | none (nonce freshness) |
| 0x11 | PATH_RESPONSE  | C↔S       | Connection migration: echo challenge nonce        | none (echoed nonce)    |

---

## 5. Flags

| Bit | Mask | Name                 | Meaning                                          |
|-----|------|----------------------|--------------------------------------------------|
| 0   | 0x01 | FIN                  | Set in FIN packets to signal teardown            |
| 1   | 0x02 | KEY_UPDATE_REQUESTED | Sender wants to begin a KEY_UPDATE exchange      |
| 2   | 0x04 | FRAGMENT             | This DATA packet is a fragment of a larger message |
| 3   | 0x08 | ECT                  | Mirrors the ECN-Capable Transport codepoint from IP TOS |
| 4   | 0x10 | CE                   | Mirrors the Congestion Experienced codepoint from IP TOS |
| 5–7 | —    | Reserved             | Must be 0                                        |

---

## 6. Error Codes

Carried in ERROR packets (payload byte 0) and surfaced via `SmrpError`.

| Wire | Rust variant          | Meaning                                       |
|------|-----------------------|-----------------------------------------------|
| 0x00 | NoError               | No error; sentinel in ACK packets             |
| 0x01 | MalformedHeader       | Header parse failure or truncation            |
| 0x02 | InvalidMagic          | Magic bytes ≠ 0x534D5250                      |
| 0x03 | UnsupportedVersion    | Version byte not recognised                   |
| 0x04 | AuthenticationFailure | AEAD tag or MAC verification failed           |
| 0x05 | UnknownSession        | Session ID not found in server state          |
| 0x06 | ReplayDetected        | Sequence number outside or already in window  |
| 0x07 | HandshakeTimeout      | HELLO_ACK not received within timeout         |
| 0x08 | SessionLimitExceeded  | Server is at MAX_SESSIONS capacity            |
| 0x09 | PayloadTooLarge       | Payload length exceeds MAX_PAYLOAD            |
| 0x0A | InternalError         | Unexpected internal failure                   |
| 0x0B | StreamClosed          | Referenced stream is already closed           |
| 0x0C | TooManyStreams         | Opening stream would exceed `max_streams`     |

Wire codes 0x0D and above decode to `InternalError`.

---

## 7. Handshake

### 7.1 Overview

```
Client                              Server
  │ [Init]                            │ [Listening]
  │                                   │
  │── HELLO ─────────────────────────>│ verify Ed25519 sig
  │   [HelloSent]                     │ generate server eph keypair
  │                                   │ derive session keys
  │<─ HELLO_ACK ──────────────────────│ [Established]
  │   verify Ed25519 sig + hash       │
  │   derive session keys             │
  │   [Established]                   │
  │                                   │
  │══ DATA ══════════════════════════>│
  │<═ DATA ═══════════════════════════│
```

### 7.2 HELLO / HELLO_ACK Payload (128 bytes, unencrypted)

**HELLO payload (client → server):**

```
Offset  Size  Field
0       32    Client ephemeral X25519 public key
32      32    Client Ed25519 signing public key
64      64    Ed25519 signature over (session_id[8] ‖ client_eph_pub[32])
```

**HELLO_ACK payload (server → client):**

```
Offset  Size  Field
0       32    Server ephemeral X25519 public key
32      32    Server Ed25519 signing public key
64      64    Ed25519 signature over (session_id[8] ‖ server_eph_pub[32] ‖ SHA-256(HELLO_payload)[32])
```

The HELLO_ACK signature includes a **transcript hash** — `SHA-256(HELLO_payload)` — that
binds the server's response to the exact HELLO it received. This prevents a server from
replaying its own HELLO_ACK against a different client HELLO. The client verifies this
binding before proceeding.

### 7.3 Key Derivation

```
shared_secret = X25519(eph_priv_local, eph_pub_peer)          # 32 bytes

c2s_key = HKDF-SHA256(ikm=shared, salt=session_id, info="smrp-v1-c2s")[0..32]
s2c_key = HKDF-SHA256(ikm=shared, salt=session_id, info="smrp-v1-s2c")[0..32]

# Four HKDF-derived 4-byte nonce prefixes (eliminate client-controlled nonce input)
data_nonce_c2s = HKDF-SHA256(ikm=c2s_key, salt=session_id, info="smrp-v1-data-nonce-c2s")[0..4]
data_nonce_s2c = HKDF-SHA256(ikm=s2c_key, salt=session_id, info="smrp-v1-data-nonce-s2c")[0..4]
ctrl_nonce_c2s = HKDF-SHA256(ikm=c2s_key, salt=session_id, info="smrp-v1-ctrl-nonce-c2s")[0..4]
ctrl_nonce_s2c = HKDF-SHA256(ikm=s2c_key, salt=session_id, info="smrp-v1-ctrl-nonce-s2c")[0..4]
```

Client sends with `c2s_key` / `data_nonce_c2s`, receives with `s2c_key` / `data_nonce_s2c`.  
Server sends with `s2c_key` / `data_nonce_s2c`, receives with `c2s_key` / `data_nonce_c2s`.

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
nonce = data_send_nonce_prefix[4] ‖ seq_be[8]        # 12 bytes total
aad   = full 54-byte header with timestamp_us zeroed  # prevents retransmit AAD mismatch
(ciphertext ‖ tag) = ChaCha20Poly1305.seal(send_key, nonce, plaintext, aad)
```

The 16-byte Poly1305 tag is appended immediately after the ciphertext.
The nonce prefix is HKDF-derived from the session key (see §7.3), so neither
party controls it directly.

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
   and the retry counter is incremented. Sequences present in the SACK set are
   skipped (see §8.10).
4. After each retransmit cycle the RTO is doubled (exponential backoff), capped
   at `rto_max`.
5. If an entry's retry counter reaches `max_retransmits`, the session is
   declared dead and `recv()` returns `Ok(None)`.
6. When an ACK is received, the corresponding entry is removed from the buffer.

**RTT Estimation (Jacobson/Karels, α=1/8, β=1/4):**

```
RTTVAR = (1-β)·RTTVAR + β·|SRTT - Ri|
SRTT   = (1-α)·SRTT   + α·Ri
RTO    = SRTT + 4·RTTVAR   (clamped to [rto_min, rto_max])
```

**Karn's algorithm:** RTT samples are only taken from DATA packets with
`retries == 0` (first transmission).

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

1. The receiver maintains a reorder buffer (`BTreeMap<seq, plaintext>`) of
   capacity `recv_buf_limit` (default: 256).
2. Every authenticated DATA packet is ACKed immediately.
3. The decrypted payload is inserted into the reorder buffer keyed by its
   sequence number.
4. The receiver drains contiguous entries starting from `next_deliver_seq`
   into an in-order delivery queue.
5. `recv()` returns entries from the delivery queue before pulling new packets
   from the network.
6. Out-of-order packets that arrive more than `recv_buf_limit` ahead of the
   current delivery head are silently dropped; the peer will retransmit them.

### 8.6 AIMD Congestion Control

**Congestion window (cwnd):**

- Initial value: `initial_cwnd` (default: 4 packets)
- **Slow-start** (`cwnd < ssthresh`): increment cwnd by 1 for each ACK.
- **Congestion avoidance** (`cwnd ≥ ssthresh`): increment cwnd by 1/cwnd per ACK (AIMD).
- **Packet loss** (retransmit event): `ssthresh = max(cwnd/2, 2)`, `cwnd = 1`.
- **ECN CE mark** (see §8.11): `ssthresh = max(cwnd/2, 2)`, `cwnd = ssthresh` (RFC 3168 §6.1.2).

**Effective window:** `min(cwnd, peer_recv_window)` — respects both congestion
control and the receiver's advertised buffer capacity.

**Backpressure:** `send()` blocks asynchronously when `pending_acks ≥ effective_window`.
A `Notify` listener is registered *before* the check to avoid lost-wake races.

**Congestion control config fields:**

| Field             | Default | Meaning                                       |
|-------------------|---------|-----------------------------------------------|
| `initial_cwnd`    | 4       | Starting congestion window (packets in flight)|
| `initial_ssthresh`| 64      | Slow-start threshold                          |
| `recv_buf_limit`  | 256     | Max out-of-order packets in reorder buffer    |

### 8.7 RESET

On receipt of an authenticated RESET packet the session is closed immediately.
No FIN_ACK is exchanged. `recv()` returns `Ok(None)`.

### 8.8 PING / PONG

PING is a one-way RTT probe. The receiver replies with PONG, echoing the PING's
`timestamp_us`. The original sender subtracts the echoed timestamp from its current
clock to compute RTT without requiring clock synchronisation. The RTT sample is fed
into the Jacobson/Karels estimator.

### 8.9 Fragmentation

Payloads larger than `MAX_PAYLOAD` (1 280 bytes) are automatically fragmented
by the library. The sender sets the `FRAGMENT` flag and populates `frag_id`,
`frag_index`, and `frag_count` in the header. Each fragment is sent as a
separate DATA packet with its own sequence number and goes through the normal
retransmit / ACK / ordered-delivery path. The receiver reassembles fragments
into the original message using a `HashMap<frag_id, FragmentAssembly>` and
delivers the reassembled payload atomically to the application.

Maximum message size: `frag_count` is a single byte, so up to **255 fragments**
of up to `MAX_PAYLOAD` bytes = **326 400 bytes** per message.

### 8.10 Selective Acknowledgement (SACK)

`SackAck` (0x0F) carries one or more out-of-order received ranges in the
payload. Each range is encoded as two u64 sequence numbers (start, end inclusive).
The sender reads these ranges into a `BTreeSet<u64>` of acknowledged sequences.
When the retransmit task fires, sequences present in the SACK set are skipped,
avoiding unnecessary retransmits for packets the receiver already has.

Maximum SACK blocks per packet: `SmrpConfig::max_sack_blocks` (default: 16).

### 8.11 Explicit Congestion Notification (ECN)

ECN support is controlled by `SmrpConfig::ecn_enabled` (default: `false`).
Requires OS support; silently ignored if the socket option is unavailable.

**Outgoing:** `IP_TOS` (IPv4) or `IPV6_TCLASS` (IPv6) is set to `ECT(0)=0x02`
via `setsockopt`, marking all outgoing packets as ECN-capable.

**Incoming:** `IP_RECVTOS` (IPv4) or `IPV6_RECVTCLASS` (IPv6) is enabled via
`setsockopt` so that the TOS/TCLASS byte is delivered as ancillary data on each
`recvmsg(2)` call. When the CE codepoint (`0b11`) is detected, `react_to_ecn_ce()`
is called immediately:

```
ssthresh = max(cwnd / 2, 2)
cwnd     = ssthresh
notify window_notify  // unblock any pending send()
```

This is equivalent to a retransmit event without actually marking any packet as
lost, conforming to RFC 3168 §6.1.2.

### 8.12 Path MTU Discovery (PMTUD)

PMTUD is controlled by `SmrpConfig::pmtud_enabled` (default: `true`).

`SmrpConnection::effective_payload` tracks the current probed payload size,
starting at `MAX_PAYLOAD`. The implementation uses probe-based discovery:

- A sealed DATA packet slightly larger than `effective_payload` is sent
  periodically (`pmtud_probe_interval`, default: 5 s).
- If an ACK is received for the probe: `effective_payload` steps up by
  `PMTUD_STEP` (128 bytes), capped at `MAX_PAYLOAD`.
- If no ACK arrives within 4 × RTT: `effective_payload` steps down by
  `PMTUD_STEP`, floored at `MIN_PMTUD_PAYLOAD` (512 bytes).

Normal `send()` calls use `effective_payload` as the DATA payload size limit
(before fragmentation triggers).

### 8.13 Send Pacing

Send pacing is controlled by `SmrpConfig::pacing_enabled` (default: `true`).

A token-bucket pacer grants send credits at a rate proportional to
`cwnd / RTT` bytes/second. Tokens are refilled on each `send()` call based on
elapsed time since the last refill. When the bucket is empty, `send()` does not
block but instead yields the current token deficit. This spreads bursts evenly
across the RTT, reducing queue build-up at bottleneck links without adding latency.

---

## 9. Anti-Replay Window

RFC 6479 sliding window, 128-bit bitmask.

- Window size: **128 packets**
- Packets within the window but with a bit already set → `ReplayDetected`
- Packets more than 127 below the highest seen → `ReplayDetected`
- **Two-phase design**: `can_accept(seq)` called *before* AEAD decryption;
  `mark_seen(seq)` called *only after* successful AEAD open.

---

## 10. Session Teardown

### Active close (initiator)

1. Initiator sends FIN with Poly1305 MAC (`seq=N`, FIN flag set)
2. Peer replies with authenticated FIN_ACK (`ack_number=N`)
3. Initiator releases session state

The initiator waits for FIN_ACK for at most `fin_ack_timeout` (default: 5 s).
If no FIN_ACK arrives within this window, the session state is released unilaterally.

### Passive close (responder)

On receiving an authenticated FIN, the peer sends an authenticated FIN_ACK
immediately and transitions to `Closed`.

---

## 11. Keepalive and Session Eviction

### Keepalive probes

If no packet has been *received* from the peer for `keepalive_interval` (default
15 s), the local side sends an authenticated KEEPALIVE (Poly1305 MAC). The peer
MUST reply with an authenticated KEEPALIVE_ACK. Spoofed KEEPALIVE or
KEEPALIVE_ACK packets are rejected by MAC verification.

KEEPALIVE uses a dedicated `KeepaliveAuth` struct shared between the
`SmrpConnection` and the keepalive background task via `Arc<Mutex<_>>`. The
keepalive nonce counter starts at `1u64 << 48` to avoid any collision with the
main `ctrl_send_seq` counter. The key material in `KeepaliveAuth` is updated
after every key rotation.

KEEPALIVE_ACK is additionally rate-limited to at most **one per second** per
connection to prevent amplification from unauthenticated probes.

### Dead session eviction

If no packet has been received for `session_dead_timeout` (default 45 s,
should be ≥ 3 × `keepalive_interval`), the session is declared dead:

- `recv()` returns `Ok(None)`.
- The session is removed from the server's session map.
- The `sessions_evicted_dead` metric is incremented.

No FIN is sent on eviction — the peer is assumed unreachable.

---

## 12. In-Band Key Update

Either party may initiate a key update to rotate session keys without a full
re-handshake (sub-session forward secrecy).

### 12.1 Protocol Flow

```
Initiator                          Responder
  │                                    │
  │── KEY_UPDATE (eph_pub_i, sig) ────>│  verify sig + counter
  │   seq = rekey_counter              │  generate eph keypair r
  │                                    │  derive new keys
  │                                    │  save old recv key (pre-rekey buffer)
  │<── KEY_UPDATE_ACK (eph_pub_r, sig) │  send KEY_UPDATE_ACK
  │  verify sig                        │  install new send key
  │  X25519 agree                      │
  │  install new keys                  │
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

### 12.3 Key Derivation on Rekey

```
shared_secret = X25519(local_eph_priv, peer_eph_pub)
salt = session_id[8] ‖ rekey_counter_be[8]

c2s = HKDF-SHA256(shared_secret, salt, "smrp-v1-rekey-c2s")
s2c = HKDF-SHA256(shared_secret, salt, "smrp-v1-rekey-s2c")
```

Nonce prefixes, KEEPALIVE auth key bytes, and the KEEPALIVE nonce prefix are all
re-derived from the new keys after each rotation.

### 12.4 Identity Pinning

The Ed25519 signing public key in the payload must match the key pinned during
the handshake. A `KEY_UPDATE` carrying a different signing key is rejected as
`AuthenticationFailure`.

### 12.5 API and Sequencing Constraint

```rust
// Blocks until KEY_UPDATE_ACK is received and new keys are installed.
async fn request_key_update(&mut self) -> Result<(), SmrpError>
```

**Prerequisite:** The retransmit buffer must be empty before calling
`request_key_update()`. In-flight DATA will be retransmitted with old ciphertext
after the key switch — the peer (holding new keys) will reject them as
authentication failures. Drain all ACKs before initiating a rekey.

### 12.6 DATA Buffering During Key Update

When the responder sends `KEY_UPDATE_ACK` and installs new keys, it saves the
previous recv key as `pre_rekey_recv_key_bytes`. DATA packets that arrive after
key update but were encrypted with the old key (sent before the initiator
received `KEY_UPDATE_ACK`) are decrypted with the pre-rekey key and buffered in
`buffered_rekey_data`. These are drained into the deliver queue once
`install_rekey_keys` completes, preventing silent packet loss at rotation
boundaries.

---

## 13. Constants Reference

### 13.1 Compile-time constants (`constants.rs`)

| Constant         | Value       | Notes                                      |
|------------------|-------------|--------------------------------------------|
| SMRP_MAGIC       | 0x534D5250  | ASCII "SMRP" big-endian                    |
| SMRP_VERSION     | 0x05        | Wire version byte                          |
| HEADER_LEN       | 54 bytes    | Fixed packet header size                   |
| MAX_PAYLOAD      | 1 280 bytes | Maximum plaintext application payload      |
| AUTH_TAG_LEN     | 16 bytes    | Poly1305 tag appended to every ciphertext  |
| MAX_PACKET       | 1 350 bytes | MAX_PAYLOAD + HEADER_LEN + AUTH_TAG_LEN    |
| SESSION_ID_LEN   | 8 bytes     | Session identifier size                    |
| NONCE_LEN        | 12 bytes    | ChaCha20-Poly1305 nonce size               |
| REPLAY_WINDOW    | 128 packets | RFC 6479 sliding window size               |

### 13.2 Runtime-configurable defaults (`SmrpConfig`)

| Parameter               | Default    | Notes                                                |
|-------------------------|------------|------------------------------------------------------|
| keepalive_interval      | 15 s       | How often to send KEEPALIVE when idle                |
| session_dead_timeout    | 45 s       | Evict session if no traffic for this long            |
| hello_clock_skew        | 30 s       | Max clock difference for HELLO timestamp check       |
| hello_rate_limit        | 10 / IP/s  | HELLO rate limit before any crypto                   |
| max_sessions            | 100 000    | Hard cap on concurrent sessions                      |
| connect_timeout         | 10 s       | Timeout for SmrpConnection::connect()                |
| recv_timeout            | 60 s       | Default timeout for SmrpConnection::recv()           |
| fin_ack_timeout         | 5 s        | How long close() waits for FIN_ACK                   |
| session_channel_capacity| 256 pkts   | Per-session in-flight packet buffer                  |
| accept_queue_capacity   | 64 conns   | New-connection queue depth at SmrpListener           |
| max_retransmits         | 5          | Max retransmit attempts before session dead          |
| rto_initial             | 200 ms     | Initial retransmission timeout                       |
| rto_min                 | 50 ms      | Minimum RTO (also retransmit-task interval)          |
| rto_max                 | 30 s       | Maximum RTO (exponential backoff ceiling)            |
| initial_cwnd            | 4 pkts     | Starting congestion window (see §8.6)                |
| initial_ssthresh        | 64 pkts    | Slow-start threshold; above this, AIMD CA runs       |
| recv_buf_limit          | 256 pkts   | Max out-of-order packets in reorder buffer           |
| max_sack_blocks         | 16         | Max SACK ranges per SackAck packet                   |
| pmtud_enabled           | true       | Enable probe-based path MTU discovery (§8.12)        |
| pmtud_probe_interval    | 5 s        | How often to attempt an upward PMTUD probe           |
| pacing_enabled          | true       | Enable token-bucket send pacing (§8.13)              |
| ecn_enabled             | false      | Mirror ECN bits and react to CE marks (§8.11)        |
| max_streams             | 256        | Max concurrent logical streams per session (§16)     |
| migration_enabled       | true       | Allow address migration via PATH_CHALLENGE (§17)     |

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

In-band key update (§12) provides sub-session granularity forward secrecy.

### Replay Protection

Two-layer defence:

1. **HELLO timestamp validation (§7.5)** — limits HELLO replay to a 60-second window
2. **DATA sequence-number window (§9)** — RFC 6479 sliding window; two-phase design prevents window poisoning

### DoS Mitigations

| Mechanism              | Detail                                               |
|------------------------|------------------------------------------------------|
| HELLO rate limiting    | 10 HELLO/IP/s (configurable); excess dropped before any crypto runs |
| HELLO timestamp check  | Stale/future HELLOs rejected before signature verification |
| MAX_SESSIONS hard cap  | HELLOs beyond `max_sessions` receive ERROR(SessionLimitExceeded) |
| Dead session eviction  | Sessions with no traffic for `session_dead_timeout` are freed automatically |
| KEEPALIVE MAC          | Spoofed KEEPALIVE/KEEPALIVE_ACK packets rejected by Poly1305 verification |
| KEEPALIVE_ACK rate-limit | At most 1 KEEPALIVE_ACK/second/connection; prevents amplification |

### Known Weaknesses

- **No certificate infrastructure** — signing keys distributed out-of-band or
  TOFU; no revocation
- **`&mut self` API** — `send()` and `recv()` both take `&mut self`; concurrent
  send+recv requires a task split
- **KEY_UPDATE sequential constraint** — retransmit buffer must be empty; DATA
  packets received during the blocking wait for `KEY_UPDATE_ACK` are discarded
- **ECN opt-in** — `ecn_enabled` is `false` by default; requires kernel support
  and explicit configuration to activate
- **Nonce entropy** — the 12-byte nonce uses a 32-bit HKDF-derived prefix; within
  a session nonce uniqueness is guaranteed by the 64-bit sequence number, but the
  32-bit prefix has negligible collision probability only within a single session's
  key lifetime
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
    pub initial_ssthresh:         usize,     // default: 64
    pub recv_buf_limit:           usize,     // default: 256
    pub max_sack_blocks:          usize,     // default: 16
    pub pmtud_enabled:            bool,      // default: true
    pub pmtud_probe_interval:     Duration,  // default: 5 s
    pub pacing_enabled:           bool,      // default: true
    pub ecn_enabled:              bool,      // default: false
    pub max_streams:              u16,       // default: 256
    pub migration_enabled:        bool,      // default: true
}
```

### 15.2 SmrpMetrics

```rust
pub struct SmrpMetrics {
    pub sessions_active:          AtomicU64,
    pub sessions_total:           AtomicU64,
    pub sessions_evicted_dead:    AtomicU64,
    pub hello_drops_rate_limit:   AtomicU64,
    pub hello_drops_clock_skew:   AtomicU64,
    pub hello_drops_capacity:     AtomicU64,
    pub packets_sent:             AtomicU64,
    pub packets_received:         AtomicU64,
    pub bytes_sent:               AtomicU64,
    pub bytes_received:           AtomicU64,
    pub packets_retransmitted:    AtomicU64,
    pub auth_failures:            AtomicU64,
    pub replay_detections:        AtomicU64,
}
```

Use `SmrpMetrics::snapshot()` for a `MetricsSnapshot` (plain `u64` fields).

### 15.3 SmrpListener

```rust
async fn bind(addr: &str) -> Result<SmrpListener, SmrpError>
async fn bind_with_config(addr: &str, cfg: Arc<SmrpConfig>) -> Result<SmrpListener, SmrpError>
async fn bind_with_config_and_key(
    addr: &str, cfg: Arc<SmrpConfig>, sign_key: SigningKey,
) -> Result<SmrpListener, SmrpError>
async fn accept(&mut self) -> Option<SmrpConnection>
fn local_addr(&self) -> SocketAddr
fn metrics(&self) -> Arc<SmrpMetrics>
fn config(&self) -> Arc<SmrpConfig>
async fn shutdown(self)
```

### 15.4 SmrpConnection

```rust
async fn connect(server_addr: &str) -> Result<SmrpConnection, SmrpError>
async fn connect_with_config(server_addr: &str, cfg: Arc<SmrpConfig>)
    -> Result<SmrpConnection, SmrpError>
async fn connect_with_pinned_server_key(server_addr: &str, pinned_pub: &[u8; 32])
    -> Result<SmrpConnection, SmrpError>
async fn send(&mut self, data: &[u8]) -> Result<(), SmrpError>
async fn recv(&mut self) -> Result<Option<Vec<u8>>, SmrpError>
async fn recv_timeout(&mut self, deadline: Duration) -> Result<Option<Vec<u8>>, SmrpError>
async fn close(self) -> Result<(), SmrpError>
async fn request_key_update(&mut self) -> Result<(), SmrpError>
fn peer_addr(&self) -> SocketAddr
fn session_id(&self) -> &[u8; 8]
```

### 15.5 SigningKey — Persistent Identity

```rust
fn generate() -> Result<SigningKey, SmrpError>
fn from_pkcs8(bytes: &[u8]) -> Result<SigningKey, SmrpError>
fn to_pkcs8(&self) -> &[u8]
fn public_key_bytes(&self) -> &[u8; 32]
```

**Recommended server pattern:**

```rust
const KEY_FILE: &str = "smrp_server.key";
let sign_key = if Path::new(KEY_FILE).exists() {
    SigningKey::from_pkcs8(&fs::read(KEY_FILE)?)?
} else {
    let key = SigningKey::generate()?;
    fs::write(KEY_FILE, key.to_pkcs8())?;
    key
};
println!("identity: {}", hex::encode(sign_key.public_key_bytes()));
let listener = SmrpListener::bind_with_config_and_key(addr, cfg, sign_key).await?;
```

---

## 16. Multiplexed Streams

DATA packets carry a `stream_id` (u16) field. Stream 0 is the default and is
always open. Non-zero stream IDs are routed to per-stream `mpsc` channels
registered via the internal `stream_txs` map on `SmrpConnection`. A maximum of
`SmrpConfig::max_streams` (default: 256) streams may be open per session;
exceeding this returns `SmrpError::TooManyStreams`.

---

## 17. Connection Migration

Either peer may send a `PATH_CHALLENGE` carrying a fresh 8-byte nonce to probe
reachability at a new address. The receiver echoes the nonce in a `PATH_RESPONSE`.
On receipt of a matching `PATH_RESPONSE`, `peer_addr` is updated to the new address.

`PATH_CHALLENGE` and `PATH_RESPONSE` carry no Poly1305 MAC — the echoed nonce
provides freshness. An observer who can see the nonce could forge a
`PATH_RESPONSE`, but cannot thereby redirect traffic permanently since only the
application confirms the new path is reachable. Migration is controlled by
`SmrpConfig::migration_enabled` (default: `true`). Only one challenge can be
in-flight at a time per session.

---

*End of Specification v1.0*
