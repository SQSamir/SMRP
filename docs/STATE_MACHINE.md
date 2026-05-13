# SMRP Session State Machine

Protocol version: 0x05

---

## Client State Machine

```
        ┌─────────────────────────────────────────────────────────────┐
        │                         IDLE                                │
        └────────────────────────────┬────────────────────────────────┘
                                     │ connect() called
                                     │ send HELLO
                                     ▼
        ┌─────────────────────────────────────────────────────────────┐
        │                      CONNECTING                             │
        │  (waiting for HELLO_ACK; timeout = connect_timeout)         │
        └──────┬──────────────────────────────────────────────────────┘
               │                         │
    HELLO_ACK received,            timeout / ERROR /
    MAC+sig verified,              wrong packet type
    keys derived                         │
               │                         ▼
               │                   ┌───────────┐
               │                   │  CLOSED   │
               │                   └───────────┘
               ▼
        ┌─────────────────────────────────────────────────────────────┐
        │                     ESTABLISHED                             │
        │                                                             │
        │  DATA [stream_id] ──────────────────────────────────────►   │
        │  ◄──────────────────────────────────── DATA [stream_id]     │
        │  ◄────────────────────────────────────── SACK_ACK (auth)    │
        │  SACK_ACK (auth) ─────────────────────────────────────────► │
        │                                                             │
        │  KEEPALIVE ──────────────────────────────────────────────►  │
        │  ◄──────────────────────────────────── KEEPALIVE_ACK (auth) │
        │                                                             │
        │  PING (auth) ─────────────────────────────────────────────► │
        │  ◄──────────────────────────────────────────── PONG (auth)  │
        │                                                             │
        │  KEY_UPDATE (signed) ─────────────────────────────────────► │
        │  ◄─────────────────────────── KEY_UPDATE_ACK (signed)       │
        │                                                             │
        │  PATH_CHALLENGE ──────────────────────────────────────────► │
        │  ◄────────────────────────────────────── PATH_RESPONSE      │
        │                                                             │
        └────┬───────────────────────────────────────────────────┬───┘
             │ close() / recv OK(None)                           │
             │ send FIN (auth)                                   │ RESET (auth)
             ▼                                                   │ received
        ┌───────────────────────────┐                           │ or dead-session
        │       FIN_SENT            │                           │ timeout
        │  (waiting for FIN_ACK;    │                           ▼
        │   timeout = fin_ack_timeout) ◄──────────FIN_ACK (auth)─┐
        └───────────┬───────────────┘                           │
                    │                                           │
                    ▼                                           ▼
              ┌───────────┐                               ┌───────────┐
              │  CLOSED   │                               │  CLOSED   │
              └───────────┘                               └───────────┘
```

### Client Transitions

| From         | Event                                       | To          | Action                       |
|--------------|---------------------------------------------|-------------|------------------------------|
| IDLE         | `connect()` called                          | CONNECTING  | Send HELLO                   |
| CONNECTING   | HELLO_ACK received, sig+MAC verified        | ESTABLISHED | Derive keys; run recv loop   |
| CONNECTING   | Timeout / ERROR / wrong type                | CLOSED      | —                            |
| ESTABLISHED  | `close()` called                            | FIN_SENT    | Send authenticated FIN       |
| ESTABLISHED  | RESET (auth) received                       | CLOSED      | —                            |
| ESTABLISHED  | Dead-session timeout                        | CLOSED      | —                            |
| ESTABLISHED  | FIN (auth) received from server             | CLOSED      | Send authenticated FIN_ACK   |
| ESTABLISHED  | PATH_CHALLENGE received                     | ESTABLISHED | Echo nonce in PATH_RESPONSE  |
| ESTABLISHED  | PATH_RESPONSE received (nonce match)        | ESTABLISHED | Update peer_addr             |
| FIN_SENT     | FIN_ACK (auth) received                     | CLOSED      | —                            |
| FIN_SENT     | fin_ack_timeout expires                     | CLOSED      | —                            |

---

## Server State Machine

```
        ┌─────────────────────────────────────────────────────────────┐
        │                       LISTENING                             │
        │  (dispatch loop; HELLO rate-limited 10/IP/s;                │
        │   timestamp validated ±hello_clock_skew)                    │
        └────────────────────────────┬────────────────────────────────┘
                                     │ HELLO received
                                     │ (within max_sessions limit)
                                     ▼
        ┌─────────────────────────────────────────────────────────────┐
        │                      HANDSHAKING                            │
        │  (per-HELLO async task; verifies Ed25519 sig;               │
        │   sends HELLO_ACK with transcript-bound signature)           │
        └──────┬──────────────────────────────────────────────────────┘
               │                         │
      HELLO_ACK sent,              crypto/network
      session established           failure
               │                         │
               ▼                         ▼
        ┌───────────────────────┐   (session not
        │     ESTABLISHED       │    registered)
        │  (same events as      │
        │   client ESTABLISHED) │
        └────┬──────────────────┘
             │ FIN (auth) received    │ SmrpListener::shutdown()
             │ or RESET (auth)        │
             ▼                        ▼
        ┌───────────────────────┐  ┌───────────────────────────┐
        │  FIN received:        │  │  Shutdown signal:          │
        │  send FIN_ACK (auth)  │  │  send FIN (auth) then      │
        │  → CLOSED             │  │  wait FIN_ACK → CLOSED    │
        └───────────────────────┘  └───────────────────────────┘
```

### Server Transitions

| From         | Event                                           | To          | Action                                |
|--------------|-------------------------------------------------|-------------|---------------------------------------|
| LISTENING    | HELLO received (rate + timestamp OK)            | HANDSHAKING | Spawn per-HELLO task                  |
| LISTENING    | HELLO rate limit exceeded                       | LISTENING   | Drop; increment metric                |
| LISTENING    | HELLO timestamp out of range                    | LISTENING   | Drop; increment metric                |
| LISTENING    | max_sessions reached                            | LISTENING   | Send ERROR; increment metric          |
| HANDSHAKING  | Ed25519 sig verified; HELLO_ACK sent            | ESTABLISHED | Register session; emit to accept queue|
| HANDSHAKING  | Crypto / network failure                        | —           | Log warning; no session registered    |
| ESTABLISHED  | FIN (auth) received                             | CLOSED      | Send authenticated FIN_ACK            |
| ESTABLISHED  | RESET (auth) received                           | CLOSED      | —                                     |
| ESTABLISHED  | Dead-session timeout (no traffic > dead_timeout)| CLOSED      | Evict; increment metric               |
| ESTABLISHED  | `SmrpListener::shutdown()` signal               | CLOSED      | Send authenticated FIN; wait FIN_ACK  |
| ESTABLISHED  | PATH_CHALLENGE received                         | ESTABLISHED | Echo nonce in PATH_RESPONSE           |
| ESTABLISHED  | PATH_RESPONSE received (nonce match)            | ESTABLISHED | Update peer_addr                      |

---

## In-Band Key Update (ESTABLISHED state only)

```
  Initiator                                Responder
      │                                        │
      │── KEY_UPDATE (signed, counter N) ─────►│
      │                                        │  verify Ed25519 sig
      │                                        │  generate eph keypair
      │                                        │  X25519 agree
      │◄────────── KEY_UPDATE_ACK (signed) ────│  install new keys
      │  verify Ed25519 sig                    │
      │  X25519 agree                          │
      │  install new keys                      │
      │                                        │
      │  (subsequent DATA uses new keys)       │
```

Key update resets all HKDF nonce prefixes. The Ed25519 identity keys are
pinned from the handshake — only the session (X25519-derived) keys rotate.

During key update, inbound DATA packets that arrive before the new keys are
installed are buffered (up to a small limit) and drained once keys are in place.
Packets that cannot be decrypted with either the old or new key are dropped.

---

## Connection Migration (ESTABLISHED state only)

```
  Initiator (new path)                        Responder
      │                                            │
      │── PATH_CHALLENGE (nonce[8]) ──────────────►│
      │                                            │  record nonce
      │◄───────────── PATH_RESPONSE (nonce[8]) ────│
      │  verify nonce matches                      │
      │  update peer_addr                          │
      │                                            │
      │  (subsequent packets use new address)      │
```

PATH_CHALLENGE and PATH_RESPONSE are sent without Poly1305 authentication
(the echoed nonce provides freshness; no session key exposure). Only one
challenge can be in-flight at a time per session.

---

## Multiplexed Streams (ESTABLISHED state only)

DATA packets carry a `stream_id` (u16) field. Stream 0 is the default and
is always open. Additional streams are opened via `open_stream()` /
`SmrpReceiver::open_stream()` and routed to per-stream `mpsc` channels. A
maximum of `config.max_streams` (default: 256) streams may be open per
session; attempts beyond this return `SmrpError::TooManyStreams`.

---

## Authenticated Packet Types

The following control packets carry a 16-byte Poly1305 MAC tag (sealed over an
empty plaintext with the full 54-byte header as AAD):

| Packet          | Type ID | Authenticated                        |
|-----------------|:-------:|--------------------------------------|
| HELLO           | 0x01    | Ed25519 sig                          |
| HELLO_ACK       | 0x02    | Ed25519 sig + transcript hash        |
| DATA            | 0x03    | ChaCha20-Poly1305 AEAD               |
| ACK             | 0x04    | Poly1305 MAC                         |
| KEEPALIVE       | 0x05    | no                                   |
| KEEPALIVE_ACK   | 0x06    | Poly1305 MAC                         |
| KEY_UPDATE      | 0x07    | Ed25519 sig                          |
| KEY_UPDATE_ACK  | 0x08    | Ed25519 sig                          |
| FIN             | 0x09    | Poly1305 MAC                         |
| FIN_ACK         | 0x0A    | Poly1305 MAC                         |
| RESET           | 0x0B    | Poly1305 MAC                         |
| PING            | 0x0C    | Poly1305 MAC                         |
| PONG            | 0x0D    | Poly1305 MAC                         |
| ERROR           | 0x0E    | no                                   |
| SACK_ACK        | 0x0F    | Poly1305 MAC                         |
| PATH_CHALLENGE  | 0x10    | no (nonce provides freshness)        |
| PATH_RESPONSE   | 0x11    | no (echoed nonce provides freshness) |

KEEPALIVE and ERROR are sent without per-packet authentication. KEEPALIVE is
rate-limited on the receive side (at most one KEEPALIVE_ACK per second per
connection) to prevent amplification.

PATH_CHALLENGE and PATH_RESPONSE carry no Poly1305 MAC. An attacker who can
observe the challenge nonce could forge a PATH_RESPONSE, but cannot thereby
redirect traffic — `peer_addr` is only updated after a full round-trip at the
application level confirms reachability on the new path.
