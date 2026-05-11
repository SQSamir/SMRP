# SMRP Session State Machine

Protocol version: 0x03

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
        │  DATA ──────────────────────────────────────────────────►   │
        │  ◄────────────────────────────────────────────── DATA       │
        │  ◄────────────────────────────────────────── ACK (auth)     │
        │  ACK (auth) ──────────────────────────────────────────────► │
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

---

## Authenticated Packet Types

The following control packets carry a 16-byte Poly1305 MAC tag (sealed over an
empty plaintext with the full 54-byte header as AAD):

| Packet        | Authenticated |
|---------------|:-------------:|
| HELLO         | Ed25519 sig   |
| HELLO_ACK     | Ed25519 sig + transcript hash |
| DATA          | ChaCha20-Poly1305 AEAD        |
| ACK           | Poly1305 MAC  |
| KEEPALIVE     | no            |
| KEEPALIVE_ACK | Poly1305 MAC  |
| KEY_UPDATE    | Ed25519 sig   |
| KEY_UPDATE_ACK| Ed25519 sig   |
| FIN           | Poly1305 MAC  |
| FIN_ACK       | Poly1305 MAC  |
| RESET         | Poly1305 MAC  |
| PING          | Poly1305 MAC  |
| PONG          | Poly1305 MAC  |
| ERROR         | no            |

KEEPALIVE and ERROR are sent without per-packet authentication. KEEPALIVE is
rate-limited on the receive side (at most one KEEPALIVE_ACK per second per
connection) to prevent amplification.
