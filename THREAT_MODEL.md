# SMRP Threat Model

Wire version: `0x02`

This document describes the security assumptions, goals, non-goals, cryptographic
design rationale, and known attack surface for the Secure Minimal Reliable Protocol
(SMRP).

---

## Attacker Capabilities

SMRP is designed to resist attackers with the following capabilities:

### Active Network Attacker
The attacker has full control of the network between any two communicating peers. They
can:
- Inject arbitrary UDP packets on any port
- Replay previously captured packets (with or without modification)
- Drop packets selectively or entirely
- Reorder packets arbitrarily
- Delay packets by any amount within network constraints

### Passive Network Attacker
The attacker can observe all traffic between peers, including:
- All cleartext fields in packet headers (session ID, sequence numbers, packet type)
- Timing and volume of communications
- IP addresses and ports of communicating parties

### Compromised Long-Term Signing Keys
The attacker may have obtained a peer's long-term Ed25519 **signing** key (e.g., via
device theft, key extraction, or a side-channel attack). This is considered a
catastrophic event for identity authentication.

**Notably excluded:** Compromise of session keys (X25519 ephemeral keys, ChaCha20-
Poly1305 session keys) is NOT modeled as an attacker capability. Session keys are
ephemeral and short-lived.

---

## Security Goals

| Goal | Mechanism |
|------|-----------|
| **Confidentiality** | All payload data is encrypted with ChaCha20-Poly1305 under a session key derived via HKDF from an X25519 ECDH exchange |
| **Integrity** | ChaCha20-Poly1305 provides authenticated encryption; any ciphertext modification causes decryption failure and packet rejection |
| **Mutual Authentication** | Both peers sign their ephemeral DH public keys with their long-term Ed25519 keys during the handshake |
| **Replay Protection** | Each packet carries a monotonically increasing sequence number; packets with already-seen or out-of-window sequence numbers are rejected |
| **Forward Secrecy (per session)** | Ephemeral X25519 key pairs are generated fresh for each session; past sessions cannot be decrypted if session keys are later compromised |
| **Identity Pinning** | Peers can pin the expected long-term Ed25519 public key of a remote peer; mismatches abort the handshake |
| **Sub-Session Forward Secrecy (key update)** | `request_key_update()` derives new session keys from the current session key and fresh entropy, limiting the plaintext exposed if a session key is later extracted |

---

## Non-Goals

The following are explicitly outside the scope of SMRP's security model:

- **DoS resilience beyond rate limiting:** SMRP applies basic per-source rate limiting
  on HELLO packets but provides no sophisticated defense against volumetric or
  amplification attacks.
- **PKI / Certificate Infrastructure:** There is no certificate authority, no
  certificate chain validation, and no X.509 support. Key authenticity is the
  application's responsibility.
- **Fragmentation:** SMRP does not fragment payloads. Oversized messages must be
  handled at the application layer.
- **Traffic Analysis Resistance:** Session IDs, packet types, and sequence numbers are
  visible in cleartext. An observer can determine session boundaries, packet counts,
  and timing.
- **Post-Quantum Security:** All primitives are classical. A sufficiently capable
  quantum adversary can break the X25519 key exchange and Ed25519 signatures.

---

## Cryptographic Design Rationale

### X25519 (Ephemeral ECDH)
X25519 Diffie-Hellman is used for session key establishment. It was chosen because:
- It provides **ephemeral** key exchange: no static DH secrets exist, so past sessions
  remain protected even after long-term key compromise (forward secrecy).
- The Curve25519 design resists several classes of implementation errors (no cofactor
  issues relevant to this use, complete addition formulas, constant-time reference
  implementations).
- The `ring` crate provides a well-reviewed, constant-time implementation.

### HKDF-SHA-256 (Key Derivation)
HKDF is used to derive all sub-keys (session encryption key, nonce prefixes for each
direction and plane) from the raw X25519 shared secret. It was chosen because:
- It provides **domain separation**: distinct info strings produce independent keys,
  preventing cross-context key reuse.
- It is a standard, widely analyzed KDF (RFC 5869) built on HMAC-SHA-256.
- Using a dedicated KDF ensures that the raw X25519 output (which has structure) is
  never used directly as a cipher key.

### Ed25519 (Long-Term Signing Keys)
Ed25519 is used for peer authentication during the handshake. It was chosen because:
- It is **fast** for both signing and verification, minimizing handshake latency.
- The deterministic signing scheme eliminates risks from poor entropy during signing
  (unlike ECDSA with a per-signature nonce).
- The `ring` crate provides a hardened implementation.

### ChaCha20-Poly1305 (AEAD Encryption)
All session payload encryption uses ChaCha20-Poly1305. It was chosen because:
- It has **no timing side channels** related to data values; the algorithm is designed
  to run in constant time without hardware AES acceleration.
- At typical SMRP session scales, nonce reuse within a session is prevented by the
  monotonic sequence number embedded in each nonce (see Nonce Design below).
- It is standardized (RFC 8439) and its security properties are well understood.
- The `ring` crate provides a vetted implementation.

---

## Known Attack Surface

### KEEPALIVE Packets Are Unauthenticated
`KEEPALIVE` packets are transmitted outside the session key scope without a MAC or
signature. Consequently:
- An attacker can **inject fake KEEPALIVE packets** to prevent a session from timing
  out, keeping a dead session alive indefinitely (session-liveness DoS).
- An attacker can **suppress KEEPALIVE packets** to cause a live session to appear dead
  and be torn down prematurely.

Neither variant exposes plaintext or session keys, but both can disrupt availability.
Mitigations: application-level heartbeats authenticated within the session, or moving
KEEPALIVE into the encrypted data plane in a future wire version.

### HELLO Replay Attacks
HELLO packets initiate new sessions. They include a timestamp, and the receiver rejects
HELLOs whose timestamp falls outside a **±30-second window** relative to local time.
Additionally, per-source rate limiting is applied to HELLO packets.

These controls limit (but do not eliminate) HELLO replay: an attacker who captures a
valid HELLO can replay it within the timestamp window to trigger spurious handshake
attempts. The server will reject such replays once a session is established (the
ephemeral key response will not match), but they consume server resources.

### Session ID Visible in Cleartext
The session ID field is transmitted unencrypted in every packet header. A passive
observer can therefore:
- Correlate packets belonging to the same session across time
- Count the number of concurrent sessions between two endpoints
- Identify session establishment and teardown events

This enables **traffic analysis** even without breaking the encryption.

---

## Nonce Design

Each nonce is 12 bytes, structured as:

```
[ 4-byte HKDF-derived prefix ][ 8-byte sequence number ]
```

**Prefix derivation:** The 4-byte prefix is derived from the session key via HKDF with
a direction- and plane-specific info string. Four independent prefixes exist per
session:

| Prefix | Direction | Plane |
|--------|-----------|-------|
| `c2s_data` | Client to Server | Data |
| `s2c_data` | Server to Client | Data |
| `c2s_ctrl` | Client to Server | Control |
| `s2c_ctrl` | Server to Client | Control |

**Nonce uniqueness guarantee:** Within a session, sequence numbers are monotonically
increasing and never reused. Since the prefix is fixed for the lifetime of a session
key and the sequence number never repeats, each (key, nonce) pair is used at most once.
After a `request_key_update()`, new prefixes are derived, resetting the effective nonce
space.

**Limitation:** The 4-byte prefix is drawn from a 2^32 space but is derived
deterministically from the session key. Across a very large number of sessions sharing
the same long-term key pair, two sessions may derive the same prefix. If they also
happen to use the same sequence number (possible for low sequence numbers), nonce reuse
would occur under ChaCha20-Poly1305 — a catastrophic failure. This becomes probable at
approximately **2^16 sessions** on the same key pair (birthday bound on 32 bits).
Applications with high session churn should rotate long-term key pairs well before this
threshold.
