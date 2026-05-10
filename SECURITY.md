# Security Policy

> **NOT PRODUCTION-READY.**
> SMRP is a research-grade protocol implementation. It has not been externally audited
> and MUST NOT be used to protect sensitive data in any production environment.

---

## Responsible Disclosure

If you discover a security vulnerability in SMRP, please report it **privately** by
emailing:

**samir.gasimov@live.com**

Use the subject line: `[SMRP SECURITY]`

Please include:
- A clear description of the vulnerability
- Steps to reproduce or a proof-of-concept
- Potential impact assessment
- Any suggested mitigations you have identified

**Response window:** The maintainer commits to acknowledging your report within **7 days**.
Please do not disclose the issue publicly until a fix has been coordinated.

---

## Supported Versions

| Version / Branch | Supported |
|------------------|-----------|
| Latest commit on `master` | Yes |
| Any tagged release or older commit | No |

Only the latest commit on the `master` branch receives security fixes. There is no
backport policy.

---

## Known Limitations

These are known security limitations of the current design. They are documented here for
transparency and to set expectations for evaluators.

### 1. No Certificate Infrastructure (TOFU / Out-of-Band Key Distribution)

SMRP performs no certificate validation. Peers authenticate each other via Ed25519
long-term signing keys, but there is no PKI to bind those keys to identities. The
protocol relies on **Trust On First Use (TOFU)** or out-of-band key distribution.
A man-in-the-middle attack is possible on the first connection if the peer's public
key has not been pinned in advance.

### 2. Unauthenticated KEEPALIVE Packets

`KEEPALIVE` packets are sent outside the established session key scope and are
**not authenticated**. An active attacker can inject or suppress KEEPALIVE packets
to manipulate session-liveness detection without breaking the cryptographic session.
This does not expose plaintext or session keys, but it can cause spurious session
timeouts or mask genuine connectivity loss.

### 3. Key Update Requires Empty Retransmit Buffer

`request_key_update()` requires the retransmit buffer to be completely empty before
proceeding. Any in-flight (unacknowledged) packets at the moment of a rekey attempt
will cause the session to be terminated rather than rekeyed. Applications that
generate continuous traffic must drain the send window before triggering a key update,
or accept the risk of session death.

### 4. HKDF-Derived 4-Byte Nonce Prefix Limits Distinct Sessions

The per-direction nonce prefix is derived from the session key via HKDF and is 4 bytes
wide. Because this value is fixed for the lifetime of a session key, the number of
distinct (prefix, key) pairs is bounded. At approximately **2^16 sessions** on the same
long-term key pair, the probability of a nonce-prefix collision between two concurrent
sessions becomes non-negligible. Reuse of a (key, nonce) pair under ChaCha20-Poly1305
would be catastrophic. Applications expecting very high session churn on a single key
pair should rotate long-term key pairs proactively.

### 5. Not Externally Audited

The protocol design and this implementation have not been reviewed by an independent
cryptographer or security auditor. Bugs in the `ring` crate bindings, the handshake
state machine, or the key derivation logic may exist and have not been ruled out.

---

## Out of Scope

The following are explicitly **not goals** of SMRP and will not be addressed:

- TLS compatibility or interoperability
- X.509 certificate support
- Any form of Public Key Infrastructure (PKI)
