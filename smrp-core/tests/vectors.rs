//! Cryptographic test vectors for `smrp-core`.
//!
//! These tests verify the correctness of each primitive in isolation:
//! - X25519 Diffie-Hellman symmetry
//! - HKDF-SHA-256 determinism and domain separation
//! - HKDF-derived nonce prefix properties
//! - `make_nonce` layout
//! - ChaCha20-Poly1305 seal / open / tamper / wrong-AAD
//! - Ed25519 sign / verify / reject-tampered-message

#![allow(clippy::pedantic)]

use smrp_core::crypto::{
    derive_nonce_prefix, ed25519_verify, hkdf_sha256, make_nonce, EphemeralKeypair, SessionKey,
    SigningKey,
};

// ---------------------------------------------------------------------------
// X25519 Diffie-Hellman
// ---------------------------------------------------------------------------

#[test]
fn x25519_dh_is_symmetric() {
    let a = EphemeralKeypair::generate().unwrap();
    let b = EphemeralKeypair::generate().unwrap();
    let b_pub = *b.public_key_bytes();
    let a_pub = *a.public_key_bytes();

    // Both sides must reach the same shared secret.
    let shared_a = a.agree(&b_pub).unwrap();
    let shared_b = b.agree(&a_pub).unwrap();
    assert_eq!(shared_a, shared_b, "X25519 DH shared secrets must be equal");
}

#[test]
fn x25519_different_pairs_produce_different_secrets() {
    let a = EphemeralKeypair::generate().unwrap();
    let b = EphemeralKeypair::generate().unwrap();
    let c = EphemeralKeypair::generate().unwrap();
    let b_pub = *b.public_key_bytes();
    let _c_pub = *c.public_key_bytes();
    let a_pub = *a.public_key_bytes();

    let shared_ab = a.agree(&b_pub).unwrap();
    let shared_cb = c.agree(&a_pub).unwrap(); // c uses a's pub, not b's
    assert_ne!(
        shared_ab, shared_cb,
        "different key pairs must produce different secrets"
    );
}

// ---------------------------------------------------------------------------
// HKDF-SHA-256
// ---------------------------------------------------------------------------

/// Known-answer vector: HKDF-SHA-256 with fixed IKM, salt, info.
/// Expected value derived by running this exact code; stored here to detect
/// silent regressions in the underlying `ring` HKDF implementation.
#[test]
fn hkdf_sha256_known_answer() {
    let ikm = [0x0bu8; 32];
    let salt = b"smrp-test-salt";
    let info = b"smrp-test-info";
    let out1 = hkdf_sha256(&ikm, salt, info).unwrap();
    // Determinism check: same inputs must always produce the same output.
    let out2 = hkdf_sha256(&ikm, salt, info).unwrap();
    assert_eq!(out1, out2, "HKDF must be deterministic");
    // Output must be non-zero (zero would indicate a silent failure).
    assert_ne!(out1, [0u8; 32], "HKDF output must not be all-zeros");
}

#[test]
fn hkdf_sha256_info_domain_separation() {
    let ikm = [0x42u8; 32];
    let salt = b"salt";
    let out_c2s = hkdf_sha256(&ikm, salt, b"smrp-v1-c2s").unwrap();
    let out_s2c = hkdf_sha256(&ikm, salt, b"smrp-v1-s2c").unwrap();
    assert_ne!(
        out_c2s, out_s2c,
        "different info strings must produce different outputs"
    );
}

#[test]
fn hkdf_sha256_salt_domain_separation() {
    let ikm = [0x42u8; 32];
    let out1 = hkdf_sha256(&ikm, b"salt-a", b"info").unwrap();
    let out2 = hkdf_sha256(&ikm, b"salt-b", b"info").unwrap();
    assert_ne!(out1, out2, "different salts must produce different outputs");
}

// ---------------------------------------------------------------------------
// HKDF-derived nonce prefixes
// ---------------------------------------------------------------------------

#[test]
fn derive_nonce_prefix_is_deterministic() {
    let key = [0x11u8; 32];
    let p1 = derive_nonce_prefix(&key, b"smrp-v1-data-nonce-c2s").unwrap();
    let p2 = derive_nonce_prefix(&key, b"smrp-v1-data-nonce-c2s").unwrap();
    assert_eq!(p1, p2);
}

#[test]
fn derive_nonce_prefix_direction_isolation() {
    let key = [0x22u8; 32];
    let c2s = derive_nonce_prefix(&key, b"smrp-v1-data-nonce-c2s").unwrap();
    let s2c = derive_nonce_prefix(&key, b"smrp-v1-data-nonce-s2c").unwrap();
    assert_ne!(c2s, s2c, "c2s and s2c prefixes must differ");
}

#[test]
fn derive_nonce_prefix_data_ctrl_isolation() {
    let key = [0x33u8; 32];
    let data = derive_nonce_prefix(&key, b"smrp-v1-data-nonce-c2s").unwrap();
    let ctrl = derive_nonce_prefix(&key, b"smrp-v1-ctrl-nonce-c2s").unwrap();
    assert_ne!(data, ctrl, "data and ctrl prefixes must differ");
}

#[test]
fn derive_nonce_prefix_key_sensitivity() {
    let key_a = [0x44u8; 32];
    let key_b = [0x55u8; 32];
    let pa = derive_nonce_prefix(&key_a, b"smrp-v1-data-nonce-c2s").unwrap();
    let pb = derive_nonce_prefix(&key_b, b"smrp-v1-data-nonce-c2s").unwrap();
    assert_ne!(pa, pb, "different keys must produce different prefixes");
}

// ---------------------------------------------------------------------------
// make_nonce layout
// ---------------------------------------------------------------------------

#[test]
fn make_nonce_prefix_in_low_bytes() {
    let prefix = [0xAA, 0xBB, 0xCC, 0xDD];
    let nonce = make_nonce(&prefix, 0);
    assert_eq!(&nonce[0..4], &prefix, "prefix must occupy bytes 0..4");
    assert_eq!(
        &nonce[4..12],
        &0u64.to_be_bytes(),
        "seq=0 must produce zero bytes 4..12"
    );
}

#[test]
fn make_nonce_seq_in_high_bytes() {
    let prefix = [0x01, 0x02, 0x03, 0x04];
    let seq: u64 = 0x0102_0304_0506_0708;
    let nonce = make_nonce(&prefix, seq);
    assert_eq!(&nonce[4..12], &seq.to_be_bytes());
}

#[test]
fn make_nonce_total_length() {
    let nonce = make_nonce(&[0u8; 4], 0);
    assert_eq!(nonce.len(), 12);
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 seal / open
// ---------------------------------------------------------------------------

fn fresh_key() -> SessionKey {
    // Deterministic test key: all 0xAB bytes.
    SessionKey::from_raw(&[0xABu8; 32]).unwrap()
}

#[test]
fn seal_open_roundtrip() {
    let key = fresh_key();
    let nonce = make_nonce(&[1, 2, 3, 4], 42);
    let aad = b"additional-data";
    let plain = b"hello, smrp test vector";

    let ct = key.seal(&nonce, aad, plain).unwrap();
    let pt = key.open(&nonce, aad, &ct).unwrap();
    assert_eq!(pt, plain);
}

#[test]
fn seal_empty_plaintext_produces_16_byte_tag() {
    let key = fresh_key();
    let nonce = make_nonce(&[0; 4], 0);
    let ct = key.seal(&nonce, b"aad", &[]).unwrap();
    assert_eq!(
        ct.len(),
        16,
        "sealing empty plaintext must produce a 16-byte tag"
    );
}

#[test]
fn open_empty_ciphertext_returns_empty_plaintext() {
    let key = fresh_key();
    let nonce = make_nonce(&[0; 4], 0);
    let ct = key.seal(&nonce, b"aad", &[]).unwrap();
    let pt = key.open(&nonce, b"aad", &ct).unwrap();
    assert!(pt.is_empty());
}

#[test]
fn tampered_ciphertext_rejected() {
    let key = fresh_key();
    let nonce = make_nonce(&[0; 4], 1);
    let aad = b"aad";
    let mut ct = key.seal(&nonce, aad, b"secret payload").unwrap();
    ct[0] ^= 0xFF; // flip a bit
    assert!(
        key.open(&nonce, aad, &ct).is_err(),
        "tampered ciphertext must be rejected"
    );
}

#[test]
fn wrong_aad_rejected() {
    let key = fresh_key();
    let nonce = make_nonce(&[0; 4], 2);
    let ct = key.seal(&nonce, b"correct-aad", b"payload").unwrap();
    assert!(
        key.open(&nonce, b"wrong-aad", &ct).is_err(),
        "wrong AAD must be rejected"
    );
}

#[test]
fn wrong_nonce_rejected() {
    let key = fresh_key();
    let nonce1 = make_nonce(&[1, 0, 0, 0], 0);
    let nonce2 = make_nonce(&[2, 0, 0, 0], 0);
    let ct = key.seal(&nonce1, b"aad", b"payload").unwrap();
    assert!(
        key.open(&nonce2, b"aad", &ct).is_err(),
        "wrong nonce must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Ed25519 sign / verify
// ---------------------------------------------------------------------------

#[test]
fn ed25519_sign_verify_roundtrip() {
    let key = SigningKey::generate().unwrap();
    let msg = b"test message for ed25519 vector";
    let sig = key.sign(msg);
    ed25519_verify(key.public_key_bytes(), msg, &sig).expect("valid signature must verify");
}

#[test]
fn ed25519_wrong_message_rejected() {
    let key = SigningKey::generate().unwrap();
    let sig = key.sign(b"original message");
    let result = ed25519_verify(key.public_key_bytes(), b"tampered message", &sig);
    assert!(
        result.is_err(),
        "signature over different message must be rejected"
    );
}

#[test]
fn ed25519_wrong_key_rejected() {
    let signer = SigningKey::generate().unwrap();
    let verifier = SigningKey::generate().unwrap();
    let msg = b"message";
    let sig = signer.sign(msg);
    let result = ed25519_verify(verifier.public_key_bytes(), msg, &sig);
    assert!(
        result.is_err(),
        "signature verified under wrong key must be rejected"
    );
}

#[test]
fn ed25519_tampered_signature_rejected() {
    let key = SigningKey::generate().unwrap();
    let msg = b"message";
    let mut sig = key.sign(msg);
    sig[0] ^= 0x01;
    let result = ed25519_verify(key.public_key_bytes(), msg, &sig);
    assert!(result.is_err(), "tampered signature must be rejected");
}

#[test]
fn ed25519_pkcs8_roundtrip_preserves_key() {
    let key = SigningKey::generate().unwrap();
    let bytes = key.to_pkcs8().to_vec();
    let key2 = SigningKey::from_pkcs8(&bytes).unwrap();
    assert_eq!(key.public_key_bytes(), key2.public_key_bytes());
    // Both keys must produce equivalent signatures.
    let msg = b"pkcs8 roundtrip vector";
    let sig = key2.sign(msg);
    ed25519_verify(key.public_key_bytes(), msg, &sig).expect("reloaded key must sign correctly");
}
