use crate::error::SmrpError;
use ring::{aead, agreement, hkdf, rand, signature as ring_sig};
use ring_sig::KeyPair as _;

/// Fills `buf` with cryptographically secure random bytes.
///
/// # Errors
/// Returns [`SmrpError::InternalError`] if the system RNG is unavailable.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], SmrpError> {
    let rng = rand::SystemRandom::new();
    let mut out = [0u8; N];
    rand::SecureRandom::fill(&rng, &mut out).map_err(|_| SmrpError::InternalError)?;
    Ok(out)
}

/// An X25519 ephemeral key pair used during the SMRP handshake.
pub struct EphemeralKeypair {
    private_key: agreement::EphemeralPrivateKey,
    public_key_bytes: [u8; 32],
}

impl EphemeralKeypair {
    /// Generates a fresh ephemeral X25519 key pair using the system RNG.
    ///
    /// # Errors
    /// Returns [`SmrpError::InternalError`] if the system RNG is unavailable.
    pub fn generate() -> Result<Self, SmrpError> {
        let rng = rand::SystemRandom::new();
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .map_err(|_| SmrpError::InternalError)?;
        let pub_key = private_key
            .compute_public_key()
            .map_err(|_| SmrpError::InternalError)?;
        let mut public_key_bytes = [0u8; 32];
        public_key_bytes.copy_from_slice(pub_key.as_ref());
        Ok(Self {
            private_key,
            public_key_bytes,
        })
    }

    /// Returns the 32-byte Curve25519 public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_key_bytes
    }

    /// Performs X25519 Diffie-Hellman and returns the 32-byte shared secret.
    /// Consumes `self` — the private key is erased after use.
    ///
    /// # Errors
    /// Returns [`SmrpError::InternalError`] on cryptographic failure.
    pub fn agree(self, peer_public_key: &[u8; 32]) -> Result<[u8; 32], SmrpError> {
        let peer_pub =
            agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key.as_ref());
        agreement::agree_ephemeral(self.private_key, &peer_pub, |shared| {
            let mut out = [0u8; 32];
            out.copy_from_slice(shared);
            out
        })
        .map_err(|_| SmrpError::InternalError)
    }
}

/// A symmetric session key wrapping ChaCha20-Poly1305.
pub struct SessionKey {
    inner: aead::LessSafeKey,
}

impl SessionKey {
    /// Constructs a [`SessionKey`] from 32 raw key bytes.
    ///
    /// # Errors
    /// Returns [`SmrpError::InternalError`] if the key length is invalid.
    pub fn from_raw(key_bytes: &[u8; 32]) -> Result<Self, SmrpError> {
        let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key_bytes.as_ref())
            .map_err(|_| SmrpError::InternalError)?;
        Ok(Self {
            inner: aead::LessSafeKey::new(unbound),
        })
    }

    /// Encrypts `plaintext` returning ciphertext + 16-byte Poly1305 tag.
    ///
    /// # Errors
    /// Returns [`SmrpError::InternalError`] on failure.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SmrpError> {
        let nonce_val = aead::Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| SmrpError::InternalError)?;
        let mut in_out = plaintext.to_vec();
        self.inner
            .seal_in_place_append_tag(nonce_val, aead::Aad::from(aad), &mut in_out)
            .map_err(|_| SmrpError::InternalError)?;
        Ok(in_out)
    }

    /// Decrypts and authenticates `ciphertext_with_tag`, returning plaintext.
    ///
    /// # Errors
    /// Returns [`SmrpError::AuthenticationFailure`] on tag mismatch.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], ciphertext_with_tag: &[u8]) -> Result<Vec<u8>, SmrpError> {
        let nonce_val = aead::Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| SmrpError::InternalError)?;
        let mut in_out = ciphertext_with_tag.to_vec();
        let plaintext_len = self
            .inner
            .open_in_place(nonce_val, aead::Aad::from(aad), &mut in_out)
            .map_err(|_| SmrpError::AuthenticationFailure)?
            .len();
        in_out.truncate(plaintext_len);
        Ok(in_out)
    }
}

struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derives 32 bytes via HKDF-SHA-256.
///
/// # Errors
/// Returns [`SmrpError::InternalError`] on failure.
pub fn hkdf_sha256(ikm: &[u8; 32], salt: &[u8], info: &[u8]) -> Result<[u8; 32], SmrpError> {
    let salt_val = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt_val.extract(ikm.as_ref());
    let mut out = [0u8; 32];
    prk.expand(&[info], HkdfLen(32))
        .map_err(|_| SmrpError::InternalError)?
        .fill(&mut out)
        .map_err(|_| SmrpError::InternalError)?;
    Ok(out)
}

/// An Ed25519 signing key pair.
pub struct SigningKey {
    inner: ring_sig::Ed25519KeyPair,
    public_bytes: [u8; 32],
}

impl SigningKey {
    /// Generates a fresh Ed25519 signing key pair.
    ///
    /// # Errors
    /// Returns [`SmrpError::InternalError`] if the RNG is unavailable.
    pub fn generate() -> Result<Self, SmrpError> {
        let rng = rand::SystemRandom::new();
        let pkcs8 = ring_sig::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| SmrpError::InternalError)?;
        let inner = ring_sig::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| SmrpError::InternalError)?;
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(inner.public_key().as_ref());
        Ok(Self { inner, public_bytes })
    }

    /// Returns the 32-byte Ed25519 public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_bytes
    }

    /// Signs `message` and returns a 64-byte Ed25519 signature.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sig = self.inner.sign(message);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }
}

/// Verifies an Ed25519 signature over `message` with `public_key`.
///
/// # Errors
/// Returns [`SmrpError::AuthenticationFailure`] if the signature is invalid.
pub fn ed25519_verify(
    public_key: &[u8; 32],
    message: &[u8],
    sig_bytes: &[u8; 64],
) -> Result<(), SmrpError> {
    let pk = ring_sig::UnparsedPublicKey::new(&ring_sig::ED25519, public_key.as_slice());
    pk.verify(message, sig_bytes.as_slice())
        .map_err(|_| SmrpError::AuthenticationFailure)
}

/// Builds the 12-byte ChaCha20-Poly1305 nonce: `session_id[0..4] || seq (8 bytes BE)`.
#[must_use]
pub fn packet_nonce(session_id: &[u8; 8], seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&session_id[0..4]);
    nonce[4..12].copy_from_slice(&seq.to_be_bytes());
    nonce
}
