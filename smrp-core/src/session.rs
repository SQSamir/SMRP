use crate::{constants::SESSION_ID_LEN, crypto::SessionKey, error::SmrpError, replay::ReplayWindow};
use std::net::SocketAddr;

/// Opaque identifier that uniquely names an SMRP session for its lifetime.
///
/// Wire representation: 8 bytes, big-endian, in every packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; SESSION_ID_LEN]);

impl SessionId {
    /// Wraps raw bytes as a [`SessionId`].
    #[must_use]
    pub fn from_bytes(bytes: [u8; SESSION_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Generates a random [`SessionId`] using the system RNG.
    ///
    /// # Errors
    /// Returns [`SmrpError::InternalError`] if the RNG is unavailable.
    pub fn generate() -> Result<Self, SmrpError> {
        let bytes = crate::crypto::random_bytes::<SESSION_ID_LEN>()?;
        Ok(Self(bytes))
    }

    /// Returns the raw byte representation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SESSION_ID_LEN] {
        &self.0
    }
}

/// Lifecycle state of an SMRP session, driven by the handshake state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session object created; no packets exchanged yet.
    Init,
    /// Local `HELLO` sent; waiting for peer `HELLO`.
    HelloSent,
    /// Peer `HELLO` received; local `HELLO` not yet sent.
    HelloReceived,
    /// Both `HELLO` messages exchanged; key derivation in progress.
    Handshaking,
    /// Handshake complete; session keys are live and data can flow.
    Established,
    /// In-band key update (`KEY_UPDATE`) in progress.
    KeyUpdate,
    /// Graceful teardown initiated; `FIN` sent or received.
    Closing,
    /// Session fully terminated; all state may be discarded.
    Closed,
    /// Session entered an unrecoverable error state.
    Error,
}

/// Live SMRP session: key material, sequence counters, and peer address.
pub struct Session {
    /// Session identifier echoed in every packet header.
    pub id: SessionId,
    /// Current lifecycle state.
    pub state: SessionState,
    /// UDP address of the remote peer.
    pub peer_addr: SocketAddr,
    /// Key used to seal packets sent to the peer.
    pub send_key: Option<SessionKey>,
    /// Key used to open packets received from the peer.
    pub recv_key: Option<SessionKey>,
    /// Monotonically increasing counter for outgoing packets.
    pub send_seq: u64,
    /// Highest sequence number received from the peer.
    pub recv_seq: u64,
    /// Peer's Ed25519 public key, verified during handshake.
    pub peer_sign_pub: Option<[u8; 32]>,
    /// Anti-replay window for incoming DATA packets.
    pub recv_replay: ReplayWindow,
}

impl Session {
    /// Returns `true` if session keys are derived and data can flow.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == SessionState::Established
            && self.send_key.is_some()
            && self.recv_key.is_some()
    }
}

#[cfg(test)]
#[allow(clippy::pedantic)]
mod tests {
    use super::*;

    #[test]
    fn session_id_round_trips() {
        let raw = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let id = SessionId::from_bytes(raw);
        assert_eq!(id.as_bytes(), &raw);
    }

    #[test]
    fn session_id_equality() {
        let a = SessionId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let b = SessionId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let c = SessionId::from_bytes([0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn session_state_is_copy() {
        let s = SessionState::Established;
        let t = s;
        assert_eq!(s, t);
    }
}
