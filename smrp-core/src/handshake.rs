/// SMRP handshake helpers shared by both client and server.
///
/// Wire layout of the HELLO / `HELLO_ACK` payload (128 bytes, unencrypted):
/// ```text
/// [0..32]   ephemeral X25519 public key
/// [32..64]  Ed25519 signing public key
/// [64..128] Ed25519 signature over (session_id || ephemeral_public_key)
/// ```
use crate::{
    constants::{SMRP_MAGIC, SMRP_VERSION},
    crypto::{self, EphemeralKeypair, SessionKey, SigningKey},
    error::SmrpError,
    packet::{self, Flags, PacketType, SmrpHeader},
    replay::ReplayWindow,
    session::{Session, SessionId, SessionState},
    transport,
};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

const HELLO_PAYLOAD_LEN: usize = 32 + 32 + 64;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn build_hello_payload(
    eph: &EphemeralKeypair,
    sign_key: &SigningKey,
    session_id: SessionId,
) -> Vec<u8> {
    let eph_pub = eph.public_key_bytes();
    let sign_pub = sign_key.public_key_bytes();

    let mut msg = Vec::with_capacity(8 + 32);
    msg.extend_from_slice(session_id.as_bytes());
    msg.extend_from_slice(eph_pub);
    let sig = sign_key.sign(&msg);

    let mut payload = Vec::with_capacity(HELLO_PAYLOAD_LEN);
    payload.extend_from_slice(eph_pub);
    payload.extend_from_slice(sign_pub);
    payload.extend_from_slice(&sig);
    payload
}

fn parse_hello_payload(
    payload: &[u8],
    session_id: SessionId,
) -> Result<([u8; 32], [u8; 32]), SmrpError> {
    if payload.len() < HELLO_PAYLOAD_LEN {
        return Err(SmrpError::MalformedHeader);
    }
    let mut eph_pub = [0u8; 32];
    let mut sign_pub = [0u8; 32];
    let mut sig = [0u8; 64];
    eph_pub.copy_from_slice(&payload[0..32]);
    sign_pub.copy_from_slice(&payload[32..64]);
    sig.copy_from_slice(&payload[64..128]);

    let mut msg = Vec::with_capacity(8 + 32);
    msg.extend_from_slice(session_id.as_bytes());
    msg.extend_from_slice(&eph_pub);
    crypto::ed25519_verify(&sign_pub, &msg, &sig)?;

    Ok((eph_pub, sign_pub))
}

fn derive_keys(
    shared: &[u8; 32],
    session_id: SessionId,
) -> Result<([u8; 32], [u8; 32]), SmrpError> {
    let salt = session_id.as_bytes().as_ref();
    let c2s = crypto::hkdf_sha256(shared, salt, b"smrp-v1-c2s")?;
    let s2c = crypto::hkdf_sha256(shared, salt, b"smrp-v1-s2c")?;
    Ok((c2s, s2c))
}

fn make_header(
    packet_type: PacketType,
    session_id: SessionId,
    seq: u64,
    ack: u64,
    payload_len: usize,
) -> SmrpHeader {
    SmrpHeader {
        magic: SMRP_MAGIC,
        version: SMRP_VERSION,
        packet_type,
        flags: Flags::default(),
        reserved: 0,
        session_id,
        sequence_number: seq,
        ack_number: ack,
        timestamp_us: packet::timestamp_us(),
        payload_len: payload_len as u16,
    }
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Performs the full client-side SMRP handshake.
///
/// Sends `HELLO` to `server_addr`, waits for `HELLO_ACK`, derives session
/// keys, and returns a fully [`SessionState::Established`] [`Session`].
///
/// # Errors
/// Propagates [`SmrpError`] on any crypto, network, or protocol failure.
pub async fn client_handshake(
    socket: &UdpSocket,
    server_addr: SocketAddr,
    sign_key: &SigningKey,
) -> Result<Session, SmrpError> {
    let eph = EphemeralKeypair::generate()?;
    let session_id = SessionId::generate()?;
    let payload = build_hello_payload(&eph, sign_key, session_id);

    let hello_hdr = make_header(PacketType::Hello, session_id, 0, 0, payload.len());
    transport::send_raw(socket, server_addr, &hello_hdr, &payload).await?;
    tracing::debug!(?session_id, "HELLO sent");

    let (ack_hdr, ack_payload, _) = transport::recv_raw(socket).await?;
    if ack_hdr.packet_type != PacketType::HelloAck {
        return Err(SmrpError::MalformedHeader);
    }

    let (server_eph_pub, server_sign_pub) =
        parse_hello_payload(&ack_payload, session_id)?;

    let shared = eph.agree(&server_eph_pub)?;
    let (c2s_raw, s2c_raw) = derive_keys(&shared, session_id)?;

    Ok(Session {
        id: session_id,
        state: SessionState::Established,
        peer_addr: server_addr,
        send_key: Some(SessionKey::from_raw(&c2s_raw)?),
        recv_key: Some(SessionKey::from_raw(&s2c_raw)?),
        send_seq: 1,
        recv_seq: 0,
        peer_sign_pub: Some(server_sign_pub),
        recv_replay: ReplayWindow::new(),
    })
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// Performs the server-side SMRP handshake in response to an incoming `HELLO`.
///
/// Parses and verifies `hello_payload`, generates a server ephemeral key,
/// derives session keys, sends `HELLO_ACK`, and returns an established [`Session`].
///
/// # Errors
/// Propagates [`SmrpError`] on any crypto, network, or protocol failure.
pub async fn server_handshake(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    session_id: SessionId,
    hello_payload: &[u8],
    server_sign_key: &SigningKey,
) -> Result<Session, SmrpError> {
    let (client_eph_pub, client_sign_pub) =
        parse_hello_payload(hello_payload, session_id)?;

    let server_eph = EphemeralKeypair::generate()?;
    let ack_payload = build_hello_payload(&server_eph, server_sign_key, session_id);

    let shared = server_eph.agree(&client_eph_pub)?;
    let (c2s_raw, s2c_raw) = derive_keys(&shared, session_id)?;

    let ack_hdr = make_header(PacketType::HelloAck, session_id, 0, 0, ack_payload.len());
    transport::send_raw(socket, client_addr, &ack_hdr, &ack_payload).await?;
    tracing::debug!(?session_id, "HELLO_ACK sent");

    Ok(Session {
        id: session_id,
        state: SessionState::Established,
        peer_addr: client_addr,
        send_key: Some(SessionKey::from_raw(&s2c_raw)?),
        recv_key: Some(SessionKey::from_raw(&c2s_raw)?),
        send_seq: 1,
        recv_seq: 0,
        peer_sign_pub: Some(client_sign_pub),
        recv_replay: ReplayWindow::new(),
    })
}

// ---------------------------------------------------------------------------
// Shared data-plane helpers
// ---------------------------------------------------------------------------

/// Encrypts `plaintext` and sends it as a `DATA` packet over an established session.
///
/// Uses the serialised header as AEAD additional data, so any header tampering
/// is detected on decryption.
///
/// # Errors
/// Returns [`SmrpError::InternalError`] if the session has no send key.
pub async fn send_data(
    socket: &UdpSocket,
    session: &mut Session,
    plaintext: &[u8],
) -> Result<(), SmrpError> {
    let key = session.send_key.as_ref().ok_or(SmrpError::InternalError)?;
    let seq = session.send_seq;
    let nonce = crypto::packet_nonce(session.id.as_bytes(), seq);

    // AAD = session_id || seq — unambiguous on both sides regardless of payload_len.
    let mut aad = [0u8; 16];
    aad[0..8].copy_from_slice(session.id.as_bytes());
    aad[8..16].copy_from_slice(&seq.to_be_bytes());
    let ciphertext = key.seal(&nonce, &aad, plaintext)?;

    let hdr_with_len = make_header(
        PacketType::Data,
        session.id,
        seq,
        session.recv_seq,
        ciphertext.len(),
    );
    transport::send_raw(socket, session.peer_addr, &hdr_with_len, &ciphertext).await?;
    session.send_seq += 1;
    Ok(())
}

/// Decrypts a `DATA` packet payload received on `session`.
///
/// Enforces anti-replay protection with a two-phase check:
/// the sequence number is validated **before** decryption so that a forged
/// packet cannot permanently consume a slot in the replay window, and the
/// window is only updated **after** successful AEAD authentication.
///
/// # Errors
/// Returns [`SmrpError::ReplayDetected`] if the sequence number has already
/// been seen or is outside the 128-packet window, [`SmrpError::AuthenticationFailure`]
/// on AEAD tag mismatch, or [`SmrpError::InternalError`] if the session has no
/// receive key.
pub fn decrypt_data(
    session: &mut Session,
    hdr: &SmrpHeader,
    ciphertext: &[u8],
) -> Result<Vec<u8>, SmrpError> {
    let seq = hdr.sequence_number;

    // Phase 1 — reject replays and out-of-window packets without touching crypto.
    session.recv_replay.can_accept(seq)?;

    let key = session.recv_key.as_ref().ok_or(SmrpError::InternalError)?;
    let nonce = crypto::packet_nonce(session.id.as_bytes(), seq);

    // Must match the AAD constructed in send_data.
    let mut aad = [0u8; 16];
    aad[0..8].copy_from_slice(session.id.as_bytes());
    aad[8..16].copy_from_slice(&seq.to_be_bytes());

    // Phase 2 — AEAD open (expensive; only runs if the seq passed phase 1).
    let plaintext = key.open(&nonce, &aad, ciphertext)?;

    // Phase 3 — commit: mark seq as seen only after authenticated decryption.
    session.recv_replay.mark_seen(seq);
    session.recv_seq = seq;
    Ok(plaintext)
}

/// Sends a zero-payload `ACK` for the given sequence number.
///
/// # Errors
/// Returns [`SmrpError::InternalError`] on socket failure.
pub async fn send_ack(
    socket: &UdpSocket,
    session: &Session,
    ack_seq: u64,
) -> Result<(), SmrpError> {
    let hdr = make_header(PacketType::Ack, session.id, session.send_seq, ack_seq, 0);
    transport::send_raw(socket, session.peer_addr, &hdr, &[]).await
}

/// Sends a `FIN` packet and marks the session as `Closing`.
///
/// # Errors
/// Returns [`SmrpError::InternalError`] on socket failure.
pub async fn send_fin(socket: &UdpSocket, session: &mut Session) -> Result<(), SmrpError> {
    let mut hdr = make_header(PacketType::Fin, session.id, session.send_seq, session.recv_seq, 0);
    hdr.flags.0 |= Flags::FIN;
    transport::send_raw(socket, session.peer_addr, &hdr, &[]).await?;
    session.state = SessionState::Closing;
    Ok(())
}
