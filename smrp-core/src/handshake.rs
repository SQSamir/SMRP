/// SMRP handshake helpers shared by both client and server.
///
/// Wire layout of the HELLO payload (128 bytes, unencrypted):
/// ```text
/// [0..32]   ephemeral X25519 public key
/// [32..64]  Ed25519 signing public key
/// [64..128] Ed25519 signature over (session_id[8] || ephemeral_pub[32])
/// ```
///
/// Wire layout of the `HELLO_ACK` payload (128 bytes, unencrypted):
/// ```text
/// [0..32]   server ephemeral X25519 public key
/// [32..64]  server Ed25519 signing public key
/// [64..128] Ed25519 signature over (session_id[8] || server_eph_pub[32] || SHA-256(HELLO_payload)[32])
/// ```
/// The SHA-256 transcript binding prevents a `HELLO_ACK` from being replayed
/// against a different `HELLO` without the server's private key.
use crate::{
    constants::{SMRP_MAGIC, SMRP_VERSION},
    crypto::{self, derive_nonce_prefix, EphemeralKeypair, SessionKey, SigningKey},
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

/// Builds the HELLO payload. Signature covers `session_id[8] || eph_pub[32]`.
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

/// Parses and verifies a HELLO payload. Returns `(eph_pub, sign_pub)`.
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

/// Builds the `HELLO_ACK` payload. Signature covers
/// `session_id[8] || server_eph_pub[32] || SHA-256(client_hello_payload)[32]`.
fn build_hello_ack_payload(
    eph: &EphemeralKeypair,
    sign_key: &SigningKey,
    session_id: SessionId,
    client_hello: &[u8],
) -> Vec<u8> {
    let eph_pub = eph.public_key_bytes();
    let sign_pub = sign_key.public_key_bytes();
    let hello_hash = crypto::sha256(client_hello);

    let mut msg = Vec::with_capacity(8 + 32 + 32);
    msg.extend_from_slice(session_id.as_bytes());
    msg.extend_from_slice(eph_pub);
    msg.extend_from_slice(&hello_hash);
    let sig = sign_key.sign(&msg);

    let mut payload = Vec::with_capacity(HELLO_PAYLOAD_LEN);
    payload.extend_from_slice(eph_pub);
    payload.extend_from_slice(sign_pub);
    payload.extend_from_slice(&sig);
    payload
}

/// Parses and verifies a `HELLO_ACK` payload against the transcript hash of the
/// original `HELLO`. Returns `(server_eph_pub, server_sign_pub)`.
fn parse_hello_ack_payload(
    payload: &[u8],
    session_id: SessionId,
    client_hello: &[u8],
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

    let hello_hash = crypto::sha256(client_hello);
    let mut msg = Vec::with_capacity(8 + 32 + 32);
    msg.extend_from_slice(session_id.as_bytes());
    msg.extend_from_slice(&eph_pub);
    msg.extend_from_slice(&hello_hash);
    crypto::ed25519_verify(&sign_pub, &msg, &sig)?;

    Ok((eph_pub, sign_pub))
}

struct DerivedKeys {
    c2s: [u8; 32],
    s2c: [u8; 32],
    data_c2s: [u8; 4],
    data_s2c: [u8; 4],
    ctrl_c2s: [u8; 4],
    ctrl_s2c: [u8; 4],
}

/// Derives session encryption keys and HKDF nonce prefixes from a shared secret.
fn derive_keys_and_prefixes(
    shared: &[u8; 32],
    session_id: SessionId,
) -> Result<DerivedKeys, SmrpError> {
    let salt = session_id.as_bytes().as_ref();
    let c2s = crypto::hkdf_sha256(shared, salt, b"smrp-v1-c2s")?;
    let s2c = crypto::hkdf_sha256(shared, salt, b"smrp-v1-s2c")?;

    Ok(DerivedKeys {
        data_c2s: derive_nonce_prefix(&c2s, b"smrp-v1-data-nonce-c2s")?,
        data_s2c: derive_nonce_prefix(&s2c, b"smrp-v1-data-nonce-s2c")?,
        ctrl_c2s: derive_nonce_prefix(&c2s, b"smrp-v1-ctrl-nonce-c2s")?,
        ctrl_s2c: derive_nonce_prefix(&s2c, b"smrp-v1-ctrl-nonce-s2c")?,
        c2s,
        s2c,
    })
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
        frag_id: 0,
        frag_index: 0,
        frag_count: 0,
        recv_window: 0,
        stream_id: 0,
    }
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Performs the full client-side SMRP handshake.
///
/// Sends `HELLO` to `server_addr`, waits for `HELLO_ACK`, derives session
/// keys and nonce prefixes, and returns a fully [`SessionState::Established`] [`Session`].
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
    let hello_payload = build_hello_payload(&eph, sign_key, session_id);

    let hello_hdr = make_header(PacketType::Hello, session_id, 0, 0, hello_payload.len());
    transport::send_raw(socket, server_addr, &hello_hdr, &hello_payload).await?;
    tracing::debug!(?session_id, "HELLO sent");

    let (ack_hdr, ack_payload, _, _) = transport::recv_raw(socket).await?;
    if ack_hdr.packet_type != PacketType::HelloAck {
        return Err(SmrpError::MalformedHeader);
    }

    // Verify the HELLO_ACK is bound to our specific HELLO via transcript hash.
    let (server_eph_pub, server_sign_pub) =
        parse_hello_ack_payload(&ack_payload, session_id, &hello_payload)?;

    let shared = eph.agree(&server_eph_pub)?;
    let dk = derive_keys_and_prefixes(&shared, session_id)?;

    Ok(Session {
        id: session_id,
        state: SessionState::Established,
        peer_addr: server_addr,
        send_key: Some(SessionKey::from_raw(&dk.c2s)?),
        recv_key: Some(SessionKey::from_raw(&dk.s2c)?),
        send_seq: 1,
        recv_seq: 0,
        peer_sign_pub: Some(server_sign_pub),
        recv_replay: ReplayWindow::new(),
        // Client sends c2s and receives s2c.
        data_send_nonce_prefix: dk.data_c2s,
        data_recv_nonce_prefix: dk.data_s2c,
        ctrl_send_nonce_prefix: dk.ctrl_c2s,
        ctrl_recv_nonce_prefix: dk.ctrl_s2c,
    })
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// Performs the server-side SMRP handshake in response to an incoming `HELLO`.
///
/// Parses and verifies `hello_payload`, generates a server ephemeral key,
/// derives session keys and nonce prefixes, sends `HELLO_ACK`, and returns an
/// established [`Session`].
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
    let (client_eph_pub, client_sign_pub) = parse_hello_payload(hello_payload, session_id)?;

    let server_eph = EphemeralKeypair::generate()?;
    // Bind HELLO_ACK to the client's HELLO via transcript hash.
    let ack_payload =
        build_hello_ack_payload(&server_eph, server_sign_key, session_id, hello_payload);

    let shared = server_eph.agree(&client_eph_pub)?;
    let dk = derive_keys_and_prefixes(&shared, session_id)?;

    let ack_hdr = make_header(PacketType::HelloAck, session_id, 0, 0, ack_payload.len());
    transport::send_raw(socket, client_addr, &ack_hdr, &ack_payload).await?;
    tracing::debug!(?session_id, "HELLO_ACK sent");

    Ok(Session {
        id: session_id,
        state: SessionState::Established,
        peer_addr: client_addr,
        send_key: Some(SessionKey::from_raw(&dk.s2c)?),
        recv_key: Some(SessionKey::from_raw(&dk.c2s)?),
        send_seq: 1,
        recv_seq: 0,
        peer_sign_pub: Some(client_sign_pub),
        recv_replay: ReplayWindow::new(),
        // Server sends s2c and receives c2s.
        data_send_nonce_prefix: dk.data_s2c,
        data_recv_nonce_prefix: dk.data_c2s,
        ctrl_send_nonce_prefix: dk.ctrl_s2c,
        ctrl_recv_nonce_prefix: dk.ctrl_c2s,
    })
}
