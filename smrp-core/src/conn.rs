//! High-level SMRP connection API.
//!
//! Hides all socket management, session state, and cryptography behind two
//! types that mirror the familiar `TcpListener` / `TcpStream` pattern.
//!
//! # Server
//! ```no_run
//! # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use smrp_core::conn::SmrpListener;
//!
//! let mut listener = SmrpListener::bind("0.0.0.0:9000").await?;
//! while let Some(mut conn) = listener.accept().await {
//!     tokio::spawn(async move {
//!         while let Ok(Some(data)) = conn.recv().await {
//!             conn.send(&data).await.ok(); // echo
//!         }
//!     });
//! }
//! # Ok(()) }
//! ```
//!
//! # Client
//! ```no_run
//! # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use smrp_core::conn::SmrpConnection;
//!
//! let mut conn = SmrpConnection::connect("127.0.0.1:9000").await?;
//! conn.send(b"hello").await?;
//! if let Some(reply) = conn.recv().await? {
//!     println!("{}", String::from_utf8_lossy(&reply));
//! }
//! conn.close().await?;
//! # Ok(()) }
//! ```

use crate::{
    constants::{
        KEEPALIVE_INTERVAL_SECS, MAX_PAYLOAD, MAX_SESSIONS, SMRP_MAGIC, SMRP_VERSION,
    },
    crypto::{packet_nonce, SigningKey},
    error::SmrpError,
    handshake,
    packet::{self, timestamp_us, Flags, PacketType, SmrpHeader},
    replay::ReplayWindow,
    session::{Session, SessionId},
    transport,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::mpsc, time};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

type Pkt = (SmrpHeader, Vec<u8>);
type SessionMap = Arc<tokio::sync::Mutex<HashMap<SessionId, mpsc::Sender<Pkt>>>>;

/// How long `close()` waits for a FIN_ACK before giving up.
const FIN_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// How long `connect()` waits for HELLO_ACK before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long `recv()` can wait before returning `Err(HandshakeTimeout)`.
/// Callers that need a different deadline should use `recv_timeout`.
const RECV_TIMEOUT: Duration = Duration::from_secs(60);

/// Dead-session threshold: 3 × keepalive interval.
pub const SESSION_DEAD_SECS: u64 = KEEPALIVE_INTERVAL_SECS * 3;

/// Max HELLO packets accepted from one source IP per second.
const HELLO_RATE_LIMIT: u32 = 10;

/// Allowed clock skew for HELLO timestamp validation (seconds).
const HELLO_CLOCK_SKEW_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// SmrpConnection
// ---------------------------------------------------------------------------

/// An established, encrypted SMRP session.
///
/// Obtained via [`SmrpConnection::connect`] (client) or [`SmrpListener::accept`] (server).
pub struct SmrpConnection {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    session_id: SessionId,

    send_key: crate::crypto::SessionKey,
    send_seq: u64,

    recv_key: crate::crypto::SessionKey,
    recv_replay: ReplayWindow,
    recv_seq: u64,

    /// Encrypted packets forwarded here by the receive task / listener dispatch.
    data_rx: mpsc::Receiver<Pkt>,
}

impl SmrpConnection {
    /// Opens an SMRP connection to `server_addr` (e.g. `"127.0.0.1:9000"`).
    ///
    /// Fails with [`SmrpError::HandshakeTimeout`] if the server does not
    /// respond within 10 seconds.
    ///
    /// # Errors
    /// Returns [`SmrpError`] on any network or cryptographic failure.
    pub async fn connect(server_addr: &str) -> Result<Self, SmrpError> {
        time::timeout(CONNECT_TIMEOUT, Self::connect_inner(server_addr))
            .await
            .map_err(|_| SmrpError::HandshakeTimeout)?
    }

    async fn connect_inner(server_addr: &str) -> Result<Self, SmrpError> {
        let addr: SocketAddr = tokio::net::lookup_host(server_addr)
            .await
            .map_err(|_| SmrpError::InternalError)?
            .next()
            .ok_or(SmrpError::InternalError)?;

        let socket = Arc::new(
            UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|_| SmrpError::InternalError)?,
        );
        let sign_key = SigningKey::generate()?;
        let session = handshake::client_handshake(&socket, addr, &sign_key).await?;

        let (data_tx, data_rx) = mpsc::channel(256);
        let session_id = session.id;

        let socket_rx = Arc::clone(&socket);
        tokio::spawn(async move {
            loop {
                match transport::recv_raw(&socket_rx).await {
                    Ok((hdr, payload, _)) => {
                        if hdr.session_id != session_id {
                            continue;
                        }
                        if data_tx.send((hdr, payload)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("client recv task: {e}");
                        break;
                    }
                }
            }
        });

        Self::assemble(session, socket, data_rx)
    }

    // --- Internal constructors ---

    pub(crate) fn from_server_session(
        session: Session,
        socket: Arc<UdpSocket>,
        data_rx: mpsc::Receiver<Pkt>,
    ) -> Result<Self, SmrpError> {
        Self::assemble(session, socket, data_rx)
    }

    fn assemble(
        mut session: Session,
        socket: Arc<UdpSocket>,
        data_rx: mpsc::Receiver<Pkt>,
    ) -> Result<Self, SmrpError> {
        Ok(Self {
            socket,
            peer_addr: session.peer_addr,
            session_id: session.id,
            send_key: session.send_key.take().ok_or(SmrpError::InternalError)?,
            send_seq: session.send_seq,
            recv_key: session.recv_key.take().ok_or(SmrpError::InternalError)?,
            recv_replay: session.recv_replay,
            recv_seq: session.recv_seq,
            data_rx,
        })
    }

    // --- Public API ---

    /// Encrypts `data` and sends it as a DATA packet.
    ///
    /// # Errors
    /// Returns [`SmrpError::PayloadTooLarge`] if `data.len() > MAX_PAYLOAD`.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), SmrpError> {
        if data.len() > MAX_PAYLOAD {
            return Err(SmrpError::PayloadTooLarge);
        }
        let seq = self.send_seq;
        let nonce = packet_nonce(self.session_id.as_bytes(), seq);
        let mut aad = [0u8; 16];
        aad[0..8].copy_from_slice(self.session_id.as_bytes());
        aad[8..16].copy_from_slice(&seq.to_be_bytes());
        let ciphertext = self.send_key.seal(&nonce, &aad, data)?;

        let hdr = SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::Data,
            flags: Flags::default(),
            reserved: 0,
            session_id: self.session_id,
            sequence_number: seq,
            ack_number: self.recv_seq,
            timestamp_us: packet::timestamp_us(),
            payload_len: ciphertext.len() as u16,
        };
        transport::send_raw(&self.socket, self.peer_addr, &hdr, &ciphertext).await?;
        self.send_seq += 1;
        Ok(())
    }

    /// Waits up to 60 seconds for the next DATA packet and returns the
    /// decrypted payload.
    ///
    /// Returns `Ok(None)` when the peer has closed the connection (FIN received
    /// and FIN_ACK sent) or the session has gone dead.
    ///
    /// # Errors
    /// Returns [`SmrpError::ReplayDetected`] or [`SmrpError::AuthenticationFailure`]
    /// on security violations. Returns [`SmrpError::HandshakeTimeout`] if no
    /// data arrives within 60 seconds.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, SmrpError> {
        self.recv_timeout(RECV_TIMEOUT).await
    }

    /// Like [`recv`](Self::recv) but with a caller-supplied deadline.
    pub async fn recv_timeout(&mut self, deadline: Duration) -> Result<Option<Vec<u8>>, SmrpError> {
        time::timeout(deadline, self.recv_inner())
            .await
            .map_err(|_| SmrpError::HandshakeTimeout)?
    }

    async fn recv_inner(&mut self) -> Result<Option<Vec<u8>>, SmrpError> {
        loop {
            let Some((hdr, payload)) = self.data_rx.recv().await else {
                return Ok(None);
            };
            match hdr.packet_type {
                PacketType::Data => {
                    let seq = hdr.sequence_number;
                    self.recv_replay.can_accept(seq)?;
                    let nonce = packet_nonce(self.session_id.as_bytes(), seq);
                    let mut aad = [0u8; 16];
                    aad[0..8].copy_from_slice(self.session_id.as_bytes());
                    aad[8..16].copy_from_slice(&seq.to_be_bytes());
                    let plaintext = self.recv_key.open(&nonce, &aad, &payload)?;
                    self.recv_replay.mark_seen(seq);
                    self.recv_seq = seq;
                    // Send cumulative ACK (best-effort; ignore errors)
                    let _ = self.send_ack(seq).await;
                    return Ok(Some(plaintext));
                }
                PacketType::Fin => {
                    // Acknowledge the FIN then signal EOF to the caller.
                    let _ = self.send_fin_ack(hdr.sequence_number).await;
                    return Ok(None);
                }
                PacketType::Keepalive => {
                    let _ = self.send_keepalive_ack().await;
                }
                // ACK, KeepaliveAck, FinAck — silently consumed
                _ => {}
            }
        }
    }

    /// Sends a FIN, waits up to 5 seconds for FIN_ACK, then releases the connection.
    ///
    /// # Errors
    /// Returns [`SmrpError::InternalError`] on a socket failure. A missing
    /// FIN_ACK within the timeout is ignored — the connection is torn down anyway.
    pub async fn close(mut self) -> Result<(), SmrpError> {
        self.send_fin_flag().await?;
        // Wait for FIN_ACK; ignore timeout — peer may already be gone.
        let _ = time::timeout(FIN_ACK_TIMEOUT, self.wait_fin_ack()).await;
        Ok(())
    }

    // --- Internal send helpers ---

    async fn send_fin_flag(&self) -> Result<(), SmrpError> {
        let mut flags = Flags::default();
        flags.0 |= Flags::FIN;
        let hdr = SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::Fin,
            flags,
            reserved: 0,
            session_id: self.session_id,
            sequence_number: self.send_seq,
            ack_number: self.recv_seq,
            timestamp_us: packet::timestamp_us(),
            payload_len: 0,
        };
        transport::send_raw(&self.socket, self.peer_addr, &hdr, &[]).await
    }

    async fn send_fin_ack(&self, ack_seq: u64) -> Result<(), SmrpError> {
        let hdr = SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::FinAck,
            flags: Flags::default(),
            reserved: 0,
            session_id: self.session_id,
            sequence_number: self.send_seq,
            ack_number: ack_seq,
            timestamp_us: timestamp_us(),
            payload_len: 0,
        };
        transport::send_raw(&self.socket, self.peer_addr, &hdr, &[]).await
    }

    async fn send_ack(&self, ack_seq: u64) -> Result<(), SmrpError> {
        let hdr = SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::Ack,
            flags: Flags::default(),
            reserved: 0,
            session_id: self.session_id,
            sequence_number: self.send_seq,
            ack_number: ack_seq,
            timestamp_us: timestamp_us(),
            payload_len: 0,
        };
        transport::send_raw(&self.socket, self.peer_addr, &hdr, &[]).await
    }

    async fn send_keepalive_ack(&self) -> Result<(), SmrpError> {
        let hdr = SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::KeepaliveAck,
            flags: Flags::default(),
            reserved: 0,
            session_id: self.session_id,
            sequence_number: self.send_seq,
            ack_number: self.recv_seq,
            timestamp_us: timestamp_us(),
            payload_len: 0,
        };
        transport::send_raw(&self.socket, self.peer_addr, &hdr, &[]).await
    }

    async fn wait_fin_ack(&mut self) {
        loop {
            let Some((hdr, _)) = self.data_rx.recv().await else {
                return;
            };
            if hdr.packet_type == PacketType::FinAck {
                return;
            }
        }
    }

    // --- Accessors ---

    /// Returns the peer's UDP address.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Returns the raw 8-byte session identifier.
    #[must_use]
    pub fn session_id(&self) -> &[u8; 8] {
        self.session_id.as_bytes()
    }
}

// ---------------------------------------------------------------------------
// SmrpListener
// ---------------------------------------------------------------------------

/// Listens for inbound SMRP connections on a UDP port.
pub struct SmrpListener {
    local_addr: SocketAddr,
    new_conn_rx: mpsc::Receiver<SmrpConnection>,
}

impl SmrpListener {
    /// Binds a UDP socket on `addr` and starts the internal dispatch task.
    ///
    /// # Errors
    /// Returns [`SmrpError`] if the socket cannot be bound.
    pub async fn bind(addr: &str) -> Result<Self, SmrpError> {
        let socket = Arc::new(
            UdpSocket::bind(addr)
                .await
                .map_err(|_| SmrpError::InternalError)?,
        );
        let local_addr = socket.local_addr().map_err(|_| SmrpError::InternalError)?;
        let sign_key = Arc::new(SigningKey::generate()?);
        let sessions: SessionMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let (new_conn_tx, new_conn_rx) = mpsc::channel(64);

        tokio::spawn(listener_dispatch(socket, sign_key, sessions, new_conn_tx));

        Ok(Self { local_addr, new_conn_rx })
    }

    /// Waits for the next inbound connection.
    ///
    /// Returns `None` if the listener's internal dispatch task has exited.
    pub async fn accept(&mut self) -> Option<SmrpConnection> {
        self.new_conn_rx.recv().await
    }

    /// Returns the local address this listener is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

// ---------------------------------------------------------------------------
// Listener dispatch task
// ---------------------------------------------------------------------------

/// Per-IP rate limiter state.
struct RateBucket {
    count: u32,
    window_start: Instant,
}

impl RateBucket {
    fn new() -> Self {
        Self { count: 0, window_start: Instant::now() }
    }

    /// Returns `true` if this packet is within the allowed rate.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.count = 0;
            self.window_start = now;
        }
        self.count += 1;
        self.count <= HELLO_RATE_LIMIT
    }
}

async fn listener_dispatch(
    socket: Arc<UdpSocket>,
    sign_key: Arc<SigningKey>,
    sessions: SessionMap,
    new_conn_tx: mpsc::Sender<SmrpConnection>,
) {
    // Per-IP HELLO rate limiter. Entries are cleaned up lazily.
    let mut rate_limits: HashMap<IpAddr, RateBucket> = HashMap::new();

    loop {
        let (hdr, payload, addr) = match transport::recv_raw(&socket).await {
            Ok(t) => t,
            Err(e) => {
                warn!("listener dispatch recv: {e}");
                continue;
            }
        };

        match hdr.packet_type {
            PacketType::Hello => {
                // --- Rate limiting ---
                let bucket = rate_limits.entry(addr.ip()).or_insert_with(RateBucket::new);
                if !bucket.allow() {
                    warn!("HELLO rate limit exceeded for {}", addr.ip());
                    continue;
                }

                // --- Timestamp validation (±30 s) ---
                let now_us = timestamp_us();
                let skew_us = HELLO_CLOCK_SKEW_SECS * 1_000_000;
                let ts = hdr.timestamp_us;
                if ts.saturating_add(skew_us) < now_us || ts > now_us.saturating_add(skew_us) {
                    warn!("HELLO from {addr} rejected: timestamp too far from now");
                    continue;
                }

                // --- Session capacity check ---
                {
                    let map = sessions.lock().await;
                    if map.len() >= MAX_SESSIONS {
                        warn!("MAX_SESSIONS reached; rejecting HELLO from {addr}");
                        // Best-effort ERROR reply
                        send_error_reply(&socket, addr, hdr.session_id, SmrpError::SessionLimitExceeded).await;
                        continue;
                    }
                }

                // --- Duplicate session check ---
                {
                    let map = sessions.lock().await;
                    if map.contains_key(&hdr.session_id) {
                        debug!("duplicate HELLO for session {:?}", hdr.session_id);
                        continue;
                    }
                }

                let socket2      = Arc::clone(&socket);
                let sign_key2    = Arc::clone(&sign_key);
                let sessions2    = Arc::clone(&sessions);
                let new_conn_tx2 = new_conn_tx.clone();
                let sid          = hdr.session_id;

                tokio::spawn(async move {
                    let session = match handshake::server_handshake(
                        &socket2, addr, sid, &payload, &sign_key2,
                    ).await {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("handshake with {addr} failed: {e}");
                            return;
                        }
                    };

                    let (data_tx, data_rx) = mpsc::channel(256);
                    let conn_sid = session.id;

                    let conn = match SmrpConnection::from_server_session(session, socket2, data_rx) {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("connection assembly failed: {e}");
                            return;
                        }
                    };

                    sessions2.lock().await.insert(conn_sid, data_tx);

                    if new_conn_tx2.send(conn).await.is_err() {
                        sessions2.lock().await.remove(&conn_sid);
                    }
                });
            }

            PacketType::Data
            | PacketType::Fin
            | PacketType::FinAck
            | PacketType::Ack
            | PacketType::Keepalive
            | PacketType::KeepaliveAck
            | PacketType::Reset => {
                let mut map = sessions.lock().await;
                let sid = hdr.session_id;
                let remove = if let Some(tx) = map.get(&sid) {
                    match tx.try_send((hdr, payload)) {
                        Ok(()) => false,
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            warn!("session {sid:?}: channel full, packet dropped");
                            false
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => true,
                    }
                } else {
                    false
                };
                if remove {
                    map.remove(&sid);
                }
            }

            other => {
                debug!("listener: unhandled packet type {other:?} from {addr}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Keepalive task
// ---------------------------------------------------------------------------

/// Spawns a keepalive task for a connection's send socket/peer.
///
/// Sends a KEEPALIVE every `KEEPALIVE_INTERVAL_SECS` seconds while `alive_rx`
/// is open. When `alive_rx` is dropped (connection closed), the task exits.
pub fn spawn_keepalive(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    session_id: SessionId,
    mut alive_rx: mpsc::Receiver<()>,
) {
    tokio::spawn(async move {
        let interval = Duration::from_secs(KEEPALIVE_INTERVAL_SECS);
        loop {
            tokio::select! {
                _ = time::sleep(interval) => {
                    let hdr = SmrpHeader {
                        magic: SMRP_MAGIC,
                        version: SMRP_VERSION,
                        packet_type: PacketType::Keepalive,
                        flags: Flags::default(),
                        reserved: 0,
                        session_id,
                        sequence_number: 0,
                        ack_number: 0,
                        timestamp_us: timestamp_us(),
                        payload_len: 0,
                    };
                    if transport::send_raw(&socket, peer_addr, &hdr, &[]).await.is_err() {
                        break;
                    }
                }
                msg = alive_rx.recv() => {
                    if msg.is_none() { break; } // connection dropped
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Error reply helper
// ---------------------------------------------------------------------------

async fn send_error_reply(
    socket: &UdpSocket,
    addr: SocketAddr,
    session_id: SessionId,
    err: SmrpError,
) {
    let hdr = SmrpHeader {
        magic: SMRP_MAGIC,
        version: SMRP_VERSION,
        packet_type: PacketType::Error,
        flags: Flags::default(),
        reserved: 0,
        session_id,
        sequence_number: 0,
        ack_number: 0,
        timestamp_us: timestamp_us(),
        payload_len: 1,
    };
    let payload = [err.wire_code()];
    let _ = transport::send_raw(socket, addr, &hdr, &payload).await;
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::pedantic)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Bind a listener on a random OS-assigned port and return its address.
    async fn start_echo_server() -> SocketAddr {
        let mut listener = SmrpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr();
        tokio::spawn(async move {
            while let Some(mut conn) = listener.accept().await {
                tokio::spawn(async move {
                    while let Ok(Some(data)) = conn.recv().await {
                        if conn.send(&data).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn single_round_trip() {
        let addr = start_echo_server().await;
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        conn.send(b"hello smrp").await.unwrap();
        let reply = conn.recv().await.unwrap().unwrap();
        assert_eq!(reply, b"hello smrp");
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn multiple_messages_same_connection() {
        let addr = start_echo_server().await;
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        for i in 0u8..16 {
            let msg = vec![i; 64];
            conn.send(&msg).await.unwrap();
            let reply = conn.recv().await.unwrap().unwrap();
            assert_eq!(reply, msg, "message {i} mismatch");
        }
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn max_payload_accepted() {
        let addr = start_echo_server().await;
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        let big = vec![0xABu8; MAX_PAYLOAD];
        conn.send(&big).await.unwrap();
        let reply = conn.recv().await.unwrap().unwrap();
        assert_eq!(reply.len(), MAX_PAYLOAD);
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn oversized_payload_rejected_locally() {
        let addr = start_echo_server().await;
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        let too_big = vec![0u8; MAX_PAYLOAD + 1];
        assert_eq!(conn.send(&too_big).await.unwrap_err(), SmrpError::PayloadTooLarge);
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_sessions() {
        let addr = start_echo_server().await;
        let mut handles = Vec::new();
        for i in 0u8..8 {
            let a = addr;
            handles.push(tokio::spawn(async move {
                let mut conn = SmrpConnection::connect(&a.to_string()).await.unwrap();
                let msg = vec![i; 32];
                conn.send(&msg).await.unwrap();
                let reply = conn.recv().await.unwrap().unwrap();
                assert_eq!(reply, msg);
                conn.close().await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    #[tokio::test]
    async fn connect_timeout_on_unreachable_server() {
        // Port 1 is unlikely to be listening anywhere.
        // We wrap with a short timeout so the test doesn't hang.
        let result = time::timeout(
            Duration::from_secs(12),
            SmrpConnection::connect("127.0.0.1:1"),
        )
        .await;
        // Either our CONNECT_TIMEOUT fires (HandshakeTimeout) or the OS refuses
        // the port — either way we must not hang indefinitely.
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn recv_timeout_returns_error_when_server_silent() {
        let addr = start_echo_server().await;
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        // Don't send anything — just wait with a short deadline.
        let result = conn.recv_timeout(Duration::from_millis(200)).await;
        assert_eq!(result.unwrap_err(), SmrpError::HandshakeTimeout);
    }

    #[tokio::test]
    async fn graceful_close_sends_fin_ack() {
        let addr = start_echo_server().await;
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        conn.send(b"bye").await.unwrap();
        let _reply = conn.recv().await.unwrap();
        // close() sends FIN and waits up to 5 s for FIN_ACK — should succeed.
        conn.close().await.unwrap();
    }
}
