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
    constants::{SMRP_MAGIC, SMRP_VERSION},
    crypto::{packet_nonce, SigningKey},
    error::SmrpError,
    handshake,
    packet::{self, Flags, PacketType, SmrpHeader},
    replay::ReplayWindow,
    session::{Session, SessionId},
    transport,
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::mpsc};
use tracing::{debug, warn};

// Encrypted-packet message type flowing through per-session channels.
type Pkt = (SmrpHeader, Vec<u8>);
type SessionMap = Arc<tokio::sync::Mutex<HashMap<SessionId, mpsc::Sender<Pkt>>>>;

// ---------------------------------------------------------------------------
// SmrpConnection
// ---------------------------------------------------------------------------

/// An established, encrypted SMRP session.
///
/// Obtained via [`SmrpConnection::connect`] (client) or
/// [`SmrpListener::accept`] (server).
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
    /// Binds an ephemeral local UDP port, performs the full SMRP handshake,
    /// and returns a ready-to-use connection.
    ///
    /// # Errors
    /// Returns [`SmrpError`] on any network or cryptographic failure.
    pub async fn connect(server_addr: &str) -> Result<Self, SmrpError> {
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

        // Spawn a task that reads from the socket and forwards packets for
        // this session into the channel.  The task exits when the channel
        // receiver is dropped (i.e. the SmrpConnection is closed).
        let socket_rx = Arc::clone(&socket);
        tokio::spawn(async move {
            loop {
                match transport::recv_raw(&socket_rx).await {
                    Ok((hdr, payload, _)) => {
                        if hdr.session_id != session_id {
                            continue; // stray packet for a different session
                        }
                        if data_tx.send((hdr, payload)).await.is_err() {
                            break; // connection was closed
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

    /// Builds a `SmrpConnection` from a completed server-side session.
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

    /// Encrypts `data` and sends it as a `DATA` packet.
    ///
    /// # Errors
    /// Returns [`SmrpError::PayloadTooLarge`] if `data` exceeds `MAX_PAYLOAD`,
    /// or [`SmrpError::InternalError`] on a socket failure.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), SmrpError> {
        if data.len() > crate::constants::MAX_PAYLOAD {
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

    /// Waits for the next `DATA` packet and returns the decrypted payload.
    ///
    /// Returns `Ok(None)` when the peer has closed the connection (`FIN`).
    ///
    /// # Errors
    /// Returns [`SmrpError::ReplayDetected`] on a replayed sequence number, or
    /// [`SmrpError::AuthenticationFailure`] on an AEAD tag mismatch.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, SmrpError> {
        loop {
            let Some((hdr, payload)) = self.data_rx.recv().await else {
                return Ok(None); // dispatch task exited or peer closed
            };
            match hdr.packet_type {
                PacketType::Data => {
                    let seq = hdr.sequence_number;
                    // Phase 1: replay check (does not modify window)
                    self.recv_replay.can_accept(seq)?;
                    // Phase 2: AEAD open
                    let nonce = packet_nonce(self.session_id.as_bytes(), seq);
                    let mut aad = [0u8; 16];
                    aad[0..8].copy_from_slice(self.session_id.as_bytes());
                    aad[8..16].copy_from_slice(&seq.to_be_bytes());
                    let plaintext = self.recv_key.open(&nonce, &aad, &payload)?;
                    // Phase 3: commit
                    self.recv_replay.mark_seen(seq);
                    self.recv_seq = seq;
                    return Ok(Some(plaintext));
                }
                PacketType::Fin => return Ok(None),
                // ACK, Keepalive, etc. — silently consumed
                _ => continue,
            }
        }
    }

    /// Sends a `FIN` and shuts down the connection.
    ///
    /// # Errors
    /// Returns [`SmrpError::InternalError`] on a socket failure.
    pub async fn close(self) -> Result<(), SmrpError> {
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
///
/// Internally runs a dispatch task that multiplexes packets from the single
/// UDP socket to per-connection channels, so multiple concurrent sessions
/// are supported without polling.
pub struct SmrpListener {
    local_addr: SocketAddr,
    new_conn_rx: mpsc::Receiver<SmrpConnection>,
}

impl SmrpListener {
    /// Binds a UDP socket on `addr` (e.g. `"0.0.0.0:9000"`) and starts
    /// the internal dispatch task.
    ///
    /// # Errors
    /// Returns [`SmrpError`] if the socket cannot be bound or the signing
    /// key cannot be generated.
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

        Ok(Self {
            local_addr,
            new_conn_rx,
        })
    }

    /// Waits for the next inbound connection and returns it.
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

/// Runs in a spawned task for the lifetime of a [`SmrpListener`].
///
/// Reads every datagram from the shared UDP socket and either:
/// - completes a handshake for `HELLO` packets (in a further sub-task), or
/// - routes `DATA` / `FIN` / etc. to the correct session channel.
async fn listener_dispatch(
    socket: Arc<UdpSocket>,
    sign_key: Arc<SigningKey>,
    sessions: SessionMap,
    new_conn_tx: mpsc::Sender<SmrpConnection>,
) {
    loop {
        let (hdr, payload, addr) = match transport::recv_raw(&socket).await {
            Ok(t) => t,
            Err(e) => {
                warn!("listener dispatch recv: {e}");
                continue;
            }
        };

        match hdr.packet_type {
            // New session request — complete handshake in a sub-task so the
            // dispatch loop is never blocked by crypto or I/O.
            PacketType::Hello => {
                let socket2 = Arc::clone(&socket);
                let sign_key2 = Arc::clone(&sign_key);
                let sessions2 = Arc::clone(&sessions);
                let new_conn_tx2 = new_conn_tx.clone();
                let sid = hdr.session_id;

                tokio::spawn(async move {
                    let session = match handshake::server_handshake(
                        &socket2,
                        addr,
                        sid,
                        &payload,
                        &sign_key2,
                    )
                    .await
                    {
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
                        // Listener was dropped — remove from map
                        sessions2.lock().await.remove(&conn_sid);
                    }
                });
            }

            // Route encrypted packet to the owning connection's channel.
            PacketType::Data | PacketType::Fin | PacketType::Ack | PacketType::Keepalive => {
                let mut map = sessions.lock().await;
                let sid = hdr.session_id;
                let remove = if let Some(tx) = map.get(&sid) {
                    match tx.try_send((hdr, payload)) {
                        Ok(()) => false,
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            warn!("session {sid:?}: channel full, packet dropped");
                            false
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => true, // conn dropped
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
