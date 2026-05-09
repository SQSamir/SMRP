//! High-level SMRP connection API.
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
//!             conn.send(&data).await.ok();
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
    constants::{KEEPALIVE_INTERVAL_SECS, MAX_PAYLOAD, MAX_SESSIONS, SMRP_MAGIC, SMRP_VERSION},
    crypto::{packet_nonce, SigningKey},
    error::SmrpError,
    handshake,
    packet::{timestamp_us, Flags, PacketType, SmrpHeader},
    replay::ReplayWindow,
    session::{Session, SessionId},
    transport,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
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

/// How long `connect()` waits for HELLO_ACK.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default deadline for `recv()`.
const RECV_TIMEOUT: Duration = Duration::from_secs(60);

/// 3 × keepalive — no packet for this long means the session is dead.
pub const SESSION_DEAD_SECS: u64 = KEEPALIVE_INTERVAL_SECS * 3;

/// Max HELLO packets accepted from one source IP per second.
const HELLO_RATE_LIMIT: u32 = 10;

/// Allowed clock skew for HELLO timestamp validation.
const HELLO_CLOCK_SKEW_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// SmrpConnection
// ---------------------------------------------------------------------------

/// An established, encrypted SMRP session.
pub struct SmrpConnection {
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    session_id: SessionId,

    send_key: crate::crypto::SessionKey,
    send_seq: u64,

    recv_key: crate::crypto::SessionKey,
    recv_replay: ReplayWindow,
    recv_seq: u64,

    /// Encrypted packets forwarded here by the recv task / listener dispatch.
    data_rx: mpsc::Receiver<Pkt>,

    /// Dropping this sender stops the keepalive task cleanly.
    _keepalive_stop: mpsc::Sender<()>,

    /// Updated on every received packet; read by the keepalive task.
    last_recv_us: Arc<AtomicU64>,

    /// Receives a single `()` when the keepalive task declares the session dead.
    dead_rx: mpsc::Receiver<()>,
}

impl SmrpConnection {
    /// Opens an SMRP connection to `server_addr`.
    ///
    /// Fails with [`SmrpError::HandshakeTimeout`] if the server does not
    /// respond within 10 seconds.
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

        // Client connections have no listener session map, so dead_session_tx is None.
        Self::assemble(session, socket, data_rx, None)
    }

    // --- Internal constructors ---

    /// Called by the listener for each completed server-side handshake.
    /// `dead_session_tx` lets the keepalive task notify the listener to evict
    /// this session from the routing map when it goes dead.
    pub(crate) fn from_server_session(
        session: Session,
        socket: Arc<UdpSocket>,
        data_rx: mpsc::Receiver<Pkt>,
        dead_session_tx: mpsc::Sender<SessionId>,
    ) -> Result<Self, SmrpError> {
        Self::assemble(session, socket, data_rx, Some(dead_session_tx))
    }

    fn assemble(
        mut session: Session,
        socket: Arc<UdpSocket>,
        data_rx: mpsc::Receiver<Pkt>,
        dead_session_tx: Option<mpsc::Sender<SessionId>>,
    ) -> Result<Self, SmrpError> {
        let (keepalive_stop_tx, keepalive_stop_rx) = mpsc::channel::<()>(1);
        let (dead_notify_tx, dead_rx) = mpsc::channel::<()>(1);

        // Seed last_recv_us with "now" so the 45-second dead-timer starts
        // from when the session was established, not from the Unix epoch.
        let last_recv_us = Arc::new(AtomicU64::new(timestamp_us()));

        spawn_keepalive_task(
            Arc::clone(&socket),
            session.peer_addr,
            session.id,
            keepalive_stop_rx,
            Arc::clone(&last_recv_us),
            dead_notify_tx,
            dead_session_tx,
        );

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
            _keepalive_stop: keepalive_stop_tx,
            last_recv_us,
            dead_rx,
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
            timestamp_us: timestamp_us(),
            payload_len: ciphertext.len() as u16,
        };
        transport::send_raw(&self.socket, self.peer_addr, &hdr, &ciphertext).await?;
        self.send_seq += 1;
        Ok(())
    }

    /// Waits up to 60 seconds for the next DATA packet.
    ///
    /// Returns `Ok(None)` on FIN, graceful shutdown, or dead-session eviction.
    /// Returns `Err(HandshakeTimeout)` if no data arrives within the deadline.
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
            tokio::select! {
                pkt = self.data_rx.recv() => {
                    let Some((hdr, payload)) = pkt else {
                        return Ok(None); // channel closed (listener shutdown or task exit)
                    };
                    // Refresh the activity timestamp on every received packet.
                    self.last_recv_us.store(timestamp_us(), Ordering::Relaxed);

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
                            // Best-effort cumulative ACK
                            let _ = self.send_ack(seq).await;
                            return Ok(Some(plaintext));
                        }
                        PacketType::Fin => {
                            let _ = self.send_fin_ack(hdr.sequence_number).await;
                            return Ok(None);
                        }
                        PacketType::Keepalive => {
                            let _ = self.send_keepalive_ack().await;
                        }
                        // ACK, KeepaliveAck, FinAck — consumed silently
                        _ => {}
                    }
                }

                // Keepalive task has declared this session dead (no traffic for 45 s).
                _ = self.dead_rx.recv() => {
                    warn!("session {:?}: dead-session timeout; closing", self.session_id);
                    return Ok(None);
                }
            }
        }
    }

    /// Sends FIN, waits up to 5 s for FIN_ACK, then releases the connection.
    pub async fn close(mut self) -> Result<(), SmrpError> {
        self.send_fin_flag().await?;
        let _ = time::timeout(FIN_ACK_TIMEOUT, self.wait_fin_ack()).await;
        Ok(())
        // Dropping self drops _keepalive_stop, stopping the keepalive task.
    }

    // --- Private send helpers ---

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
            timestamp_us: timestamp_us(),
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
// Keepalive task (internal)
// ---------------------------------------------------------------------------

/// Spawns the per-connection keepalive task.
///
/// - Every `KEEPALIVE_INTERVAL_SECS` seconds: sends a KEEPALIVE probe.
/// - If no packet has been received for `SESSION_DEAD_SECS`:
///   - signals `dead_notify_tx` so `recv()` returns `Ok(None)`.
///   - sends the session ID on `dead_session_tx` (if Some) so the listener
///     removes it from the routing map.
/// - Exits cleanly when `stop_rx` is closed (i.e. connection was closed by
///   the application before the dead-session threshold was reached).
fn spawn_keepalive_task(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    session_id: SessionId,
    mut stop_rx: mpsc::Receiver<()>,
    last_recv_us: Arc<AtomicU64>,
    dead_notify_tx: mpsc::Sender<()>,
    dead_session_tx: Option<mpsc::Sender<SessionId>>,
) {
    tokio::spawn(async move {
        let probe_interval = Duration::from_secs(KEEPALIVE_INTERVAL_SECS);
        let dead_threshold_us = SESSION_DEAD_SECS * 1_000_000;

        loop {
            tokio::select! {
                _ = time::sleep(probe_interval) => {
                    let now_us  = timestamp_us();
                    let last_us = last_recv_us.load(Ordering::Relaxed);

                    // Dead-session check: no packet received for SESSION_DEAD_SECS.
                    if now_us.saturating_sub(last_us) >= dead_threshold_us {
                        warn!("session {session_id:?}: no traffic for {SESSION_DEAD_SECS}s — evicting");
                        // Signal recv() to return None.
                        let _ = dead_notify_tx.try_send(());
                        // Signal listener to remove from routing map.
                        if let Some(tx) = dead_session_tx {
                            let _ = tx.send(session_id).await;
                        }
                        break;
                    }

                    // Send a keepalive probe.
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
                        break; // socket gone
                    }
                    debug!("session {session_id:?}: KEEPALIVE sent");
                }

                // Connection was closed normally — stop cleanly.
                _ = stop_rx.recv() => {
                    debug!("session {session_id:?}: keepalive task stopping (connection closed)");
                    break;
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// SmrpListener
// ---------------------------------------------------------------------------

/// Listens for inbound SMRP connections on a UDP port.
pub struct SmrpListener {
    local_addr: SocketAddr,
    new_conn_rx: mpsc::Receiver<SmrpConnection>,
    /// One send drops the dispatch loop, stopping new connection acceptance.
    shutdown_tx: mpsc::Sender<()>,
    /// Shared with the dispatch task; used by `shutdown()` to inject FINs.
    sessions: SessionMap,
}

impl SmrpListener {
    /// Binds a UDP socket on `addr` and starts the internal dispatch task.
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
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        // Channel for keepalive tasks to report dead sessions to the dispatch loop.
        let (dead_session_tx, dead_session_rx) = mpsc::channel::<SessionId>(256);

        tokio::spawn(listener_dispatch(
            socket,
            sign_key,
            Arc::clone(&sessions),
            new_conn_tx,
            shutdown_rx,
            dead_session_tx,
            dead_session_rx,
        ));

        Ok(Self {
            local_addr,
            new_conn_rx,
            shutdown_tx,
            sessions,
        })
    }

    /// Waits for the next inbound connection.
    ///
    /// Returns `None` if the listener has been shut down.
    pub async fn accept(&mut self) -> Option<SmrpConnection> {
        self.new_conn_rx.recv().await
    }

    /// Returns the local address this listener is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Gracefully shuts down the listener.
    ///
    /// - Stops the dispatch loop (no new connections will be accepted).
    /// - Injects a synthetic FIN into every active session's receive channel,
    ///   causing each `SmrpConnection::recv()` to return `Ok(None)`.
    /// - Dropping the returned value causes `accept()` to return `None`.
    pub async fn shutdown(self) {
        // Drop shutdown_tx — the dispatch loop's select! on shutdown_rx will
        // immediately see the channel close and break out of its loop.
        drop(self.shutdown_tx);

        // Inject a synthetic FIN into every active session so in-flight
        // recv() calls drain and return Ok(None) promptly.
        let map = self.sessions.lock().await;
        for (sid, tx) in map.iter() {
            let _ = tx.try_send((shutdown_fin(*sid), vec![]));
        }
        // Dropping self drops new_conn_rx, causing accept() to return None.
    }
}

/// Builds a synthetic FIN header used for graceful listener shutdown.
fn shutdown_fin(session_id: SessionId) -> SmrpHeader {
    let mut flags = Flags::default();
    flags.0 |= Flags::FIN;
    SmrpHeader {
        magic: SMRP_MAGIC,
        version: SMRP_VERSION,
        packet_type: PacketType::Fin,
        flags,
        reserved: 0,
        session_id,
        sequence_number: 0,
        ack_number: 0,
        timestamp_us: timestamp_us(),
        payload_len: 0,
    }
}

// ---------------------------------------------------------------------------
// Listener dispatch task
// ---------------------------------------------------------------------------

struct RateBucket {
    count: u32,
    window_start: Instant,
}

impl RateBucket {
    fn new() -> Self {
        Self { count: 0, window_start: Instant::now() }
    }

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
    mut shutdown_rx: mpsc::Receiver<()>,
    dead_session_tx: mpsc::Sender<SessionId>,
    mut dead_session_rx: mpsc::Receiver<SessionId>,
) {
    let mut rate_limits: HashMap<IpAddr, RateBucket> = HashMap::new();

    loop {
        tokio::select! {
            // --- Incoming UDP datagram ---
            result = transport::recv_raw(&socket) => {
                let (hdr, payload, addr) = match result {
                    Ok(t) => t,
                    Err(e) => { warn!("listener dispatch recv: {e}"); continue; }
                };

                match hdr.packet_type {
                    PacketType::Hello => {
                        // Rate limit
                        let bucket = rate_limits.entry(addr.ip()).or_insert_with(RateBucket::new);
                        if !bucket.allow() {
                            warn!("HELLO rate limit exceeded for {}", addr.ip());
                            continue;
                        }

                        // Timestamp validation ±30 s
                        let now_us  = timestamp_us();
                        let skew_us = HELLO_CLOCK_SKEW_SECS * 1_000_000;
                        let ts = hdr.timestamp_us;
                        if ts.saturating_add(skew_us) < now_us
                            || ts > now_us.saturating_add(skew_us)
                        {
                            warn!("HELLO from {addr} rejected: timestamp out of range");
                            continue;
                        }

                        // Session capacity
                        {
                            let map = sessions.lock().await;
                            if map.len() >= MAX_SESSIONS {
                                warn!("MAX_SESSIONS reached; rejecting HELLO from {addr}");
                                send_error_reply(
                                    &socket, addr, hdr.session_id,
                                    SmrpError::SessionLimitExceeded,
                                ).await;
                                continue;
                            }
                            if map.contains_key(&hdr.session_id) {
                                debug!("duplicate HELLO for session {:?}", hdr.session_id);
                                continue;
                            }
                        }

                        // Spawn handshake sub-task
                        let socket2       = Arc::clone(&socket);
                        let sign_key2     = Arc::clone(&sign_key);
                        let sessions2     = Arc::clone(&sessions);
                        let new_conn_tx2  = new_conn_tx.clone();
                        let dead_sess_tx2 = dead_session_tx.clone();
                        let sid           = hdr.session_id;

                        tokio::spawn(async move {
                            let session = match handshake::server_handshake(
                                &socket2, addr, sid, &payload, &sign_key2,
                            ).await {
                                Ok(s) => s,
                                Err(e) => { warn!("handshake with {addr} failed: {e}"); return; }
                            };

                            let (data_tx, data_rx) = mpsc::channel(256);
                            let conn_sid = session.id;

                            let conn = match SmrpConnection::from_server_session(
                                session, socket2, data_rx, dead_sess_tx2,
                            ) {
                                Ok(c) => c,
                                Err(e) => { warn!("connection assembly failed: {e}"); return; }
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
                        if remove { map.remove(&sid); }
                    }

                    other => {
                        debug!("listener: unhandled packet type {other:?} from {addr}");
                    }
                }
            }

            // --- Shutdown signal ---
            _ = shutdown_rx.recv() => {
                debug!("listener dispatch: shutdown signal received");
                break;
            }

            // --- Dead session eviction from keepalive tasks ---
            Some(dead_sid) = dead_session_rx.recv() => {
                sessions.lock().await.remove(&dead_sid);
                debug!("listener dispatch: evicted dead session {dead_sid:?}");
            }
        }
    }
    // Exiting the loop drops new_conn_tx, so accept() returns None.
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
    let _ = transport::send_raw(socket, addr, &hdr, &[err.wire_code()]).await;
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::pedantic)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn start_echo_server() -> (SocketAddr, SmrpListener) {
        let listener = SmrpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr();
        (addr, listener)
    }

    async fn run_echo(mut listener: SmrpListener) {
        tokio::spawn(async move {
            while let Some(mut conn) = listener.accept().await {
                tokio::spawn(async move {
                    while let Ok(Some(data)) = conn.recv().await {
                        if conn.send(&data).await.is_err() { break; }
                    }
                });
            }
        });
    }

    // --- Basic round-trip ---

    #[tokio::test]
    async fn single_round_trip() {
        let (addr, listener) = start_echo_server().await;
        run_echo(listener).await;

        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        conn.send(b"hello smrp").await.unwrap();
        let reply = conn.recv().await.unwrap().unwrap();
        assert_eq!(reply, b"hello smrp");
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn multiple_messages_same_connection() {
        let (addr, listener) = start_echo_server().await;
        run_echo(listener).await;

        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        for i in 0u8..16 {
            let msg = vec![i; 64];
            conn.send(&msg).await.unwrap();
            let reply = conn.recv().await.unwrap().unwrap();
            assert_eq!(reply, msg);
        }
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn max_payload_accepted() {
        let (addr, listener) = start_echo_server().await;
        run_echo(listener).await;

        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        let big = vec![0xABu8; MAX_PAYLOAD];
        conn.send(&big).await.unwrap();
        let reply = conn.recv().await.unwrap().unwrap();
        assert_eq!(reply.len(), MAX_PAYLOAD);
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn oversized_payload_rejected_locally() {
        let (addr, listener) = start_echo_server().await;
        run_echo(listener).await;

        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        let too_big = vec![0u8; MAX_PAYLOAD + 1];
        assert_eq!(conn.send(&too_big).await.unwrap_err(), SmrpError::PayloadTooLarge);
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_sessions() {
        let (addr, listener) = start_echo_server().await;
        run_echo(listener).await;

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
        for h in handles { h.await.unwrap(); }
    }

    // --- Timeout ---

    #[tokio::test]
    async fn connect_timeout_fires() {
        // Port 1 is almost certainly not listening.
        let result = time::timeout(
            Duration::from_secs(12),
            SmrpConnection::connect("127.0.0.1:1"),
        ).await;
        assert!(result.is_ok()); // outer timeout didn't fire — inner one did
        assert!(result.unwrap().is_err());
    }

    #[tokio::test]
    async fn recv_timeout_returns_error_when_server_silent() {
        let (addr, listener) = start_echo_server().await;
        run_echo(listener).await;

        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        let result = conn.recv_timeout(Duration::from_millis(200)).await;
        assert_eq!(result.unwrap_err(), SmrpError::HandshakeTimeout);
    }

    // --- FIN / FIN_ACK ---

    #[tokio::test]
    async fn graceful_close_completes() {
        let (addr, listener) = start_echo_server().await;
        run_echo(listener).await;

        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        conn.send(b"bye").await.unwrap();
        let _ = conn.recv().await.unwrap();
        conn.close().await.unwrap();
    }

    // --- Graceful listener shutdown ---

    #[tokio::test]
    async fn listener_shutdown_causes_accept_to_return_none() {
        let (addr, listener) = start_echo_server().await;

        // Connect a client before shutdown.
        let mut client = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        client.send(b"ping").await.unwrap();

        // Shut down the listener — this consumes it.
        // We drive accept() via a separate channel returned above; the internal
        // dispatch task is what we're testing here.
        listener.shutdown().await;

        // The client's next recv() should see Ok(None) because the listener
        // injected a FIN into the session channel.
        let result = time::timeout(Duration::from_secs(2), client.recv()).await;
        assert!(result.is_ok(), "recv after shutdown timed out");
        assert!(result.unwrap().unwrap().is_none(), "expected Ok(None) after shutdown");
    }

    #[tokio::test]
    async fn no_new_connections_after_shutdown() {
        let (addr, listener) = start_echo_server().await;
        listener.shutdown().await;

        // Attempting to connect after shutdown should time out — no one
        // is processing HELLOs.
        let result = time::timeout(
            Duration::from_millis(500),
            SmrpConnection::connect(&addr.to_string()),
        ).await;
        assert!(result.is_err(), "expected timeout after listener shutdown");
    }
}
