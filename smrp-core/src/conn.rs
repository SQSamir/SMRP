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
    config::SmrpConfig,
    crypto::{packet_nonce, SigningKey},
    error::SmrpError,
    handshake,
    metrics::SmrpMetrics,
    packet::{timestamp_us, Flags, PacketType, SmrpHeader},
    replay::ReplayWindow,
    session::{Session, SessionId},
    transport,
    constants::{SMRP_MAGIC, SMRP_VERSION, MAX_PAYLOAD},
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
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

/// Per-session routing entry stored in the listener's session map.
struct SessionEntry {
    /// Channel into the server-side SmrpConnection's receive loop.
    data_tx:   mpsc::Sender<Pkt>,
    /// UDP address of the remote peer (needed to send FINs during shutdown).
    peer_addr: SocketAddr,
}

type SessionMap = Arc<tokio::sync::Mutex<HashMap<SessionId, SessionEntry>>>;

// ---------------------------------------------------------------------------
// SmrpConnection
// ---------------------------------------------------------------------------

/// An established, encrypted SMRP session.
///
/// Obtained via [`SmrpConnection::connect`] (client) or
/// [`SmrpListener::accept`] (server).
pub struct SmrpConnection {
    socket:    Arc<UdpSocket>,
    peer_addr: SocketAddr,
    session_id: SessionId,

    send_key:  crate::crypto::SessionKey,
    send_seq:  u64,

    recv_key:    crate::crypto::SessionKey,
    recv_replay: ReplayWindow,
    recv_seq:    u64,

    data_rx: mpsc::Receiver<Pkt>,

    /// Dropping this stops the keepalive task cleanly.
    _keepalive_stop: mpsc::Sender<()>,
    /// Updated on every received packet; read by the keepalive task.
    last_recv_us: Arc<AtomicU64>,
    /// Fires once when the keepalive task declares the session dead.
    dead_rx: mpsc::Receiver<()>,

    cfg:     Arc<SmrpConfig>,
    metrics: Arc<SmrpMetrics>,
    /// Guards against double-decrement of `metrics.sessions_active`.
    closed:  Arc<AtomicBool>,
}

impl SmrpConnection {
    // --- Public constructors ---

    /// Opens an SMRP connection to `server_addr` using default configuration.
    pub async fn connect(server_addr: &str) -> Result<Self, SmrpError> {
        Self::connect_with_config(server_addr, Arc::new(SmrpConfig::default())).await
    }

    /// Opens an SMRP connection using a custom [`SmrpConfig`].
    pub async fn connect_with_config(
        server_addr: &str,
        cfg: Arc<SmrpConfig>,
    ) -> Result<Self, SmrpError> {
        let timeout = cfg.connect_timeout;
        time::timeout(timeout, Self::connect_inner(server_addr, cfg))
            .await
            .map_err(|_| SmrpError::HandshakeTimeout)?
    }

    async fn connect_inner(server_addr: &str, cfg: Arc<SmrpConfig>) -> Result<Self, SmrpError> {
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
        let session  = handshake::client_handshake(&socket, addr, &sign_key).await?;

        let (data_tx, data_rx) = mpsc::channel(cfg.session_channel_capacity);
        let session_id = session.id;

        let socket_rx = Arc::clone(&socket);
        tokio::spawn(async move {
            loop {
                match transport::recv_raw(&socket_rx).await {
                    Ok((hdr, payload, _)) => {
                        if hdr.session_id != session_id { continue; }
                        if data_tx.send((hdr, payload)).await.is_err() { break; }
                    }
                    Err(e) => { debug!("client recv task: {e}"); break; }
                }
            }
        });

        // Client connections use a private metrics instance (not externally visible).
        Self::assemble(session, socket, data_rx, cfg, Arc::new(SmrpMetrics::new()), None)
    }

    // --- Internal constructors ---

    /// Called by the listener for each completed server-side handshake.
    pub(crate) fn from_server_session(
        session:         Session,
        socket:          Arc<UdpSocket>,
        data_rx:         mpsc::Receiver<Pkt>,
        cfg:             Arc<SmrpConfig>,
        metrics:         Arc<SmrpMetrics>,
        dead_session_tx: mpsc::Sender<SessionId>,
    ) -> Result<Self, SmrpError> {
        Self::assemble(session, socket, data_rx, cfg, metrics, Some(dead_session_tx))
    }

    fn assemble(
        mut session:     Session,
        socket:          Arc<UdpSocket>,
        data_rx:         mpsc::Receiver<Pkt>,
        cfg:             Arc<SmrpConfig>,
        metrics:         Arc<SmrpMetrics>,
        dead_session_tx: Option<mpsc::Sender<SessionId>>,
    ) -> Result<Self, SmrpError> {
        let (keepalive_stop_tx, keepalive_stop_rx) = mpsc::channel::<()>(1);
        let (dead_notify_tx, dead_rx)              = mpsc::channel::<()>(1);
        // Seed with "now" so dead-timer starts from session establishment.
        let last_recv_us = Arc::new(AtomicU64::new(timestamp_us()));
        let closed       = Arc::new(AtomicBool::new(false));

        spawn_keepalive_task(
            Arc::clone(&socket),
            session.peer_addr,
            session.id,
            keepalive_stop_rx,
            Arc::clone(&last_recv_us),
            dead_notify_tx,
            dead_session_tx,
            Arc::clone(&metrics),
            Arc::clone(&closed),
            cfg.keepalive_interval,
            cfg.session_dead_timeout,
        );

        Ok(Self {
            socket,
            peer_addr:       session.peer_addr,
            session_id:      session.id,
            send_key:        session.send_key.take().ok_or(SmrpError::InternalError)?,
            send_seq:        session.send_seq,
            recv_key:        session.recv_key.take().ok_or(SmrpError::InternalError)?,
            recv_replay:     session.recv_replay,
            recv_seq:        session.recv_seq,
            data_rx,
            _keepalive_stop: keepalive_stop_tx,
            last_recv_us,
            dead_rx,
            cfg,
            metrics,
            closed,
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
        let seq   = self.send_seq;
        let nonce = packet_nonce(self.session_id.as_bytes(), seq);
        let mut aad = [0u8; 16];
        aad[0..8].copy_from_slice(self.session_id.as_bytes());
        aad[8..16].copy_from_slice(&seq.to_be_bytes());
        let ciphertext = self.send_key.seal(&nonce, &aad, data)?;

        let hdr = SmrpHeader {
            magic:           SMRP_MAGIC,
            version:         SMRP_VERSION,
            packet_type:     PacketType::Data,
            flags:           Flags::default(),
            reserved:        0,
            session_id:      self.session_id,
            sequence_number: seq,
            ack_number:      self.recv_seq,
            timestamp_us:    timestamp_us(),
            payload_len:     ciphertext.len() as u16,
        };
        transport::send_raw(&self.socket, self.peer_addr, &hdr, &ciphertext).await?;
        self.send_seq += 1;

        self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.metrics.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Waits for the next DATA packet (up to `cfg.recv_timeout`).
    ///
    /// Returns `Ok(None)` on FIN, graceful shutdown, or dead-session eviction.
    /// Returns `Err(HandshakeTimeout)` if nothing arrives within the deadline.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, SmrpError> {
        let deadline = self.cfg.recv_timeout;
        self.recv_timeout(deadline).await
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
                        return Ok(None); // channel closed
                    };
                    self.last_recv_us.store(timestamp_us(), Ordering::Relaxed);

                    match hdr.packet_type {
                        PacketType::Data => {
                            let seq = hdr.sequence_number;

                            if let Err(e) = self.recv_replay.can_accept(seq) {
                                self.metrics.replay_detections.fetch_add(1, Ordering::Relaxed);
                                return Err(e);
                            }

                            let nonce = packet_nonce(self.session_id.as_bytes(), seq);
                            let mut aad = [0u8; 16];
                            aad[0..8].copy_from_slice(self.session_id.as_bytes());
                            aad[8..16].copy_from_slice(&seq.to_be_bytes());

                            let plaintext = self.recv_key.open(&nonce, &aad, &payload)
                                .map_err(|e| {
                                    self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                                    e
                                })?;

                            self.recv_replay.mark_seen(seq);
                            self.recv_seq = seq;
                            let _ = self.send_ack(seq).await;

                            self.metrics.packets_received.fetch_add(1, Ordering::Relaxed);
                            self.metrics.bytes_received.fetch_add(plaintext.len() as u64, Ordering::Relaxed);
                            return Ok(Some(plaintext));
                        }
                        PacketType::Fin => {
                            let _ = self.send_fin_ack(hdr.sequence_number).await;
                            self.mark_closed();
                            return Ok(None);
                        }
                        PacketType::Keepalive   => { let _ = self.send_keepalive_ack().await; }
                        PacketType::KeepaliveAck => {}
                        PacketType::Ack          => {}
                        PacketType::FinAck       => {}
                        _                        => {}
                    }
                }

                _ = self.dead_rx.recv() => {
                    warn!("session {:?}: dead-session timeout; closing", self.session_id);
                    return Ok(None);
                }
            }
        }
    }

    /// Sends FIN, waits up to `cfg.fin_ack_timeout` for FIN_ACK, then releases.
    pub async fn close(mut self) -> Result<(), SmrpError> {
        self.send_fin_flag().await?;
        let timeout = self.cfg.fin_ack_timeout;
        let _ = time::timeout(timeout, self.wait_fin_ack()).await;
        self.mark_closed();
        Ok(())
    }

    // --- Private helpers ---

    fn mark_closed(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.metrics.sessions_active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    async fn send_fin_flag(&self) -> Result<(), SmrpError> {
        let mut flags = Flags::default();
        flags.0 |= Flags::FIN;
        transport::send_raw(&self.socket, self.peer_addr, &SmrpHeader {
            magic: SMRP_MAGIC, version: SMRP_VERSION,
            packet_type: PacketType::Fin, flags, reserved: 0,
            session_id: self.session_id,
            sequence_number: self.send_seq, ack_number: self.recv_seq,
            timestamp_us: timestamp_us(), payload_len: 0,
        }, &[]).await
    }

    async fn send_fin_ack(&self, ack_seq: u64) -> Result<(), SmrpError> {
        transport::send_raw(&self.socket, self.peer_addr, &SmrpHeader {
            magic: SMRP_MAGIC, version: SMRP_VERSION,
            packet_type: PacketType::FinAck, flags: Flags::default(), reserved: 0,
            session_id: self.session_id,
            sequence_number: self.send_seq, ack_number: ack_seq,
            timestamp_us: timestamp_us(), payload_len: 0,
        }, &[]).await
    }

    async fn send_ack(&self, ack_seq: u64) -> Result<(), SmrpError> {
        transport::send_raw(&self.socket, self.peer_addr, &SmrpHeader {
            magic: SMRP_MAGIC, version: SMRP_VERSION,
            packet_type: PacketType::Ack, flags: Flags::default(), reserved: 0,
            session_id: self.session_id,
            sequence_number: self.send_seq, ack_number: ack_seq,
            timestamp_us: timestamp_us(), payload_len: 0,
        }, &[]).await
    }

    async fn send_keepalive_ack(&self) -> Result<(), SmrpError> {
        transport::send_raw(&self.socket, self.peer_addr, &SmrpHeader {
            magic: SMRP_MAGIC, version: SMRP_VERSION,
            packet_type: PacketType::KeepaliveAck, flags: Flags::default(), reserved: 0,
            session_id: self.session_id,
            sequence_number: self.send_seq, ack_number: self.recv_seq,
            timestamp_us: timestamp_us(), payload_len: 0,
        }, &[]).await
    }

    async fn wait_fin_ack(&mut self) {
        loop {
            let Some((hdr, _)) = self.data_rx.recv().await else { return; };
            if hdr.packet_type == PacketType::FinAck { return; }
        }
    }

    // --- Accessors ---

    /// Returns the peer's UDP address.
    #[must_use] pub fn peer_addr(&self)   -> SocketAddr  { self.peer_addr }

    /// Returns the raw 8-byte session identifier.
    #[must_use] pub fn session_id(&self)  -> &[u8; 8]    { self.session_id.as_bytes() }
}

// ---------------------------------------------------------------------------
// Keepalive task
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn spawn_keepalive_task(
    socket:          Arc<UdpSocket>,
    peer_addr:       SocketAddr,
    session_id:      SessionId,
    mut stop_rx:     mpsc::Receiver<()>,
    last_recv_us:    Arc<AtomicU64>,
    dead_notify_tx:  mpsc::Sender<()>,
    dead_session_tx: Option<mpsc::Sender<SessionId>>,
    metrics:         Arc<SmrpMetrics>,
    closed:          Arc<AtomicBool>,
    probe_interval:  Duration,
    dead_threshold:  Duration,
) {
    let dead_threshold_us = dead_threshold.as_micros() as u64;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = time::sleep(probe_interval) => {
                    let now_us  = timestamp_us();
                    let last_us = last_recv_us.load(Ordering::Relaxed);

                    if now_us.saturating_sub(last_us) >= dead_threshold_us {
                        warn!("session {session_id:?}: no traffic for {}s — evicting",
                              dead_threshold.as_secs());

                        // Decrement sessions_active exactly once.
                        if !closed.swap(true, Ordering::AcqRel) {
                            metrics.sessions_active.fetch_sub(1, Ordering::Relaxed);
                        }
                        metrics.sessions_evicted_dead.fetch_add(1, Ordering::Relaxed);

                        let _ = dead_notify_tx.try_send(());
                        if let Some(tx) = dead_session_tx {
                            let _ = tx.send(session_id).await;
                        }
                        break;
                    }

                    let hdr = SmrpHeader {
                        magic: SMRP_MAGIC, version: SMRP_VERSION,
                        packet_type: PacketType::Keepalive, flags: Flags::default(), reserved: 0,
                        session_id, sequence_number: 0, ack_number: 0,
                        timestamp_us: timestamp_us(), payload_len: 0,
                    };
                    if transport::send_raw(&socket, peer_addr, &hdr, &[]).await.is_err() {
                        break;
                    }
                    debug!("session {session_id:?}: KEEPALIVE sent");
                }

                _ = stop_rx.recv() => {
                    debug!("session {session_id:?}: keepalive task stopping");
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
    local_addr:  SocketAddr,
    /// Shared with the dispatch task; needed by `shutdown()` to send FINs.
    socket:      Arc<UdpSocket>,
    new_conn_rx: mpsc::Receiver<SmrpConnection>,
    /// Drop or send on this to stop the dispatch loop.
    shutdown_tx: mpsc::Sender<()>,
    /// Shared with the dispatch task; holds peer_addr per session for shutdown.
    sessions:    SessionMap,
    cfg:         Arc<SmrpConfig>,
    metrics:     Arc<SmrpMetrics>,
}

impl SmrpListener {
    /// Binds a UDP socket on `addr` using default configuration.
    pub async fn bind(addr: &str) -> Result<Self, SmrpError> {
        Self::bind_with_config(addr, Arc::new(SmrpConfig::default())).await
    }

    /// Binds a UDP socket on `addr` using a custom [`SmrpConfig`].
    pub async fn bind_with_config(addr: &str, cfg: Arc<SmrpConfig>) -> Result<Self, SmrpError> {
        let socket = Arc::new(
            UdpSocket::bind(addr).await.map_err(|_| SmrpError::InternalError)?,
        );
        let local_addr  = socket.local_addr().map_err(|_| SmrpError::InternalError)?;
        let sign_key    = Arc::new(SigningKey::generate()?);
        let sessions: SessionMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let metrics     = Arc::new(SmrpMetrics::new());
        let (new_conn_tx, new_conn_rx)     = mpsc::channel(cfg.accept_queue_capacity);
        let (shutdown_tx, shutdown_rx)     = mpsc::channel::<()>(1);
        let (dead_sess_tx, dead_sess_rx)   = mpsc::channel::<SessionId>(256);

        tokio::spawn(listener_dispatch(
            Arc::clone(&socket),
            sign_key,
            Arc::clone(&sessions),
            new_conn_tx,
            shutdown_rx,
            dead_sess_tx,
            dead_sess_rx,
            Arc::clone(&cfg),
            Arc::clone(&metrics),
        ));

        Ok(Self { local_addr, socket, new_conn_rx, shutdown_tx, sessions, cfg, metrics })
    }

    /// Waits for the next inbound connection.
    ///
    /// Returns `None` after [`shutdown`](Self::shutdown) is called.
    pub async fn accept(&mut self) -> Option<SmrpConnection> {
        self.new_conn_rx.recv().await
    }

    /// Returns the local address this listener is bound to.
    #[must_use] pub fn local_addr(&self) -> SocketAddr { self.local_addr }

    /// Returns a shared handle to the listener's metrics counters.
    #[must_use] pub fn metrics(&self) -> Arc<SmrpMetrics> { Arc::clone(&self.metrics) }

    /// Returns the active configuration.
    #[must_use] pub fn config(&self) -> Arc<SmrpConfig> { Arc::clone(&self.cfg) }

    /// Gracefully shuts down the listener.
    ///
    /// 1. Signals the dispatch loop to stop (no new connections accepted).
    /// 2. Sends a real FIN UDP packet to every connected peer so their
    ///    `recv()` returns `Ok(None)` promptly.
    /// 3. Injects a synthetic FIN into every server-side session channel.
    /// 4. Dropping `self` closes `new_conn_rx`, causing `accept()` → `None`.
    pub async fn shutdown(self) {
        // Stop the dispatch loop.
        drop(self.shutdown_tx);

        let map = self.sessions.lock().await;
        for (sid, entry) in map.iter() {
            // Send a real FIN over the wire so the remote peer is notified.
            let fin = shutdown_fin(*sid);
            let _ = transport::send_raw(&self.socket, entry.peer_addr, &fin, &[]).await;

            // Also inject into the server-side SmrpConnection's channel so
            // any in-progress server recv() returns Ok(None) quickly.
            let _ = entry.data_tx.try_send((shutdown_fin(*sid), vec![]));
        }
        // Dropping self drops new_conn_rx → accept() returns None.
    }
}

fn shutdown_fin(session_id: SessionId) -> SmrpHeader {
    let mut flags = Flags::default();
    flags.0 |= Flags::FIN;
    SmrpHeader {
        magic: SMRP_MAGIC, version: SMRP_VERSION,
        packet_type: PacketType::Fin, flags, reserved: 0,
        session_id, sequence_number: 0, ack_number: 0,
        timestamp_us: timestamp_us(), payload_len: 0,
    }
}

// ---------------------------------------------------------------------------
// Listener dispatch task
// ---------------------------------------------------------------------------

struct RateBucket { count: u32, window_start: Instant }

impl RateBucket {
    fn new() -> Self { Self { count: 0, window_start: Instant::now() } }

    fn allow(&mut self, limit: u32) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.count = 0;
            self.window_start = now;
        }
        self.count += 1;
        self.count <= limit
    }
}

#[allow(clippy::too_many_arguments)]
async fn listener_dispatch(
    socket:          Arc<UdpSocket>,
    sign_key:        Arc<SigningKey>,
    sessions:        SessionMap,
    new_conn_tx:     mpsc::Sender<SmrpConnection>,
    mut shutdown_rx: mpsc::Receiver<()>,
    dead_session_tx: mpsc::Sender<SessionId>,
    mut dead_sess_rx: mpsc::Receiver<SessionId>,
    cfg:             Arc<SmrpConfig>,
    metrics:         Arc<SmrpMetrics>,
) {
    let mut rate_limits: HashMap<IpAddr, RateBucket> = HashMap::new();

    loop {
        tokio::select! {
            result = transport::recv_raw(&socket) => {
                let (hdr, payload, addr) = match result {
                    Ok(t)  => t,
                    Err(e) => { warn!("listener recv: {e}"); continue; }
                };

                match hdr.packet_type {
                    PacketType::Hello => {
                        // Rate limit
                        let bucket = rate_limits.entry(addr.ip()).or_insert_with(RateBucket::new);
                        if !bucket.allow(cfg.hello_rate_limit) {
                            metrics.hello_drops_rate_limit.fetch_add(1, Ordering::Relaxed);
                            warn!("HELLO rate limit exceeded for {}", addr.ip());
                            continue;
                        }

                        // Timestamp validation
                        let now_us  = timestamp_us();
                        let skew_us = cfg.hello_clock_skew.as_micros() as u64;
                        let ts = hdr.timestamp_us;
                        if ts.saturating_add(skew_us) < now_us || ts > now_us.saturating_add(skew_us) {
                            metrics.hello_drops_clock_skew.fetch_add(1, Ordering::Relaxed);
                            warn!("HELLO from {addr}: timestamp out of range");
                            continue;
                        }

                        // Session capacity
                        {
                            let map = sessions.lock().await;
                            if map.len() >= cfg.max_sessions {
                                metrics.hello_drops_capacity.fetch_add(1, Ordering::Relaxed);
                                warn!("MAX_SESSIONS reached; rejecting HELLO from {addr}");
                                send_error_reply(&socket, addr, hdr.session_id,
                                                 SmrpError::SessionLimitExceeded).await;
                                continue;
                            }
                            if map.contains_key(&hdr.session_id) {
                                debug!("duplicate HELLO for session {:?}", hdr.session_id);
                                continue;
                            }
                        }

                        let socket2       = Arc::clone(&socket);
                        let sign_key2     = Arc::clone(&sign_key);
                        let sessions2     = Arc::clone(&sessions);
                        let new_conn_tx2  = new_conn_tx.clone();
                        let dead_sess_tx2 = dead_session_tx.clone();
                        let cfg2          = Arc::clone(&cfg);
                        let metrics2      = Arc::clone(&metrics);
                        let sid           = hdr.session_id;

                        tokio::spawn(async move {
                            let session = match handshake::server_handshake(
                                &socket2, addr, sid, &payload, &sign_key2,
                            ).await {
                                Ok(s)  => s,
                                Err(e) => { warn!("handshake with {addr} failed: {e}"); return; }
                            };

                            let cap      = cfg2.session_channel_capacity;
                            let (data_tx, data_rx) = mpsc::channel(cap);
                            let conn_sid = session.id;

                            let conn = match SmrpConnection::from_server_session(
                                session, socket2, data_rx, cfg2, Arc::clone(&metrics2), dead_sess_tx2,
                            ) {
                                Ok(c)  => c,
                                Err(e) => { warn!("connection assembly failed: {e}"); return; }
                            };

                            metrics2.sessions_active.fetch_add(1, Ordering::Relaxed);
                            metrics2.sessions_total.fetch_add(1, Ordering::Relaxed);

                            sessions2.lock().await.insert(conn_sid, SessionEntry {
                                data_tx,
                                peer_addr: addr,
                            });

                            if new_conn_tx2.send(conn).await.is_err() {
                                sessions2.lock().await.remove(&conn_sid);
                            }
                        });
                    }

                    PacketType::Data | PacketType::Fin | PacketType::FinAck
                    | PacketType::Ack | PacketType::Keepalive | PacketType::KeepaliveAck
                    | PacketType::Reset => {
                        let mut map = sessions.lock().await;
                        let sid    = hdr.session_id;
                        let remove = if let Some(entry) = map.get(&sid) {
                            match entry.data_tx.try_send((hdr, payload)) {
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

                    other => { debug!("listener: unhandled {other:?} from {addr}"); }
                }
            }

            _ = shutdown_rx.recv() => {
                debug!("listener dispatch: shutdown");
                break;
            }

            Some(dead_sid) = dead_sess_rx.recv() => {
                sessions.lock().await.remove(&dead_sid);
                debug!("listener dispatch: evicted dead session {dead_sid:?}");
            }
        }
    }
    // Exiting drops new_conn_tx → accept() returns None.
}

async fn send_error_reply(
    socket: &UdpSocket, addr: SocketAddr,
    session_id: SessionId, err: SmrpError,
) {
    let hdr = SmrpHeader {
        magic: SMRP_MAGIC, version: SMRP_VERSION,
        packet_type: PacketType::Error, flags: Flags::default(), reserved: 0,
        session_id, sequence_number: 0, ack_number: 0,
        timestamp_us: timestamp_us(), payload_len: 1,
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

    async fn echo_server() -> (SocketAddr, SmrpListener) {
        let listener = SmrpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr();
        (addr, listener)
    }

    fn spawn_echo(mut listener: SmrpListener) {
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

    // --- Round-trip ---

    #[tokio::test]
    async fn single_round_trip() {
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        conn.send(b"hello smrp").await.unwrap();
        assert_eq!(conn.recv().await.unwrap().unwrap(), b"hello smrp");
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn multiple_messages_same_connection() {
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        for i in 0u8..16 {
            let msg = vec![i; 64];
            conn.send(&msg).await.unwrap();
            assert_eq!(conn.recv().await.unwrap().unwrap(), msg);
        }
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn max_payload_accepted() {
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        let big = vec![0xABu8; MAX_PAYLOAD];
        conn.send(&big).await.unwrap();
        assert_eq!(conn.recv().await.unwrap().unwrap().len(), MAX_PAYLOAD);
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn oversized_payload_rejected_locally() {
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        assert_eq!(
            conn.send(&vec![0u8; MAX_PAYLOAD + 1]).await.unwrap_err(),
            SmrpError::PayloadTooLarge
        );
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_sessions() {
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let handles: Vec<_> = (0u8..8).map(|i| {
            let a = addr;
            tokio::spawn(async move {
                let mut conn = SmrpConnection::connect(&a.to_string()).await.unwrap();
                let msg = vec![i; 32];
                conn.send(&msg).await.unwrap();
                assert_eq!(conn.recv().await.unwrap().unwrap(), msg);
                conn.close().await.unwrap();
            })
        }).collect();
        for h in handles { h.await.unwrap(); }
    }

    // --- Timeouts ---

    #[tokio::test]
    async fn connect_timeout_fires() {
        let result = time::timeout(
            Duration::from_secs(12),
            SmrpConnection::connect("127.0.0.1:1"),
        ).await;
        assert!(result.is_ok(), "outer timeout fired unexpectedly");
        assert!(result.unwrap().is_err(), "connect should have failed");
    }

    #[tokio::test]
    async fn recv_timeout_fires_when_server_silent() {
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        let res = conn.recv_timeout(Duration::from_millis(200)).await;
        assert_eq!(res.unwrap_err(), SmrpError::HandshakeTimeout);
    }

    // --- FIN / FIN_ACK ---

    #[tokio::test]
    async fn graceful_close_completes() {
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        conn.send(b"bye").await.unwrap();
        let _ = conn.recv().await.unwrap();
        conn.close().await.unwrap();
    }

    // --- Graceful listener shutdown ---

    #[tokio::test]
    async fn listener_shutdown_notifies_client() {
        let (addr, listener) = echo_server().await;
        let mut client = SmrpConnection::connect(&addr.to_string()).await.unwrap();

        // Small pause: the handshake sub-task inserts the session into the map
        // *after* sending HELLO_ACK (which unblocks connect()).  Without this
        // pause, shutdown() may lock the map before the entry is inserted.
        tokio::time::sleep(Duration::from_millis(100)).await;

        listener.shutdown().await;

        // The client should see Ok(None) from the FIN sent over the wire.
        let result = time::timeout(Duration::from_secs(2), client.recv()).await;
        assert!(result.is_ok(), "client.recv() timed out after shutdown");
        assert!(result.unwrap().unwrap().is_none(), "expected Ok(None)");
    }

    #[tokio::test]
    async fn no_new_connections_after_shutdown() {
        let (addr, listener) = echo_server().await;
        listener.shutdown().await;
        let result = time::timeout(
            Duration::from_millis(500),
            SmrpConnection::connect(&addr.to_string()),
        ).await;
        assert!(result.is_err(), "expected timeout — listener is shut down");
    }

    // --- Metrics ---

    #[tokio::test]
    async fn metrics_track_sent_received() {
        let (addr, listener) = echo_server().await;
        let m = listener.metrics();
        spawn_echo(listener);

        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        conn.send(b"measure me").await.unwrap();
        let _ = conn.recv().await.unwrap();
        conn.close().await.unwrap();

        // Give the server-side a moment to finish processing.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let snap = m.snapshot();
        assert!(snap.sessions_total >= 1, "sessions_total should be ≥ 1");
        assert!(snap.packets_received >= 1, "server should have received ≥ 1 packet");
        assert!(snap.bytes_received >= b"measure me".len() as u64);
    }

    // --- SmrpConfig ---

    #[tokio::test]
    async fn custom_config_connect_timeout() {
        let cfg = Arc::new(SmrpConfig {
            connect_timeout: Duration::from_millis(300),
            ..SmrpConfig::default()
        });
        let start = Instant::now();
        let _ = SmrpConnection::connect_with_config("127.0.0.1:1", cfg).await;
        // Should have returned within ~1 s (well under the default 10 s).
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
