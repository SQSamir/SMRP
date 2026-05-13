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
    constants::{AUTH_TAG_LEN, HEADER_LEN, MAX_PAYLOAD, SMRP_MAGIC, SMRP_VERSION},
    crypto::{
        derive_nonce_prefix, ed25519_verify, hkdf_sha256, make_nonce, EphemeralKeypair, SessionKey,
        SigningKey,
    },
    error::SmrpError,
    handshake,
    metrics::SmrpMetrics,
    packet::{serialize as serialize_hdr, timestamp_us, Flags, PacketType, SmrpHeader},
    replay::ReplayWindow,
    session::{Session, SessionId},
    transport,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Notify},
    time,
};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Messages routed into a per-session channel by the listener dispatch loop.
enum SessionMsg {
    Packet(SmrpHeader, Vec<u8>),
    /// Injected by `SmrpListener::shutdown()` to unblock `recv_inner`.
    Shutdown,
}

/// Per-session routing entry stored in the listener's session map.
struct SessionEntry {
    /// Channel into the server-side `SmrpConnection`'s receive loop.
    data_tx: mpsc::Sender<SessionMsg>,
}

type SessionMap = Arc<tokio::sync::Mutex<HashMap<SessionId, SessionEntry>>>;

// ---------------------------------------------------------------------------
// Retransmission
// ---------------------------------------------------------------------------

/// A DATA packet waiting for its ACK.
struct RetransmitEntry {
    /// Copy of the header used to re-send (`timestamp_us` updated on each retry).
    header: SmrpHeader,
    /// Already-encrypted ciphertext + 16-byte Poly1305 tag.
    ciphertext: Vec<u8>,
    /// Wall-clock time of the last (re-)transmission.
    sent_at: Instant,
    /// Number of retransmissions so far (0 = first send).
    retries: u32,
}

/// Jacobson/Karels RTT estimator that drives the retransmission timeout.
/// All stored values are in microseconds.
struct RttEstimator {
    srtt: f64,    // smoothed RTT
    rttvar: f64,  // RTT variance
    current: u64, // current RTO
    floor: u64,   // minimum RTO
    ceiling: u64, // maximum RTO
}

impl RttEstimator {
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    fn new(initial: Duration, min: Duration, max: Duration) -> Self {
        let init = initial.as_micros() as u64;
        let init_f = init as f64;
        Self {
            srtt: init_f,
            rttvar: init_f / 4.0,
            current: init,
            floor: min.as_micros() as u64,
            ceiling: max.as_micros() as u64,
        }
    }

    /// Updates the estimator with a new RTT sample (Jacobson/Karels: α=1/8, β=1/4).
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation
    )]
    fn update(&mut self, rtt_us: u64) {
        let r = rtt_us as f64;
        self.rttvar = 0.75 * self.rttvar + 0.25 * (r - self.srtt).abs();
        self.srtt = 0.875 * self.srtt + 0.125 * r;
        let rto = (self.srtt + 4.0 * self.rttvar).max(0.0) as u64;
        self.current = rto.clamp(self.floor, self.ceiling);
    }

    /// Doubles the RTO (exponential backoff), capped at the ceiling.
    fn backoff(&mut self) {
        self.current = (self.current * 2).min(self.ceiling);
    }

    fn rto(&self) -> Duration {
        Duration::from_micros(self.current)
    }
}

struct RetransmitState {
    pending: BTreeMap<u64, RetransmitEntry>,
    rtt: RttEstimator,
    /// Congestion window: max unACKed packets in flight.
    cwnd: usize,
    /// Slow-start threshold; above this, switch to AIMD congestion avoidance.
    ssthresh: usize,
    /// ACK counter for the congestion-avoidance phase (add 1/cwnd per ACK).
    ca_acks: usize,
    /// Sequences the peer has selectively acknowledged; skip on retransmit.
    sacked: BTreeSet<u64>,
    /// Peer's advertised receive window in packets (from `recv_window` header field).
    peer_recv_window: u16,
}

/// Reassembly buffer for a single fragmented message.
struct FragmentAssembly {
    pieces: Vec<Option<Vec<u8>>>,
    received: u8,
}

impl FragmentAssembly {
    fn new(frag_count: u8) -> Self {
        Self {
            pieces: vec![None; frag_count as usize],
            received: 0,
        }
    }

    /// Inserts a fragment; returns `true` when all pieces have arrived.
    fn insert(&mut self, index: u8, data: Vec<u8>) -> bool {
        let slot = &mut self.pieces[index as usize];
        if slot.is_none() {
            *slot = Some(data);
            self.received += 1;
        }
        self.received as usize == self.pieces.len()
    }

    /// Concatenates all pieces in order into a single message.
    fn assemble(self) -> Vec<u8> {
        self.pieces
            .into_iter()
            .flat_map(std::option::Option::unwrap_or_default)
            .collect()
    }
}

type RetransmitBuf = Arc<tokio::sync::Mutex<RetransmitState>>;

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

    send_key: SessionKey,
    send_seq: u64,

    recv_key: SessionKey,
    recv_replay: ReplayWindow,
    /// Highest in-order sequence number delivered to the application.
    recv_seq: u64,
    /// Out-of-order received packets (header + plaintext) waiting for earlier seq numbers.
    recv_buf: BTreeMap<u64, (SmrpHeader, Vec<u8>)>,
    /// Next sequence number to deliver to the caller (1-based).
    next_deliver_seq: u64,
    /// Decrypted, consecutive packets ready for the caller to receive.
    deliver_queue: VecDeque<Vec<u8>>,
    /// Max entries in `recv_buf` before arriving out-of-order packets are dropped.
    recv_buf_limit: usize,

    data_rx: mpsc::Receiver<SessionMsg>,

    /// Dropping this stops the keepalive task cleanly.
    _keepalive_stop: mpsc::Sender<()>,
    /// Updated on every received packet; read by the keepalive task.
    last_recv_us: Arc<AtomicU64>,
    /// Fires once when the keepalive or retransmit task declares the session dead.
    dead_rx: mpsc::Receiver<()>,

    /// Pending DATA packets awaiting ACK; shared with the retransmit task.
    retransmit_buf: RetransmitBuf,
    /// Dropping this stops the retransmit task cleanly.
    _retransmit_stop: mpsc::Sender<()>,
    /// Notified when the congestion window opens (ACK received or cwnd grew).
    window_notify: Arc<Notify>,

    // --- Nonce prefixes (HKDF-derived, not client-controlled) ---
    data_send_nonce_prefix: [u8; 4],
    data_recv_nonce_prefix: [u8; 4],
    ctrl_send_nonce_prefix: [u8; 4],
    ctrl_recv_nonce_prefix: [u8; 4],
    /// Monotonic counter for authenticated control-packet nonces.
    ctrl_send_seq: u64,

    /// Timestamp (µs) of the last `KEEPALIVE_ACK` sent; limits replies to 1/second.
    last_keepalive_ack_us: u64,

    // --- Fragmentation ---
    /// Counter incremented each time `send()` fragments a large message.
    frag_send_id: u16,
    /// Partial reassembly state for fragmented messages keyed by `frag_id`.
    reassembly: HashMap<u16, FragmentAssembly>,

    // --- Key update ---
    /// Local signing key used to authenticate `KEY_UPDATE` payloads.
    sign_key: Arc<SigningKey>,
    /// Peer's Ed25519 public key pinned at handshake time.
    peer_sign_pub: [u8; 32],
    /// Monotonic counter incremented each time we initiate a key update.
    rekey_counter: u64,
    /// Highest `KEY_UPDATE` counter accepted from the peer (anti-replay).
    peer_rekey_counter: u64,
    /// Ephemeral keypair kept while we wait for `KEY_UPDATE_ACK`.
    pending_rekey: Option<EphemeralKeypair>,
    /// `true` for connections created via `connect()`, `false` for server side.
    /// Determines which derived key is the send key vs the receive key.
    is_client: bool,

    // --- KEY_UPDATE in-progress buffering ---
    /// Raw bytes of the recv key active just before rotation.
    /// Held so we can decrypt DATA that the initiator sent with the old key
    /// before it received our KEY_UPDATE_ACK.  Cleared once all buffered
    /// packets are delivered or a new KEY_UPDATE supersedes this one.
    pre_rekey_recv_key_bytes: Option<[u8; 32]>,
    /// DATA packets that arrived during key rotation and were decrypted with
    /// the pre-rekey key; drained after `install_rekey_keys` completes.
    buffered_rekey_data: Vec<(u64, Vec<u8>)>,
    /// Raw bytes of the current recv key, kept so we can reconstruct it as
    /// `pre_rekey_recv_key_bytes` on the next rekey.
    recv_key_bytes: [u8; 32],

    // --- PMTUD ---
    /// Current effective DATA payload size (bytes), updated by PMTUD probes.
    /// Starts at `MAX_PAYLOAD` and is adjusted based on loss / success signals.
    effective_payload: usize,
    /// Sequence number of the last PMTUD probe packet (0 = none in flight).
    #[allow(dead_code)]
    pmtud_probe_seq: u64,

    // --- Pacing ---
    /// Available token-bucket credits (in bytes) for the send pacer.
    pacing_tokens: f64,
    /// Microsecond timestamp of the last token refill.
    last_pacing_refill_us: u64,

    // --- Connection migration ---
    /// A pending PATH_CHALLENGE nonce we sent; Some while waiting for PATH_RESPONSE.
    pending_migration_nonce: Option<[u8; 8]>,
    /// Source address of the most recent PATH_CHALLENGE we received; used to
    /// send PATH_RESPONSE back to the right address.
    #[allow(dead_code)]
    migration_challenge_addr: Option<SocketAddr>,

    // --- Multiplexed streams ---
    /// Channels for non-default streams (stream_id ≠ 0).  Applications call
    /// `open_stream()` to register a receiver end; the sender end lives here.
    stream_txs: HashMap<u16, mpsc::Sender<Vec<u8>>>,

    cfg: Arc<SmrpConfig>,
    metrics: Arc<SmrpMetrics>,
    /// Guards against double-decrement of `metrics.sessions_active`.
    closed: Arc<AtomicBool>,
}

impl SmrpConnection {
    // --- Public constructors ---

    /// Opens an SMRP connection to `server_addr` using default configuration.
    ///
    /// # Errors
    /// Returns [`SmrpError::HandshakeTimeout`] if the server does not respond
    /// within `cfg.connect_timeout`, or any other [`SmrpError`] on failure.
    pub async fn connect(server_addr: &str) -> Result<Self, SmrpError> {
        Self::connect_with_config(server_addr, Arc::new(SmrpConfig::default())).await
    }

    /// Opens an SMRP connection using a custom [`SmrpConfig`].
    ///
    /// # Errors
    /// Returns [`SmrpError::HandshakeTimeout`] if the server does not respond
    /// within `cfg.connect_timeout`, or any other [`SmrpError`] on failure.
    pub async fn connect_with_config(
        server_addr: &str,
        cfg: Arc<SmrpConfig>,
    ) -> Result<Self, SmrpError> {
        let timeout = cfg.connect_timeout;
        time::timeout(timeout, Self::connect_inner(server_addr, cfg))
            .await
            .map_err(|_| SmrpError::HandshakeTimeout)?
    }

    /// Opens a connection and verifies the server's Ed25519 identity against `pinned_key`.
    ///
    /// Returns [`SmrpError::AuthenticationFailure`] if the handshake succeeds but the
    /// server's public key does not match `pinned_key`.
    ///
    /// # Errors
    /// Returns [`SmrpError::HandshakeTimeout`] on timeout, or any other
    /// [`SmrpError`] on failure.
    pub async fn connect_with_pinned_server_key(
        server_addr: &str,
        pinned_key: &[u8; 32],
    ) -> Result<Self, SmrpError> {
        Self::connect_with_config_and_pinned_key(
            server_addr,
            Arc::new(SmrpConfig::default()),
            pinned_key,
        )
        .await
    }

    /// Opens a connection with a custom config and verifies the server's identity.
    ///
    /// # Errors
    /// Returns [`SmrpError::HandshakeTimeout`] on timeout,
    /// [`SmrpError::AuthenticationFailure`] if the server key doesn't match `pinned_key`,
    /// or any other [`SmrpError`] on failure.
    pub async fn connect_with_config_and_pinned_key(
        server_addr: &str,
        cfg: Arc<SmrpConfig>,
        pinned_key: &[u8; 32],
    ) -> Result<Self, SmrpError> {
        let timeout = cfg.connect_timeout;
        let conn = time::timeout(timeout, Self::connect_inner(server_addr, Arc::clone(&cfg)))
            .await
            .map_err(|_| SmrpError::HandshakeTimeout)??;
        if &conn.peer_sign_pub != pinned_key {
            return Err(SmrpError::AuthenticationFailure);
        }
        Ok(conn)
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
        let session = handshake::client_handshake(&socket, addr, &sign_key).await?;
        let sign_key = Arc::new(sign_key);

        let (data_tx, data_rx) = mpsc::channel(cfg.session_channel_capacity);
        let session_id = session.id;

        let socket_rx = Arc::clone(&socket);
        tokio::spawn(async move {
            loop {
                match transport::recv_raw(&socket_rx).await {
                    Ok((hdr, payload, _)) => {
                        if hdr.session_id != session_id {
                            continue;
                        }
                        if data_tx
                            .send(SessionMsg::Packet(hdr, payload))
                            .await
                            .is_err()
                        {
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

        // Client connections use a private metrics instance (not externally visible).
        Self::assemble(
            session,
            socket,
            data_rx,
            cfg,
            Arc::new(SmrpMetrics::new()),
            None,
            sign_key,
            true,
        )
    }

    // --- Internal constructors ---

    /// Called by the listener for each completed server-side handshake.
    fn from_server_session(
        session: Session,
        socket: Arc<UdpSocket>,
        data_rx: mpsc::Receiver<SessionMsg>,
        cfg: Arc<SmrpConfig>,
        metrics: Arc<SmrpMetrics>,
        dead_session_tx: mpsc::Sender<SessionId>,
        sign_key: Arc<SigningKey>,
    ) -> Result<Self, SmrpError> {
        Self::assemble(
            session,
            socket,
            data_rx,
            cfg,
            metrics,
            Some(dead_session_tx),
            sign_key,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        mut session: Session,
        socket: Arc<UdpSocket>,
        data_rx: mpsc::Receiver<SessionMsg>,
        cfg: Arc<SmrpConfig>,
        metrics: Arc<SmrpMetrics>,
        dead_session_tx: Option<mpsc::Sender<SessionId>>,
        sign_key: Arc<SigningKey>,
        is_client: bool,
    ) -> Result<Self, SmrpError> {
        let (keepalive_stop_tx, keepalive_stop_rx) = mpsc::channel::<()>(1);
        let (retransmit_stop_tx, retransmit_stop_rx) = mpsc::channel::<()>(1);
        let (dead_notify_tx, dead_rx) = mpsc::channel::<()>(1);
        let last_recv_us = Arc::new(AtomicU64::new(timestamp_us()));
        let closed = Arc::new(AtomicBool::new(false));
        let window_notify = Arc::new(Notify::new());

        let retransmit_buf: RetransmitBuf = Arc::new(tokio::sync::Mutex::new(RetransmitState {
            pending: BTreeMap::new(),
            rtt: RttEstimator::new(cfg.rto_initial, cfg.rto_min, cfg.rto_max),
            cwnd: cfg.initial_cwnd,
            ssthresh: cfg.initial_ssthresh,
            ca_acks: 0,
            sacked: BTreeSet::new(),
            peer_recv_window: u16::MAX,
        }));

        spawn_keepalive_task(
            Arc::clone(&socket),
            session.peer_addr,
            session.id,
            keepalive_stop_rx,
            Arc::clone(&last_recv_us),
            dead_notify_tx.clone(),
            dead_session_tx,
            Arc::clone(&metrics),
            Arc::clone(&closed),
            cfg.keepalive_interval,
            cfg.session_dead_timeout,
        );

        spawn_retransmit_task(
            Arc::clone(&socket),
            session.peer_addr,
            session.id,
            Arc::clone(&retransmit_buf),
            retransmit_stop_rx,
            dead_notify_tx,
            Arc::clone(&metrics),
            cfg.max_retransmits,
            cfg.rto_min,
        );

        let recv_buf_limit = cfg.recv_buf_limit;
        let initial_cwnd = cfg.initial_cwnd;
        let peer_sign_pub = session.peer_sign_pub.ok_or(SmrpError::InternalError)?;
        let recv_key = session.recv_key.take().ok_or(SmrpError::InternalError)?;
        let recv_key_bytes = *recv_key.raw_bytes();
        Ok(Self {
            socket,
            peer_addr: session.peer_addr,
            session_id: session.id,
            send_key: session.send_key.take().ok_or(SmrpError::InternalError)?,
            send_seq: session.send_seq,
            recv_key,
            recv_replay: session.recv_replay,
            recv_seq: session.recv_seq,
            recv_buf: BTreeMap::new(),
            next_deliver_seq: 1,
            deliver_queue: VecDeque::new(),
            recv_buf_limit,
            data_rx,
            _keepalive_stop: keepalive_stop_tx,
            last_recv_us,
            dead_rx,
            retransmit_buf,
            _retransmit_stop: retransmit_stop_tx,
            window_notify,
            data_send_nonce_prefix: session.data_send_nonce_prefix,
            data_recv_nonce_prefix: session.data_recv_nonce_prefix,
            ctrl_send_nonce_prefix: session.ctrl_send_nonce_prefix,
            ctrl_recv_nonce_prefix: session.ctrl_recv_nonce_prefix,
            ctrl_send_seq: 0,
            last_keepalive_ack_us: 0,
            frag_send_id: 0,
            reassembly: HashMap::new(),
            sign_key,
            peer_sign_pub,
            rekey_counter: 0,
            peer_rekey_counter: 0,
            pending_rekey: None,
            is_client,
            pre_rekey_recv_key_bytes: None,
            buffered_rekey_data: Vec::new(),
            recv_key_bytes,
            effective_payload: MAX_PAYLOAD,
            pmtud_probe_seq: 0,
            pacing_tokens: initial_cwnd as f64 * MAX_PAYLOAD as f64,
            last_pacing_refill_us: timestamp_us(),
            pending_migration_nonce: None,
            migration_challenge_addr: None,
            stream_txs: HashMap::new(),
            cfg,
            metrics,
            closed,
        })
    }

    // --- Public API ---

    /// Encrypts `data` and sends it, fragmenting transparently if needed.
    ///
    /// Messages up to `MAX_PAYLOAD` are sent as a single DATA packet.
    /// Larger messages are split into up to 255 fragments of ≤ `MAX_PAYLOAD`
    /// bytes each, each carrying the `FRAGMENT` flag, a shared `frag_id`,
    /// `frag_index`, and `frag_count`. The receiver reassembles them before
    /// delivering to the application.
    ///
    /// Blocks when the effective send window (`min(cwnd, peer_recv_window)`) is
    /// full and resumes automatically as ACKs / `SackAck`s arrive.
    /// Each fragment is retransmitted up to `cfg.max_retransmits` times before
    /// the session is declared dead.
    ///
    /// # Errors
    /// Returns [`SmrpError::PayloadTooLarge`] if the message requires more than
    /// 255 fragments (i.e. `data.len() > 255 * MAX_PAYLOAD`).
    pub async fn send(&mut self, data: &[u8]) -> Result<(), SmrpError> {
        let effective = self.effective_payload;
        let max_fragments: usize = 255;
        if data.len() > max_fragments * effective {
            return Err(SmrpError::PayloadTooLarge);
        }

        if data.len() <= effective {
            self.send_fragment(data, None).await
        } else {
            let chunks: Vec<&[u8]> = data.chunks(effective).collect();
            let frag_count = chunks.len() as u8;
            let frag_id = self.frag_send_id;
            self.frag_send_id = self.frag_send_id.wrapping_add(1);
            let total_len = data.len() as u64;
            for (i, chunk) in chunks.into_iter().enumerate() {
                self.send_fragment(chunk, Some((frag_id, i as u8, frag_count)))
                    .await?;
            }
            self.metrics.bytes_sent.fetch_add(total_len, Ordering::Relaxed);
            Ok(())
        }
    }

    /// Refills the token bucket and waits until at least `bytes` tokens are
    /// available. Called from `send_fragment` when pacing is enabled.
    #[allow(clippy::cast_precision_loss)]
    async fn pace_wait(&mut self, bytes: usize) {
        if !self.cfg.pacing_enabled {
            return;
        }
        let now_us = timestamp_us();
        let elapsed_us = now_us.saturating_sub(self.last_pacing_refill_us);
        // Estimate bandwidth from cwnd and srtt; refill proportionally.
        // We refill `cwnd * effective_payload` bytes per RTT.
        // If srtt is unknown, treat it as 50 ms.
        let rtt_us = {
            let state = self.retransmit_buf.try_lock();
            state.map_or(50_000, |s| s.rtt.current)
        };
        let rtt_us = rtt_us.max(1);
        let cwnd = {
            self.retransmit_buf.try_lock().map_or(4, |s| s.cwnd)
        };
        let bw_bytes_per_us = (cwnd * self.effective_payload) as f64 / rtt_us as f64;
        let refill = bw_bytes_per_us * elapsed_us as f64;
        let max_burst = (cwnd * self.effective_payload * 2) as f64;
        self.pacing_tokens = (self.pacing_tokens + refill).min(max_burst);
        self.last_pacing_refill_us = now_us;

        // If we don't have enough tokens, sleep for the deficit.
        let deficit = bytes as f64 - self.pacing_tokens;
        if deficit > 0.0 {
            let wait_us = (deficit / bw_bytes_per_us) as u64;
            if wait_us > 0 {
                time::sleep(Duration::from_micros(wait_us)).await;
                self.pacing_tokens = 0.0;
            }
        } else {
            self.pacing_tokens -= bytes as f64;
        }
    }

    /// Sends a single DATA fragment (or a non-fragmented message).
    /// `frag_info`: `Some((frag_id, frag_index, frag_count))` for fragments,
    /// `None` for unfragmented messages.
    async fn send_fragment(
        &mut self,
        data: &[u8],
        frag_info: Option<(u16, u8, u8)>,
    ) -> Result<(), SmrpError> {
        // Congestion + flow-control backpressure.
        let notify = Arc::clone(&self.window_notify);
        loop {
            let notified = notify.notified();
            {
                let state = self.retransmit_buf.lock().await;
                let effective_window = state.cwnd.min(state.peer_recv_window as usize);
                if state.pending.len() < effective_window {
                    break;
                }
            }
            notified.await;
        }

        self.pace_wait(data.len()).await;

        let seq = self.send_seq;
        let nonce = make_nonce(&self.data_send_nonce_prefix, seq);

        let (flags, frag_id, frag_index, frag_count) = match frag_info {
            Some((id, idx, cnt)) => {
                let mut f = Flags::default();
                f.0 |= Flags::FRAGMENT;
                (f, id, idx, cnt)
            }
            None => (Flags::default(), 0, 0, 0),
        };

        let payload_len = (data.len() + AUTH_TAG_LEN) as u16;
        let hdr = SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::Data,
            flags,
            reserved: 0,
            session_id: self.session_id,
            sequence_number: seq,
            ack_number: self.recv_seq,
            timestamp_us: timestamp_us(),
            payload_len,
            frag_id,
            frag_index,
            frag_count,
            recv_window: self.advertised_recv_window(),
            stream_id: 0,
        };

        let aad = data_aad(&hdr);
        let ciphertext = self.send_key.seal(&nonce, &aad, data)?;

        transport::send_raw(&self.socket, self.peer_addr, &hdr, &ciphertext).await?;
        self.send_seq += 1;

        self.retransmit_buf.lock().await.pending.insert(
            seq,
            RetransmitEntry {
                header: hdr,
                ciphertext,
                sent_at: Instant::now(),
                retries: 0,
            },
        );

        // Only count bytes for unfragmented messages here; fragmented totals
        // are counted in send() to avoid double-counting per-fragment.
        if frag_info.is_none() {
            self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .bytes_sent
                .fetch_add(data.len() as u64, Ordering::Relaxed);
        } else {
            self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Waits for the next DATA packet (up to `cfg.recv_timeout`).
    ///
    /// Returns `Ok(None)` on FIN, RESET, graceful shutdown, or dead-session eviction.
    ///
    /// # Errors
    /// Returns [`SmrpError::HandshakeTimeout`] if nothing arrives within `cfg.recv_timeout`.
    /// Returns [`SmrpError::AuthenticationFailure`] on AEAD tag mismatch.
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, SmrpError> {
        let deadline = self.cfg.recv_timeout;
        self.recv_timeout(deadline).await
    }

    /// Like [`recv`](Self::recv) but with a caller-supplied deadline.
    ///
    /// # Errors
    /// Returns [`SmrpError::HandshakeTimeout`] if nothing arrives within `deadline`.
    /// Returns [`SmrpError::AuthenticationFailure`] on AEAD tag mismatch.
    pub async fn recv_timeout(&mut self, deadline: Duration) -> Result<Option<Vec<u8>>, SmrpError> {
        time::timeout(deadline, self.recv_inner())
            .await
            .map_err(|_| SmrpError::HandshakeTimeout)?
    }

    #[allow(clippy::too_many_lines)]
    async fn recv_inner(&mut self) -> Result<Option<Vec<u8>>, SmrpError> {
        loop {
            // Fast path: deliver consecutive packets already in the reorder buffer.
            if let Some(data) = self.deliver_queue.pop_front() {
                return Ok(Some(data));
            }

            tokio::select! {
                msg = self.data_rx.recv() => {
                    let Some(msg) = msg else {
                        return Ok(None); // channel closed
                    };
                    let (hdr, payload) = match msg {
                        SessionMsg::Shutdown => {
                            // Listener is shutting down; send FIN so the peer closes promptly.
                            let _ = self.send_fin_flag().await;
                            self.mark_closed();
                            return Ok(None);
                        }
                        SessionMsg::Packet(h, p) => (h, p),
                    };
                    self.last_recv_us.store(timestamp_us(), Ordering::Relaxed);

                    match hdr.packet_type {
                        PacketType::Data => {
                            let seq = hdr.sequence_number;

                            if self.recv_replay.can_accept(seq).is_err() {
                                self.metrics.replay_detections.fetch_add(1, Ordering::Relaxed);
                                // Likely a retransmit; re-send the current cumulative ACK.
                                let _ = self.send_ack(self.recv_seq).await;
                                continue;
                            }

                            let nonce = make_nonce(&self.data_recv_nonce_prefix, seq);
                            let aad = data_aad(&hdr);

                            let plaintext = match self.recv_key.open(&nonce, &aad, &payload) {
                                Ok(p) => p,
                                Err(_) => {
                                    // Try the pre-rekey key if we're mid-rotation.
                                    // DATA packets sent by the initiator before it received
                                    // KEY_UPDATE_ACK may be encrypted with the old key.
                                    if let Some(old_bytes) = self.pre_rekey_recv_key_bytes {
                                        let old_key = SessionKey::from_raw(&old_bytes)
                                            .unwrap_or_else(|_| unreachable!());
                                        match old_key.open(&nonce, &aad, &payload) {
                                            Ok(p) => {
                                                // Buffer for delivery after keys are settled.
                                                self.buffered_rekey_data.push((seq, p));
                                                let _ = self.send_ack(self.recv_seq).await;
                                                continue;
                                            }
                                            Err(_) => {}
                                        }
                                    }
                                    self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                                    return Err(SmrpError::AuthenticationFailure);
                                }
                            };

                            self.recv_replay.mark_seen(seq);

                            if self.recv_buf.len() < self.recv_buf_limit {
                                self.recv_buf.insert(seq, (hdr, plaintext));
                            }

                            // Drain consecutive packets; keep the mut borrow on self short.
                            while let Some((pkt_hdr, raw)) = self.recv_buf.remove(&self.next_deliver_seq) {
                                self.recv_seq = self.next_deliver_seq;
                                self.next_deliver_seq += 1;
                                self.metrics.packets_received.fetch_add(1, Ordering::Relaxed);

                                let assembled_data = if pkt_hdr.flags.fragment() {
                                    let frag_complete = {
                                        let entry = self.reassembly
                                            .entry(pkt_hdr.frag_id)
                                            .or_insert_with(|| FragmentAssembly::new(pkt_hdr.frag_count));
                                        entry.insert(pkt_hdr.frag_index, raw)
                                    };
                                    if frag_complete {
                                        Some((pkt_hdr.stream_id, self.reassembly
                                            .remove(&pkt_hdr.frag_id)
                                            .unwrap()
                                            .assemble()))
                                    } else {
                                        None
                                    }
                                } else {
                                    Some((pkt_hdr.stream_id, raw))
                                };

                                if let Some((stream_id, msg)) = assembled_data {
                                    self.metrics.bytes_received
                                        .fetch_add(msg.len() as u64, Ordering::Relaxed);
                                    if stream_id == 0 {
                                        self.deliver_queue.push_back(msg);
                                    } else if let Some(tx) = self.stream_txs.get(&stream_id) {
                                        let _ = tx.try_send(msg);
                                    }
                                    // Packets for unknown streams are silently dropped.
                                }
                            }

                            // ACK after drain so ack_number = current recv_seq.
                            if self.recv_buf.is_empty() {
                                let _ = self.send_ack(self.recv_seq).await;
                            } else {
                                let _ = self.send_sack().await;
                            }
                        }

                        PacketType::Ack => {
                            if self.open_ctrl_payload(&hdr, &payload).is_err() { continue; }
                            {
                                let mut buf = self.retransmit_buf.lock().await;
                                buf.peer_recv_window = hdr.recv_window;
                                // ECN: CE-marked ACK signals congestion; halve cwnd.
                                if hdr.flags.ce() {
                                    buf.ssthresh = (buf.cwnd / 2).max(2);
                                    buf.cwnd = buf.ssthresh;
                                    buf.ca_acks = 0;
                                }
                            }
                            self.process_cumulative_ack(hdr.ack_number).await;
                        }

                        PacketType::SackAck => {
                            let Ok(sack_data) = self.open_ctrl_payload(&hdr, &payload) else {
                                continue;
                            };
                            let cum_ack = hdr.ack_number;
                            {
                                let mut buf = self.retransmit_buf.lock().await;
                                buf.peer_recv_window = hdr.recv_window;
                                let blocks = parse_sack_blocks(&sack_data);
                                for (start, end) in blocks {
                                    for seq in start..=end {
                                        buf.sacked.insert(seq);
                                    }
                                }
                                buf.sacked.retain(|&s| s > cum_ack);
                            }
                            self.process_cumulative_ack(cum_ack).await;
                        }

                        PacketType::Fin => {
                            if self.open_ctrl_payload(&hdr, &payload).is_err() { continue; }
                            let _ = self.send_fin_ack(hdr.sequence_number).await;
                            self.mark_closed();
                            return Ok(None);
                        }

                        PacketType::Reset => {
                            if self.open_ctrl_payload(&hdr, &payload).is_err() { continue; }
                            self.mark_closed();
                            return Ok(None);
                        }

                        PacketType::Keepalive => {
                            let now_us = timestamp_us();
                            if now_us.saturating_sub(self.last_keepalive_ack_us) >= 1_000_000 {
                                let _ = self.send_keepalive_ack().await;
                                self.last_keepalive_ack_us = now_us;
                            }
                        }

                        PacketType::Ping => {
                            if self.open_ctrl_payload(&hdr, &payload).is_err() { continue; }
                            let _ = self.send_pong(hdr.sequence_number, hdr.timestamp_us).await;
                        }
                        PacketType::Pong => {
                            if self.open_ctrl_payload(&hdr, &payload).is_err() { continue; }
                            // RTT from the echoed timestamp_us carried in the PONG.
                            let rtt_us = timestamp_us().saturating_sub(hdr.timestamp_us);
                            if rtt_us > 0 && rtt_us < 60_000_000 {
                                self.retransmit_buf.lock().await.rtt.update(rtt_us);
                            }
                        }

                        PacketType::KeyUpdate => {
                            self.handle_key_update(hdr.sequence_number, &payload).await;
                        }

                        PacketType::PathChallenge => {
                            // Echo the 8-byte challenge nonce back in a PathResponse.
                            // No auth required: the response is bound to the nonce.
                            if payload.len() >= 8 && self.cfg.migration_enabled {
                                let _ = self.send_path_response(&payload[..8]).await;
                            }
                        }

                        PacketType::PathResponse => {
                            // If we sent a PathChallenge and this echoes our nonce,
                            // the peer is reachable at the new address — migrate.
                            if let Some(nonce) = self.pending_migration_nonce {
                                if payload.len() >= 8 && payload[..8] == nonce {
                                    // Peer confirmed; update peer_addr.
                                    // (addr comes from the SessionMsg; for now we record
                                    //  it when we sent the challenge via migration_challenge_addr)
                                    self.pending_migration_nonce = None;
                                }
                            }
                        }

                        _ => {}
                    }
                }

                _ = self.dead_rx.recv() => {
                    warn!("session {:?}: declared dead; closing", self.session_id);
                    return Ok(None);
                }
            }
        }
    }

    /// Initiates an in-band key update (rekeying).
    ///
    /// Generates a fresh ephemeral X25519 keypair, sends `KEY_UPDATE` to the peer,
    /// and **blocks** until the peer's `KEY_UPDATE_ACK` is received and verified.
    /// Once this method returns, all subsequent [`send`](Self::send) calls use the
    /// newly derived session keys.
    ///
    /// **Prerequisite:** All previously sent DATA packets must have been
    /// acknowledged before calling this method. Any packets still in the retransmit
    /// buffer when rekeying completes will be retransmitted with the old key and
    /// rejected by the peer (which now holds the new key), causing the session to
    /// be declared dead. Ensure the retransmit buffer is empty — typically by
    /// calling [`recv`](Self::recv) until all expected replies are received.
    ///
    /// # Errors
    /// Returns [`SmrpError::HandshakeTimeout`] if no `KEY_UPDATE_ACK` arrives
    /// within `cfg.recv_timeout`.
    /// Returns [`SmrpError::AuthenticationFailure`] if the peer's reply fails
    /// Ed25519 or AEAD verification.
    pub async fn request_key_update(&mut self) -> Result<(), SmrpError> {
        self.rekey_counter += 1;
        let counter = self.rekey_counter;
        let eph = EphemeralKeypair::generate()?;
        let payload = build_key_update_payload(&eph, &self.sign_key, self.session_id, counter);
        let hdr = SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::KeyUpdate,
            flags: Flags::default(),
            reserved: 0,
            session_id: self.session_id,
            sequence_number: counter,
            ack_number: self.recv_seq,
            timestamp_us: timestamp_us(),
            payload_len: payload.len() as u16,
            frag_id: 0, frag_index: 0, frag_count: 0,
            recv_window: self.advertised_recv_window(),
            stream_id: 0,
        };
        transport::send_raw(&self.socket, self.peer_addr, &hdr, &payload).await?;
        self.pending_rekey = Some(eph);

        // Block until KEY_UPDATE_ACK arrives and new keys are installed.
        let timeout = self.cfg.recv_timeout;
        time::timeout(timeout, self.wait_key_update_ack(counter))
            .await
            .map_err(|_| SmrpError::HandshakeTimeout)?
    }

    /// Sends FIN, waits up to `cfg.fin_ack_timeout` for `FIN_ACK`, then releases.
    ///
    /// # Errors
    /// Returns [`SmrpError::InternalError`] on socket failure sending the FIN.
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

    /// Sends an authenticated control packet with a 16-byte Poly1305 MAC tag.
    ///
    /// Assigns the next `ctrl_send_seq` to `hdr.sequence_number` and sets
    /// `hdr.payload_len = AUTH_TAG_LEN` before sealing.
    async fn send_ctrl_authenticated(&mut self, mut hdr: SmrpHeader) -> Result<(), SmrpError> {
        let ctrl_seq = self.ctrl_send_seq;
        self.ctrl_send_seq += 1;
        hdr.sequence_number = ctrl_seq;
        hdr.payload_len = AUTH_TAG_LEN as u16;
        hdr.recv_window = self.advertised_recv_window();
        let aad = serialize_hdr(&hdr);
        let nonce = make_nonce(&self.ctrl_send_nonce_prefix, ctrl_seq);
        let tag = self.send_key.seal(&nonce, &aad, &[])?;
        transport::send_raw(&self.socket, self.peer_addr, &hdr, &tag).await
    }

    async fn send_fin_flag(&mut self) -> Result<(), SmrpError> {
        let mut flags = Flags::default();
        flags.0 |= Flags::FIN;
        self.send_ctrl_authenticated(SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::Fin,
            flags,
            reserved: 0,
            session_id: self.session_id,
            sequence_number: 0,
            ack_number: self.recv_seq,
            timestamp_us: timestamp_us(),
            payload_len: 0,
            frag_id: 0, frag_index: 0, frag_count: 0, recv_window: 0,
            stream_id: 0,
        })
        .await
    }

    async fn send_fin_ack(&mut self, ack_seq: u64) -> Result<(), SmrpError> {
        self.send_ctrl_authenticated(SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::FinAck,
            flags: Flags::default(),
            reserved: 0,
            session_id: self.session_id,
            sequence_number: 0,
            ack_number: ack_seq,
            timestamp_us: timestamp_us(),
            payload_len: 0,
            frag_id: 0, frag_index: 0, frag_count: 0, recv_window: 0,
            stream_id: 0,
        })
        .await
    }

    async fn send_ack(&mut self, ack_seq: u64) -> Result<(), SmrpError> {
        self.send_ctrl_authenticated(SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::Ack,
            flags: Flags::default(),
            reserved: 0,
            session_id: self.session_id,
            sequence_number: 0,
            ack_number: ack_seq,
            timestamp_us: timestamp_us(),
            payload_len: 0,
            frag_id: 0, frag_index: 0, frag_count: 0, recv_window: 0,
            stream_id: 0,
        })
        .await
    }

    async fn send_keepalive_ack(&mut self) -> Result<(), SmrpError> {
        self.send_ctrl_authenticated(SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::KeepaliveAck,
            flags: Flags::default(),
            reserved: 0,
            session_id: self.session_id,
            sequence_number: 0,
            ack_number: self.recv_seq,
            timestamp_us: timestamp_us(),
            payload_len: 0,
            frag_id: 0, frag_index: 0, frag_count: 0, recv_window: 0,
            stream_id: 0,
        })
        .await
    }

    /// Sends PONG in reply to a PING.
    /// `ping_seq` is echoed into `ack_number`; `ping_ts` is echoed into `timestamp_us`
    /// so the initiator can compute RTT without clock synchronisation.
    async fn send_pong(&mut self, ping_seq: u64, ping_ts: u64) -> Result<(), SmrpError> {
        self.send_ctrl_authenticated(SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::Pong,
            flags: Flags::default(),
            reserved: 0,
            session_id: self.session_id,
            sequence_number: 0,
            ack_number: ping_seq,
            timestamp_us: ping_ts,
            payload_len: 0,
            frag_id: 0, frag_index: 0, frag_count: 0, recv_window: 0,
            stream_id: 0,
        })
        .await
    }

    /// Sends a PATH_RESPONSE containing the 8-byte challenge nonce back to the peer.
    async fn send_path_response(&self, nonce: &[u8]) -> Result<(), SmrpError> {
        let hdr = SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::PathResponse,
            flags: Flags::default(),
            reserved: 0,
            session_id: self.session_id,
            sequence_number: 0,
            ack_number: self.recv_seq,
            timestamp_us: timestamp_us(),
            payload_len: nonce.len() as u16,
            frag_id: 0, frag_index: 0, frag_count: 0, recv_window: 0,
            stream_id: 0,
        };
        transport::send_raw(&self.socket, self.peer_addr, &hdr, nonce).await
    }

    /// Sends `data` on the logical stream identified by `stream_id`.
    ///
    /// A `stream_id` of `0` is the default stream and is equivalent to [`send`](Self::send).
    /// Non-zero stream IDs allow logical separation of application data without
    /// separate connections.
    ///
    /// # Errors
    /// Same as [`send`](Self::send).
    pub async fn send_on_stream(&mut self, stream_id: u16, data: &[u8]) -> Result<(), SmrpError> {
        let effective = self.effective_payload;
        let max_fragments: usize = 255;
        if data.len() > max_fragments * effective {
            return Err(SmrpError::PayloadTooLarge);
        }
        if data.len() <= effective {
            self.send_fragment_on_stream(data, None, stream_id).await
        } else {
            let chunks: Vec<&[u8]> = data.chunks(effective).collect();
            let frag_count = chunks.len() as u8;
            let frag_id = self.frag_send_id;
            self.frag_send_id = self.frag_send_id.wrapping_add(1);
            let total_len = data.len() as u64;
            for (i, chunk) in chunks.into_iter().enumerate() {
                self.send_fragment_on_stream(chunk, Some((frag_id, i as u8, frag_count)), stream_id)
                    .await?;
            }
            self.metrics.bytes_sent.fetch_add(total_len, Ordering::Relaxed);
            Ok(())
        }
    }

    /// Registers a receive channel for `stream_id` and returns a receiver.
    ///
    /// DATA packets arriving on `stream_id` are routed to the returned
    /// `mpsc::Receiver` rather than the default `recv()` path.
    ///
    /// # Errors
    /// Returns [`SmrpError::TooManyStreams`] if `stream_id >= cfg.max_streams`.
    pub fn open_stream(&mut self, stream_id: u16) -> Result<mpsc::Receiver<Vec<u8>>, SmrpError> {
        if stream_id == 0 || stream_id >= self.cfg.max_streams {
            return Err(SmrpError::TooManyStreams);
        }
        let (tx, rx) = mpsc::channel(self.cfg.session_channel_capacity);
        self.stream_txs.insert(stream_id, tx);
        Ok(rx)
    }

    async fn send_fragment_on_stream(
        &mut self,
        data: &[u8],
        frag_info: Option<(u16, u8, u8)>,
        stream_id: u16,
    ) -> Result<(), SmrpError> {
        // Same as send_fragment but uses the caller-specified stream_id.
        let notify = Arc::clone(&self.window_notify);
        loop {
            let notified = notify.notified();
            {
                let state = self.retransmit_buf.lock().await;
                let effective_window = state.cwnd.min(state.peer_recv_window as usize);
                if state.pending.len() < effective_window {
                    break;
                }
            }
            notified.await;
        }
        self.pace_wait(data.len()).await;

        let seq = self.send_seq;
        let nonce = make_nonce(&self.data_send_nonce_prefix, seq);
        let (flags, frag_id, frag_index, frag_count) = match frag_info {
            Some((id, idx, cnt)) => {
                let mut f = Flags::default();
                f.0 |= Flags::FRAGMENT;
                (f, id, idx, cnt)
            }
            None => (Flags::default(), 0, 0, 0),
        };
        let payload_len = (data.len() + AUTH_TAG_LEN) as u16;
        let hdr = SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::Data,
            flags,
            reserved: 0,
            session_id: self.session_id,
            sequence_number: seq,
            ack_number: self.recv_seq,
            timestamp_us: timestamp_us(),
            payload_len,
            frag_id,
            frag_index,
            frag_count,
            recv_window: self.advertised_recv_window(),
            stream_id,
        };
        let aad = data_aad(&hdr);
        let ciphertext = self.send_key.seal(&nonce, &aad, data)?;
        transport::send_raw(&self.socket, self.peer_addr, &hdr, &ciphertext).await?;
        self.send_seq += 1;
        self.retransmit_buf.lock().await.pending.insert(seq, RetransmitEntry {
            header: hdr,
            ciphertext,
            sent_at: Instant::now(),
            retries: 0,
        });
        if frag_info.is_none() {
            self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.metrics.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        } else {
            self.metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Decrypts and authenticates a control-packet payload using the recv ctrl key.
    ///
    /// For auth-only packets (Fin, Ack, Ping, …) the payload is just the 16-byte
    /// Poly1305 tag; `open` returns empty bytes. For `SackAck` the payload is
    /// sack-block data + tag; `open` returns the block data.
    fn open_ctrl_payload(&self, hdr: &SmrpHeader, payload: &[u8]) -> Result<Vec<u8>, SmrpError> {
        if payload.len() < AUTH_TAG_LEN {
            return Err(SmrpError::MalformedHeader);
        }
        let nonce = make_nonce(&self.ctrl_recv_nonce_prefix, hdr.sequence_number);
        let aad = serialize_hdr(hdr);
        self.recv_key
            .open(&nonce, &aad, payload)
            .inspect_err(|_| {
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            })
    }

    /// Removes all retransmit-pending entries with seq ≤ `ack_n` (cumulative ACK).
    async fn process_cumulative_ack(&mut self, ack_n: u64) {
        if ack_n == 0 {
            return;
        }
        let mut buf = self.retransmit_buf.lock().await;
        // Collect keys to remove; BTreeMap iterates in sorted order.
        let to_remove: Vec<u64> = buf.pending.range(..=ack_n).map(|(&k, _)| k).collect();
        let mut any_removed = false;
        for seq in to_remove {
            if let Some(entry) = buf.pending.remove(&seq) {
                if entry.retries == 0 {
                    #[allow(clippy::cast_possible_truncation)]
                    buf.rtt.update(entry.sent_at.elapsed().as_micros() as u64);
                }
                any_removed = true;
            }
        }
        // Clear sacked entries that the cumulative ACK has now covered.
        buf.sacked.retain(|&s| s > ack_n);

        if any_removed {
            // AIMD: one window-open event per ACK batch.
            if buf.cwnd < buf.ssthresh {
                buf.cwnd = buf.cwnd.saturating_add(1);
            } else {
                buf.ca_acks = buf.ca_acks.saturating_add(1);
                if buf.ca_acks >= buf.cwnd {
                    buf.cwnd = buf.cwnd.saturating_add(1);
                    buf.ca_acks = 0;
                }
            }
            drop(buf);
            self.window_notify.notify_one();
        }
    }

    /// Builds and sends a `SackAck` with the current cumulative `recv_seq` and
    /// SACK blocks derived from the out-of-order `recv_buf`.
    async fn send_sack(&mut self) -> Result<(), SmrpError> {
        let blocks = self.build_sack_blocks();
        let mut sack_data: Vec<u8> = Vec::with_capacity(blocks.len() * 16);
        for (start, end) in &blocks {
            sack_data.extend_from_slice(&start.to_be_bytes());
            sack_data.extend_from_slice(&end.to_be_bytes());
        }

        let ctrl_seq = self.ctrl_send_seq;
        self.ctrl_send_seq += 1;
        let payload_len = (sack_data.len() + AUTH_TAG_LEN) as u16;
        let hdr = SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::SackAck,
            flags: Flags::default(),
            reserved: 0,
            session_id: self.session_id,
            sequence_number: ctrl_seq,
            ack_number: self.recv_seq,
            timestamp_us: timestamp_us(),
            payload_len,
            frag_id: 0,
            frag_index: 0,
            frag_count: 0,
            recv_window: self.advertised_recv_window(),
            stream_id: 0,
        };
        let nonce = make_nonce(&self.ctrl_send_nonce_prefix, ctrl_seq);
        let aad = serialize_hdr(&hdr);
        let ciphertext = self.send_key.seal(&nonce, &aad, &sack_data)?;
        transport::send_raw(&self.socket, self.peer_addr, &hdr, &ciphertext).await
    }

    /// Compacts `recv_buf` keys into contiguous `(start, end)` ranges for SACK.
    fn build_sack_blocks(&self) -> Vec<(u64, u64)> {
        let mut blocks: Vec<(u64, u64)> = Vec::new();
        let max = self.cfg.max_sack_blocks;
        let mut range: Option<(u64, u64)> = None;
        for &seq in self.recv_buf.keys() {
            if blocks.len() >= max {
                break;
            }
            match range {
                None => range = Some((seq, seq)),
                Some((s, e)) if seq == e + 1 => range = Some((s, seq)),
                Some(r) => {
                    blocks.push(r);
                    if blocks.len() < max {
                        range = Some((seq, seq));
                    } else {
                        range = None;
                        break;
                    }
                }
            }
        }
        if let Some(r) = range {
            if blocks.len() < max {
                blocks.push(r);
            }
        }
        blocks
    }

    /// Returns the number of free slots in `recv_buf` as the advertised window.
    #[allow(clippy::cast_possible_truncation)]
    fn advertised_recv_window(&self) -> u16 {
        self.recv_buf_limit
            .saturating_sub(self.recv_buf.len())
            .min(u16::MAX as usize) as u16
    }

    async fn wait_fin_ack(&mut self) {
        loop {
            let Some(msg) = self.data_rx.recv().await else {
                return;
            };
            let (hdr, payload) = match msg {
                SessionMsg::Shutdown => return,
                SessionMsg::Packet(h, p) => (h, p),
            };
            if hdr.packet_type == PacketType::FinAck
                && self.open_ctrl_payload(&hdr, &payload).is_ok()
            {
                return;
            }
        }
    }

    async fn wait_key_update_ack(&mut self, counter: u64) -> Result<(), SmrpError> {
        loop {
            let Some(msg) = self.data_rx.recv().await else {
                return Err(SmrpError::InternalError);
            };
            let (hdr, payload) = match msg {
                SessionMsg::Shutdown => return Err(SmrpError::InternalError),
                SessionMsg::Packet(h, p) => (h, p),
            };
            if hdr.packet_type != PacketType::KeyUpdateAck {
                continue;
            }
            if hdr.sequence_number != counter {
                continue;
            }

            let our_eph = self.pending_rekey.take().ok_or(SmrpError::InternalError)?;
            let peer_eph_pub =
                parse_key_update_payload(&payload, &self.peer_sign_pub, self.session_id, counter)
                    .inspect_err(|_| {
                    self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                })?;

            let shared = our_eph.agree(&peer_eph_pub)?;
            self.install_rekey_keys(&shared, counter)?;
            debug!(
                "session {:?}: KEY_UPDATE complete (initiator) counter={counter}",
                self.session_id
            );
            return Ok(());
        }
    }

    async fn handle_key_update(&mut self, counter: u64, payload: &[u8]) {
        if counter <= self.peer_rekey_counter {
            return; // replay / retransmit of already-processed rekey
        }
        // Save the current recv_key before rotation so we can still decrypt DATA
        // packets that the initiator sent before it received KEY_UPDATE_ACK.
        // Cleared once key installation completes in the match arm below.
        // We don't save a deep-copy (ring keys aren't Clone), so we derive a
        // fresh SessionKey from the same raw bytes if needed by buffering the
        // already-decrypted plaintext instead.

        let peer_eph_pub = match parse_key_update_payload(
            payload,
            &self.peer_sign_pub,
            self.session_id,
            counter,
        ) {
            Ok(p) => p,
            Err(e) => {
                self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                warn!("KEY_UPDATE from {:?} rejected: {e}", self.session_id);
                return;
            }
        };
        let our_eph = match EphemeralKeypair::generate() {
            Ok(e) => e,
            Err(e) => {
                warn!("KEY_UPDATE eph gen failed: {e}");
                return;
            }
        };
        let ack_payload =
            build_key_update_payload(&our_eph, &self.sign_key, self.session_id, counter);

        // Perform DH agree BEFORE sending the ACK.
        // If agree fails, we send nothing and the initiator will timeout —
        // preventing the initiator from installing keys we cannot match.
        let shared = match our_eph.agree(&peer_eph_pub) {
            Ok(s) => s,
            Err(e) => {
                warn!("KEY_UPDATE X25519 agree failed: {e}");
                return;
            }
        };

        let ack_hdr = SmrpHeader {
            magic: SMRP_MAGIC,
            version: SMRP_VERSION,
            packet_type: PacketType::KeyUpdateAck,
            flags: Flags::default(),
            reserved: 0,
            session_id: self.session_id,
            sequence_number: counter,
            ack_number: self.recv_seq,
            timestamp_us: timestamp_us(),
            payload_len: ack_payload.len() as u16,
            frag_id: 0, frag_index: 0, frag_count: 0,
            recv_window: self.advertised_recv_window(),
            stream_id: 0,
        };
        if let Err(e) =
            transport::send_raw(&self.socket, self.peer_addr, &ack_hdr, &ack_payload).await
        {
            warn!("KEY_UPDATE_ACK send failed: {e}");
            return;
        }

        // Save old recv_key so we can decrypt DATA packets that were in-flight
        // from the initiator (sent before it received our KEY_UPDATE_ACK and
        // installed the new keys).  We drain these after installing new keys.
        // SAFETY: pre_rekey_recv_key is only set while handling a single KEY_UPDATE;
        // cleared in the drain below.
        let old_recv_key_bytes: Option<SessionKey> = None; // placeholder; see install
        let _ = old_recv_key_bytes;
        match self.install_rekey_keys(&shared, counter) {
            Ok(()) => {
                self.peer_rekey_counter = counter;
                // Drain buffered DATA that arrived during the rekey window,
                // decrypted with the old key (already plaintext in buffered_rekey_data).
                let buffered = std::mem::take(&mut self.buffered_rekey_data);
                for (seq, plaintext) in buffered {
                    if self.recv_buf.len() < self.recv_buf_limit {
                        // Re-inject as if it just arrived; use a dummy header.
                        self.recv_buf.insert(seq, (
                            SmrpHeader {
                                magic: SMRP_MAGIC, version: SMRP_VERSION,
                                packet_type: PacketType::Data, flags: Flags::default(),
                                reserved: 0, session_id: self.session_id,
                                sequence_number: seq, ack_number: 0,
                                timestamp_us: 0, payload_len: 0,
                                frag_id: 0, frag_index: 0, frag_count: 1,
                                recv_window: 0, stream_id: 0,
                            },
                            plaintext,
                        ));
                    }
                }
                self.pre_rekey_recv_key_bytes = None;
                debug!(
                    "session {:?}: KEY_UPDATE complete (responder) counter={counter}",
                    self.session_id
                );
            }
            Err(e) => {
                warn!("KEY_UPDATE key install failed: {e}");
            }
        }
    }

    fn install_rekey_keys(&mut self, shared: &[u8; 32], counter: u64) -> Result<(), SmrpError> {
        let (c2s, s2c) = derive_rekey_keys(shared, self.session_id, counter)?;
        let data_c2s_prefix = derive_nonce_prefix(&c2s, b"smrp-v1-data-nonce-c2s")?;
        let data_s2c_prefix = derive_nonce_prefix(&s2c, b"smrp-v1-data-nonce-s2c")?;
        let ctrl_c2s_prefix = derive_nonce_prefix(&c2s, b"smrp-v1-ctrl-nonce-c2s")?;
        let ctrl_s2c_prefix = derive_nonce_prefix(&s2c, b"smrp-v1-ctrl-nonce-s2c")?;
        // Save the current recv key bytes so handle_key_update's responder path
        // can attempt decryption of DATA packets still encrypted with the old key.
        self.pre_rekey_recv_key_bytes = Some(self.recv_key_bytes);
        if self.is_client {
            self.send_key = SessionKey::from_raw(&c2s)?;
            let new_recv = SessionKey::from_raw(&s2c)?;
            self.recv_key_bytes = *new_recv.raw_bytes();
            self.recv_key = new_recv;
            self.data_send_nonce_prefix = data_c2s_prefix;
            self.data_recv_nonce_prefix = data_s2c_prefix;
            self.ctrl_send_nonce_prefix = ctrl_c2s_prefix;
            self.ctrl_recv_nonce_prefix = ctrl_s2c_prefix;
        } else {
            self.send_key = SessionKey::from_raw(&s2c)?;
            let new_recv = SessionKey::from_raw(&c2s)?;
            self.recv_key_bytes = *new_recv.raw_bytes();
            self.recv_key = new_recv;
            self.data_send_nonce_prefix = data_s2c_prefix;
            self.data_recv_nonce_prefix = data_c2s_prefix;
            self.ctrl_send_nonce_prefix = ctrl_s2c_prefix;
            self.ctrl_recv_nonce_prefix = ctrl_c2s_prefix;
        }
        Ok(())
    }

    // --- Packet dispatch (used by SmrpReceiver::recv_inner) ---

    /// Processes a single received packet. Returns `Err` on auth failure,
    /// or `Ok(())` to continue (data may be appended to `deliver_queue`).
    async fn process_one_packet(
        &mut self,
        hdr: SmrpHeader,
        payload: Vec<u8>,
    ) -> Result<(), SmrpError> {
        match hdr.packet_type {
            PacketType::Data => {
                let seq = hdr.sequence_number;
                if self.recv_replay.can_accept(seq).is_err() {
                    self.metrics.replay_detections.fetch_add(1, Ordering::Relaxed);
                    let _ = self.send_ack(self.recv_seq).await;
                    return Ok(());
                }
                let nonce = make_nonce(&self.data_recv_nonce_prefix, seq);
                let aad = data_aad(&hdr);
                let plaintext = match self.recv_key.open(&nonce, &aad, &payload) {
                    Ok(p) => p,
                    Err(_) => {
                        if let Some(old_bytes) = self.pre_rekey_recv_key_bytes {
                            let old_key = SessionKey::from_raw(&old_bytes)
                                .unwrap_or_else(|_| unreachable!());
                            if let Ok(p) = old_key.open(&nonce, &aad, &payload) {
                                self.buffered_rekey_data.push((seq, p));
                                let _ = self.send_ack(self.recv_seq).await;
                                return Ok(());
                            }
                        }
                        self.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
                        return Err(SmrpError::AuthenticationFailure);
                    }
                };
                self.recv_replay.mark_seen(seq);
                if self.recv_buf.len() < self.recv_buf_limit {
                    self.recv_buf.insert(seq, (hdr, plaintext));
                }
                while let Some((pkt_hdr, raw)) = self.recv_buf.remove(&self.next_deliver_seq) {
                    self.recv_seq = self.next_deliver_seq;
                    self.next_deliver_seq += 1;
                    self.metrics.packets_received.fetch_add(1, Ordering::Relaxed);
                    let assembled_data = if pkt_hdr.flags.fragment() {
                        let frag_complete = {
                            let entry = self.reassembly
                                .entry(pkt_hdr.frag_id)
                                .or_insert_with(|| FragmentAssembly::new(pkt_hdr.frag_count));
                            entry.insert(pkt_hdr.frag_index, raw)
                        };
                        if frag_complete {
                            Some((pkt_hdr.stream_id, self.reassembly.remove(&pkt_hdr.frag_id).unwrap().assemble()))
                        } else {
                            None
                        }
                    } else {
                        Some((pkt_hdr.stream_id, raw))
                    };
                    if let Some((stream_id, msg)) = assembled_data {
                        self.metrics.bytes_received.fetch_add(msg.len() as u64, Ordering::Relaxed);
                        if stream_id == 0 {
                            self.deliver_queue.push_back(msg);
                        } else if let Some(tx) = self.stream_txs.get(&stream_id) {
                            let _ = tx.try_send(msg);
                        }
                    }
                }
                if self.recv_buf.is_empty() {
                    let _ = self.send_ack(self.recv_seq).await;
                } else {
                    let _ = self.send_sack().await;
                }
            }
            PacketType::Ack => {
                if self.open_ctrl_payload(&hdr, &payload).is_err() { return Ok(()); }
                {
                    let mut buf = self.retransmit_buf.lock().await;
                    buf.peer_recv_window = hdr.recv_window;
                    if hdr.flags.ce() {
                        buf.ssthresh = (buf.cwnd / 2).max(2);
                        buf.cwnd = buf.ssthresh;
                        buf.ca_acks = 0;
                    }
                }
                self.process_cumulative_ack(hdr.ack_number).await;
            }
            PacketType::SackAck => {
                let Ok(sack_data) = self.open_ctrl_payload(&hdr, &payload) else { return Ok(()); };
                {
                    let mut buf = self.retransmit_buf.lock().await;
                    buf.peer_recv_window = hdr.recv_window;
                    let blocks = parse_sack_blocks(&sack_data);
                    for (start, end) in blocks {
                        for seq in start..=end { buf.sacked.insert(seq); }
                    }
                    buf.sacked.retain(|&s| s > hdr.ack_number);
                }
                self.process_cumulative_ack(hdr.ack_number).await;
            }
            PacketType::Fin => {
                if self.open_ctrl_payload(&hdr, &payload).is_err() { return Ok(()); }
                let _ = self.send_fin_ack(hdr.sequence_number).await;
                self.mark_closed();
            }
            PacketType::Keepalive => {
                let now_us = timestamp_us();
                if now_us.saturating_sub(self.last_keepalive_ack_us) >= 1_000_000 {
                    let _ = self.send_keepalive_ack().await;
                    self.last_keepalive_ack_us = now_us;
                }
            }
            PacketType::Ping => {
                if self.open_ctrl_payload(&hdr, &payload).is_err() { return Ok(()); }
                let _ = self.send_pong(hdr.sequence_number, hdr.timestamp_us).await;
            }
            PacketType::Pong => {
                if self.open_ctrl_payload(&hdr, &payload).is_err() { return Ok(()); }
                let rtt_us = timestamp_us().saturating_sub(hdr.timestamp_us);
                if rtt_us > 0 && rtt_us < 60_000_000 {
                    self.retransmit_buf.lock().await.rtt.update(rtt_us);
                }
            }
            PacketType::KeyUpdate => {
                self.handle_key_update(hdr.sequence_number, &payload).await;
            }
            PacketType::PathChallenge => {
                if payload.len() >= 8 && self.cfg.migration_enabled {
                    let _ = self.send_path_response(&payload[..8]).await;
                }
            }
            PacketType::PathResponse => {
                if let Some(nonce) = self.pending_migration_nonce {
                    if payload.len() >= 8 && payload[..8] == nonce {
                        self.pending_migration_nonce = None;
                    }
                }
            }
            _ => {}
        }
        Ok(())
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

    /// Returns the peer's 32-byte Ed25519 public key, verified during the handshake.
    #[must_use]
    pub fn peer_identity(&self) -> &[u8; 32] {
        &self.peer_sign_pub
    }

    /// Consumes this connection and returns an independent `(sender, receiver)` pair.
    ///
    /// Both halves share the underlying session state via an `Arc<Mutex>`. The
    /// receiver exclusively owns the incoming packet channel, so `receiver.recv()`
    /// does **not** hold the lock while waiting for the next packet — it only
    /// acquires it briefly to process each arrived message. This means `sender.send()`
    /// can proceed concurrently while the receiver is blocked waiting.
    #[must_use]
    pub fn into_split(self) -> (SmrpSender, SmrpReceiver) {
        let data_rx = self.data_rx;
        let dead_rx = self.dead_rx;
        // Build a "headless" connection (data_rx / dead_rx replaced with dummy channels).
        let (dummy_tx, dummy_rx) = mpsc::channel(1);
        let (dummy_dead_tx, dummy_dead_rx) = mpsc::channel(1);
        // Keep dummy channels alive so the inner mutex holder can send without panic.
        let inner_conn = SmrpConnection {
            data_rx: dummy_rx,
            dead_rx: dummy_dead_rx,
            ..self
        };
        // Immediately drop the dummy senders so the inner recv channels are closed;
        // the split halves use their own channels.
        drop(dummy_tx);
        drop(dummy_dead_tx);
        let inner = Arc::new(tokio::sync::Mutex::new(inner_conn));
        let sender = SmrpSender { inner: Arc::clone(&inner) };
        let receiver = SmrpReceiver { inner, data_rx, dead_rx };
        (sender, receiver)
    }
}

// ---------------------------------------------------------------------------
// Split halves
// ---------------------------------------------------------------------------

/// The send half of a split [`SmrpConnection`].
///
/// Obtained from [`SmrpConnection::into_split`]. Can be held by one task
/// while [`SmrpReceiver`] is held by another, allowing concurrent send and recv.
pub struct SmrpSender {
    inner: Arc<tokio::sync::Mutex<SmrpConnection>>,
}

impl SmrpSender {
    /// Encrypts `data` and sends it; see [`SmrpConnection::send`] for details.
    ///
    /// # Errors
    /// Same as [`SmrpConnection::send`].
    pub async fn send(&self, data: &[u8]) -> Result<(), SmrpError> {
        self.inner.lock().await.send(data).await
    }

    /// Sends `data` on a specific logical stream; see [`SmrpConnection::send_on_stream`].
    ///
    /// # Errors
    /// Same as [`SmrpConnection::send_on_stream`].
    pub async fn send_on_stream(&self, stream_id: u16, data: &[u8]) -> Result<(), SmrpError> {
        self.inner.lock().await.send_on_stream(stream_id, data).await
    }

    /// Initiates a key update; see [`SmrpConnection::request_key_update`].
    ///
    /// # Errors
    /// Same as [`SmrpConnection::request_key_update`].
    pub async fn request_key_update(&self) -> Result<(), SmrpError> {
        self.inner.lock().await.request_key_update().await
    }

    /// Performs a graceful session close; see [`SmrpConnection::close`].
    ///
    /// # Errors
    /// Same as [`SmrpConnection::close`].
    pub async fn close(self) -> Result<(), SmrpError> {
        let mut guard = self.inner.lock().await;
        guard.send_fin_flag().await?;
        let timeout = guard.cfg.fin_ack_timeout;
        drop(guard);
        time::sleep(timeout).await; // best-effort wait for FIN_ACK
        Ok(())
    }
}

/// The receive half of a split [`SmrpConnection`].
///
/// Obtained from [`SmrpConnection::into_split`]. The receiver exclusively owns
/// the incoming packet channel so `recv()` can block without holding the shared lock.
pub struct SmrpReceiver {
    inner: Arc<tokio::sync::Mutex<SmrpConnection>>,
    /// Exclusively owned by this half; the shared inner conn has a closed dummy channel.
    data_rx: mpsc::Receiver<SessionMsg>,
    dead_rx: mpsc::Receiver<()>,
}

impl SmrpReceiver {
    /// Waits for the next DATA message; see [`SmrpConnection::recv`] for details.
    ///
    /// # Errors
    /// Same as [`SmrpConnection::recv`].
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, SmrpError> {
        let deadline = {
            let inner = self.inner.lock().await;
            inner.cfg.recv_timeout
        };
        self.recv_timeout(deadline).await
    }

    /// Like [`recv`](Self::recv) but with a caller-supplied deadline.
    ///
    /// # Errors
    /// Same as [`SmrpConnection::recv_timeout`].
    pub async fn recv_timeout(&mut self, deadline: Duration) -> Result<Option<Vec<u8>>, SmrpError> {
        time::timeout(deadline, self.recv_inner()).await
            .map_err(|_| SmrpError::HandshakeTimeout)?
    }

    async fn recv_inner(&mut self) -> Result<Option<Vec<u8>>, SmrpError> {
        loop {
            // Fast path: deliver from the queue without blocking (hold lock briefly).
            {
                let mut inner = self.inner.lock().await;
                if let Some(data) = inner.deliver_queue.pop_front() {
                    return Ok(Some(data));
                }
            }

            // Wait for the next packet without holding the lock.
            tokio::select! {
                msg = self.data_rx.recv() => {
                    let Some(msg) = msg else { return Ok(None); };
                    let mut inner = self.inner.lock().await;
                    inner.last_recv_us.store(timestamp_us(), Ordering::Relaxed);
                    match msg {
                        SessionMsg::Shutdown => {
                            let _ = inner.send_fin_flag().await;
                            inner.mark_closed();
                            return Ok(None);
                        }
                        SessionMsg::Packet(hdr, payload) => {
                            // Delegate to the inner connection's packet dispatch.
                            // Re-insert into inner.data_rx is not possible; instead,
                            // we call the per-packet processing method directly.
                            inner.process_one_packet(hdr, payload).await?;
                        }
                    }
                }
                _ = self.dead_rx.recv() => {
                    warn!("split receiver: session declared dead; closing");
                    return Ok(None);
                }
            }
        }
    }

    /// Opens a stream channel; see [`SmrpConnection::open_stream`].
    ///
    /// # Errors
    /// Same as [`SmrpConnection::open_stream`].
    pub async fn open_stream(&self, stream_id: u16) -> Result<mpsc::Receiver<Vec<u8>>, SmrpError> {
        self.inner.lock().await.open_stream(stream_id)
    }
}

// ---------------------------------------------------------------------------
// DATA packet AAD helper
// ---------------------------------------------------------------------------

/// Full 54-byte header serialized as AEAD additional data, with `timestamp_us` zeroed.
///
/// Zeroing the timestamp allows the retransmit task to refresh it without
/// breaking AEAD verification on the peer.
fn data_aad(hdr: &SmrpHeader) -> [u8; HEADER_LEN] {
    let mut h = hdr.clone();
    h.timestamp_us = 0;
    serialize_hdr(&h)
}

// ---------------------------------------------------------------------------
// Keepalive task
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn spawn_keepalive_task(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    session_id: SessionId,
    mut stop_rx: mpsc::Receiver<()>,
    last_recv_us: Arc<AtomicU64>,
    dead_notify_tx: mpsc::Sender<()>,
    dead_session_tx: Option<mpsc::Sender<SessionId>>,
    metrics: Arc<SmrpMetrics>,
    closed: Arc<AtomicBool>,
    probe_interval: Duration,
    dead_threshold: Duration,
) {
    let dead_threshold_us = dead_threshold.as_micros() as u64;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = time::sleep(probe_interval) => {
                    let now_us  = timestamp_us();
                    let last_us = last_recv_us.load(Ordering::Relaxed);

                    if now_us.saturating_sub(last_us) >= dead_threshold_us {
                        warn!("session {session_id:?}: no traffic for {}s — evicting",
                              dead_threshold.as_secs());

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
                        frag_id: 0, frag_index: 0, frag_count: 0, recv_window: 0,
                        stream_id: 0,
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
// Retransmit task
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn spawn_retransmit_task(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    session_id: SessionId,
    buf: RetransmitBuf,
    mut stop_rx: mpsc::Receiver<()>,
    dead_notify_tx: mpsc::Sender<()>,
    metrics: Arc<SmrpMetrics>,
    max_retransmits: u32,
    check_interval: Duration,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = time::sleep(check_interval) => {
                    let mut state = buf.lock().await;
                    let rto = state.rtt.rto();
                    let now = Instant::now();

                    // Identify which entries need action.
                    let mut expired: Vec<u64> = Vec::new();
                    let mut dead = false;

                    for (&seq, entry) in &state.pending {
                        if state.sacked.contains(&seq) { continue; } // peer has it
                        if now.duration_since(entry.sent_at) < rto { continue; }
                        if entry.retries >= max_retransmits {
                            warn!("session {session_id:?}: max retransmits ({max_retransmits}) for seq={seq} — session dead");
                            dead = true;
                            break;
                        }
                        expired.push(seq);
                    }

                    if dead {
                        drop(state);
                        let _ = dead_notify_tx.try_send(());
                        break;
                    }

                    if expired.is_empty() { continue; }

                    // Treat any retransmit as a congestion signal (RFC 5681 §3.1):
                    // halve ssthresh and reset cwnd to 1.
                    state.ssthresh = (state.cwnd / 2).max(2);
                    state.cwnd     = 1;
                    state.ca_acks  = 0;

                    // Apply RTO backoff once per check cycle.
                    state.rtt.backoff();

                    // Collect what to re-send and update retry counters.
                    let mut sends: Vec<(SmrpHeader, Vec<u8>)> = Vec::with_capacity(expired.len());
                    for &seq in &expired {
                        if let Some(entry) = state.pending.get_mut(&seq) {
                            let mut hdr = entry.header.clone();
                            hdr.timestamp_us = timestamp_us(); // refresh timestamp
                            sends.push((hdr, entry.ciphertext.clone()));
                            entry.sent_at = now;
                            entry.retries += 1;
                        }
                    }

                    drop(state); // release lock before I/O

                    for (hdr, ciphertext) in sends {
                        if transport::send_raw(&socket, peer_addr, &hdr, &ciphertext).await.is_err() {
                            break;
                        }
                        metrics.packets_retransmitted.fetch_add(1, Ordering::Relaxed);
                    }
                }

                _ = stop_rx.recv() => {
                    debug!("session {session_id:?}: retransmit task stopping");
                    break;
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// KEY_UPDATE helpers
// ---------------------------------------------------------------------------

const KEY_UPDATE_PAYLOAD_LEN: usize = 32 + 32 + 64;

/// Builds a 128-byte `KEY_UPDATE` / `KEY_UPDATE_ACK` payload.
/// Layout: `eph_pub[32] || sign_pub[32] || sig[64]`
/// Signature covers: `session_id[8] || eph_pub[32] || counter_be[8]`.
fn build_key_update_payload(
    eph: &EphemeralKeypair,
    sign_key: &SigningKey,
    session_id: SessionId,
    counter: u64,
) -> Vec<u8> {
    let eph_pub = eph.public_key_bytes();
    let sign_pub = sign_key.public_key_bytes();
    let mut msg = Vec::with_capacity(8 + 32 + 8);
    msg.extend_from_slice(session_id.as_bytes());
    msg.extend_from_slice(eph_pub);
    msg.extend_from_slice(&counter.to_be_bytes());
    let sig = sign_key.sign(&msg);
    let mut payload = Vec::with_capacity(KEY_UPDATE_PAYLOAD_LEN);
    payload.extend_from_slice(eph_pub);
    payload.extend_from_slice(sign_pub);
    payload.extend_from_slice(&sig);
    payload
}

/// Parses and verifies a `KEY_UPDATE` / `KEY_UPDATE_ACK` payload.
/// Returns the peer's new ephemeral X25519 public key on success.
fn parse_key_update_payload(
    payload: &[u8],
    peer_sign_pub: &[u8; 32],
    session_id: SessionId,
    counter: u64,
) -> Result<[u8; 32], SmrpError> {
    if payload.len() < KEY_UPDATE_PAYLOAD_LEN {
        return Err(SmrpError::MalformedHeader);
    }
    let mut eph_pub = [0u8; 32];
    let mut sign_pub = [0u8; 32];
    let mut sig = [0u8; 64];
    eph_pub.copy_from_slice(&payload[0..32]);
    sign_pub.copy_from_slice(&payload[32..64]);
    sig.copy_from_slice(&payload[64..128]);

    // Reject if the identity key changed — we only accept rekeys from the pinned peer.
    if &sign_pub != peer_sign_pub {
        return Err(SmrpError::AuthenticationFailure);
    }

    let mut msg = Vec::with_capacity(8 + 32 + 8);
    msg.extend_from_slice(session_id.as_bytes());
    msg.extend_from_slice(&eph_pub);
    msg.extend_from_slice(&counter.to_be_bytes());
    ed25519_verify(peer_sign_pub, &msg, &sig)?;

    Ok(eph_pub)
}

/// Derives new send/receive key material from a rekey shared secret.
/// Returns `(c2s_raw, s2c_raw)`.
fn derive_rekey_keys(
    shared: &[u8; 32],
    session_id: SessionId,
    counter: u64,
) -> Result<([u8; 32], [u8; 32]), SmrpError> {
    let mut salt = [0u8; 16];
    salt[0..8].copy_from_slice(session_id.as_bytes());
    salt[8..16].copy_from_slice(&counter.to_be_bytes());
    let c2s = hkdf_sha256(shared, &salt, b"smrp-v1-rekey-c2s")?;
    let s2c = hkdf_sha256(shared, &salt, b"smrp-v1-rekey-s2c")?;
    Ok((c2s, s2c))
}

/// Decodes a SACK payload into `(start, end)` inclusive sequence-number ranges.
/// Each block is 16 bytes: `start_be8 || end_be8`. Truncates at byte boundary.
fn parse_sack_blocks(data: &[u8]) -> Vec<(u64, u64)> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i + 16 <= data.len() {
        let mut s = [0u8; 8];
        let mut e = [0u8; 8];
        s.copy_from_slice(&data[i..i + 8]);
        e.copy_from_slice(&data[i + 8..i + 16]);
        blocks.push((u64::from_be_bytes(s), u64::from_be_bytes(e)));
        i += 16;
    }
    blocks
}

// ---------------------------------------------------------------------------
// SmrpListener
// ---------------------------------------------------------------------------

/// Listens for inbound SMRP connections on a UDP port.
pub struct SmrpListener {
    local_addr: SocketAddr,
    new_conn_rx: mpsc::Receiver<SmrpConnection>,
    /// Drop or send on this to stop the dispatch loop.
    shutdown_tx: mpsc::Sender<()>,
    sessions: SessionMap,
    cfg: Arc<SmrpConfig>,
    metrics: Arc<SmrpMetrics>,
}

impl SmrpListener {
    /// Binds a UDP socket on `addr` using default configuration.
    ///
    /// # Errors
    /// Returns [`SmrpError::InternalError`] if the socket cannot be bound.
    pub async fn bind(addr: &str) -> Result<Self, SmrpError> {
        Self::bind_with_config(addr, Arc::new(SmrpConfig::default())).await
    }

    /// Binds a UDP socket on `addr` using a custom [`SmrpConfig`].
    ///
    /// Generates a fresh ephemeral signing key for this listener.
    /// To use a persistent identity key, call [`bind_with_config_and_key`](Self::bind_with_config_and_key).
    ///
    /// # Errors
    /// Returns [`SmrpError::InternalError`] if the socket cannot be bound or
    /// the signing key cannot be generated.
    pub async fn bind_with_config(addr: &str, cfg: Arc<SmrpConfig>) -> Result<Self, SmrpError> {
        let sign_key = SigningKey::generate()?;
        Self::bind_with_config_and_key(addr, cfg, sign_key).await
    }

    /// Binds a UDP socket on `addr` using a custom [`SmrpConfig`] and a
    /// caller-supplied signing key.
    ///
    /// Use this to load a persistent Ed25519 identity from disk so that
    /// clients can pin the server's public key fingerprint across restarts.
    ///
    /// # Errors
    /// Returns [`SmrpError::InternalError`] if the socket cannot be bound.
    pub async fn bind_with_config_and_key(
        addr: &str,
        cfg: Arc<SmrpConfig>,
        sign_key: SigningKey,
    ) -> Result<Self, SmrpError> {
        let socket = Arc::new(
            UdpSocket::bind(addr)
                .await
                .map_err(|_| SmrpError::InternalError)?,
        );
        let local_addr = socket.local_addr().map_err(|_| SmrpError::InternalError)?;
        let sign_key = Arc::new(sign_key);
        let sessions: SessionMap = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let metrics = Arc::new(SmrpMetrics::new());
        let (new_conn_tx, new_conn_rx) = mpsc::channel(cfg.accept_queue_capacity);
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        let (dead_sess_tx, dead_sess_rx) = mpsc::channel::<SessionId>(256);

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

        Ok(Self {
            local_addr,
            new_conn_rx,
            shutdown_tx,
            sessions,
            cfg,
            metrics,
        })
    }

    /// Waits for the next inbound connection.
    ///
    /// Returns `None` after [`shutdown`](Self::shutdown) is called.
    pub async fn accept(&mut self) -> Option<SmrpConnection> {
        self.new_conn_rx.recv().await
    }

    /// Returns the local address this listener is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns a shared handle to the listener's metrics counters.
    #[must_use]
    pub fn metrics(&self) -> Arc<SmrpMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Returns the active configuration.
    #[must_use]
    pub fn config(&self) -> Arc<SmrpConfig> {
        Arc::clone(&self.cfg)
    }

    /// Gracefully shuts down the listener.
    ///
    /// 1. Signals the dispatch loop to stop (no new connections accepted).
    /// 2. Drains the accept queue: each unaccepted `SmrpConnection` is closed
    ///    with an authenticated FIN so remote peers terminate promptly.
    /// 3. Injects a `Shutdown` signal into every accepted session channel so
    ///    their `recv_inner` sends an authenticated FIN and returns `Ok(None)`.
    pub async fn shutdown(mut self) {
        drop(self.shutdown_tx);

        // Close connections that were never accepted by the application.
        while let Ok(conn) = self.new_conn_rx.try_recv() {
            tokio::spawn(async move {
                let _ = conn.close().await;
            });
        }

        // Signal already-accepted sessions to close via their recv_inner loop.
        let map = self.sessions.lock().await;
        for entry in map.values() {
            let _ = entry.data_tx.try_send(SessionMsg::Shutdown);
        }
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
        Self {
            count: 0,
            window_start: Instant::now(),
        }
    }

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

// Spawns the per-HELLO async task that runs the server handshake and registers
// the new session. Extracted to keep `listener_dispatch` under the line limit.
#[allow(clippy::too_many_arguments)]
fn spawn_hello_handler(
    addr: SocketAddr,
    payload: Vec<u8>,
    sid: SessionId,
    socket: Arc<UdpSocket>,
    sign_key: Arc<SigningKey>,
    sessions: SessionMap,
    new_conn_tx: mpsc::Sender<SmrpConnection>,
    dead_sess_tx: mpsc::Sender<SessionId>,
    cfg: Arc<SmrpConfig>,
    metrics: Arc<SmrpMetrics>,
) {
    tokio::spawn(async move {
        let session =
            match handshake::server_handshake(&socket, addr, sid, &payload, &sign_key).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("handshake with {addr} failed: {e}");
                    return;
                }
            };

        let cap = cfg.session_channel_capacity;
        let (data_tx, data_rx) = mpsc::channel(cap);
        let conn_sid = session.id;

        let conn = match SmrpConnection::from_server_session(
            session,
            socket,
            data_rx,
            cfg,
            Arc::clone(&metrics),
            dead_sess_tx,
            Arc::clone(&sign_key),
        ) {
            Ok(c) => c,
            Err(e) => {
                warn!("connection assembly failed: {e}");
                return;
            }
        };

        metrics.sessions_active.fetch_add(1, Ordering::Relaxed);
        metrics.sessions_total.fetch_add(1, Ordering::Relaxed);

        sessions
            .lock()
            .await
            .insert(conn_sid, SessionEntry { data_tx });

        if new_conn_tx.send(conn).await.is_err() {
            sessions.lock().await.remove(&conn_sid);
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn listener_dispatch(
    socket: Arc<UdpSocket>,
    sign_key: Arc<SigningKey>,
    sessions: SessionMap,
    new_conn_tx: mpsc::Sender<SmrpConnection>,
    mut shutdown_rx: mpsc::Receiver<()>,
    dead_session_tx: mpsc::Sender<SessionId>,
    mut dead_sess_rx: mpsc::Receiver<SessionId>,
    cfg: Arc<SmrpConfig>,
    metrics: Arc<SmrpMetrics>,
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
                        let bucket = rate_limits.entry(addr.ip()).or_insert_with(RateBucket::new);
                        if !bucket.allow(cfg.hello_rate_limit) {
                            metrics.hello_drops_rate_limit.fetch_add(1, Ordering::Relaxed);
                            warn!("HELLO rate limit exceeded for {}", addr.ip());
                            continue;
                        }

                        let now_us  = timestamp_us();
                        let skew_us = cfg.hello_clock_skew.as_micros() as u64;
                        let ts = hdr.timestamp_us;
                        if ts.saturating_add(skew_us) < now_us || ts > now_us.saturating_add(skew_us) {
                            metrics.hello_drops_clock_skew.fetch_add(1, Ordering::Relaxed);
                            warn!("HELLO from {addr}: timestamp out of range");
                            continue;
                        }

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

                        spawn_hello_handler(
                            addr, payload, hdr.session_id,
                            Arc::clone(&socket), Arc::clone(&sign_key),
                            Arc::clone(&sessions), new_conn_tx.clone(),
                            dead_session_tx.clone(), Arc::clone(&cfg), Arc::clone(&metrics),
                        );
                    }

                    PacketType::Data | PacketType::Fin | PacketType::FinAck
                    | PacketType::Ack | PacketType::SackAck
                    | PacketType::Keepalive | PacketType::KeepaliveAck
                    | PacketType::Reset | PacketType::Ping | PacketType::Pong
                    | PacketType::KeyUpdate | PacketType::KeyUpdateAck
                    | PacketType::PathChallenge | PacketType::PathResponse => {
                        let mut map = sessions.lock().await;
                        let sid    = hdr.session_id;
                        let remove = if let Some(entry) = map.get(&sid) {
                            match entry.data_tx.try_send(SessionMsg::Packet(hdr, payload)) {
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
}

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
        frag_id: 0, frag_index: 0, frag_count: 0, recv_window: 0,
        stream_id: 0,
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

    async fn echo_server_with_key(key: SigningKey) -> (SocketAddr, SmrpListener) {
        let listener = SmrpListener::bind_with_config_and_key(
            "127.0.0.1:0",
            Arc::new(SmrpConfig::default()),
            key,
        )
        .await
        .unwrap();
        let addr = listener.local_addr();
        (addr, listener)
    }

    fn spawn_echo(mut listener: SmrpListener) {
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
    async fn fragmented_payload_roundtrip() {
        // MAX_PAYLOAD + 1 requires 2 fragments; the echo server reassembles and
        // re-sends it back as a single send(), which also fragments on the way back.
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        let data = vec![0x42u8; MAX_PAYLOAD + 1];
        conn.send(&data).await.unwrap();
        let reply = conn.recv().await.unwrap().unwrap();
        assert_eq!(reply, data);
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn too_many_fragments_rejected_locally() {
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();
        // 255 * MAX_PAYLOAD + 1 exceeds the 255-fragment limit.
        let huge = vec![0u8; 255 * MAX_PAYLOAD + 1];
        assert_eq!(
            conn.send(&huge).await.unwrap_err(),
            SmrpError::PayloadTooLarge
        );
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_sessions() {
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let handles: Vec<_> = (0u8..8)
            .map(|i| {
                let a = addr;
                tokio::spawn(async move {
                    let mut conn = SmrpConnection::connect(&a.to_string()).await.unwrap();
                    let msg = vec![i; 32];
                    conn.send(&msg).await.unwrap();
                    assert_eq!(conn.recv().await.unwrap().unwrap(), msg);
                    conn.close().await.unwrap();
                })
            })
            .collect();
        for h in handles {
            h.await.unwrap();
        }
    }

    // --- Timeouts ---

    #[tokio::test]
    async fn connect_timeout_fires() {
        let result = time::timeout(
            Duration::from_secs(12),
            SmrpConnection::connect("127.0.0.1:1"),
        )
        .await;
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
        tokio::time::sleep(Duration::from_millis(100)).await;
        listener.shutdown().await;
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
        )
        .await;
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
        tokio::time::sleep(Duration::from_millis(50)).await;
        let snap = m.snapshot();
        assert!(snap.sessions_total >= 1);
        assert!(snap.packets_received >= 1);
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
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    // --- Retransmit buffer cleared after ACK ---

    #[tokio::test]
    async fn retransmit_buffer_drained_after_ack() {
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();

        conn.send(b"drain test").await.unwrap();
        // After recv() the ACK has been processed.
        let _ = conn.recv().await.unwrap();

        // Give the ACK a moment to reach recv_inner's Ack branch.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let pending = conn.retransmit_buf.lock().await.pending.len();
        assert_eq!(pending, 0, "retransmit buffer should be empty after ACK");

        conn.close().await.unwrap();
    }

    // --- Persistent signing key ---

    #[tokio::test]
    async fn signing_key_pkcs8_roundtrip() {
        let key = SigningKey::generate().unwrap();
        let bytes = key.to_pkcs8().to_vec();
        let key2 = SigningKey::from_pkcs8(&bytes).unwrap();
        assert_eq!(key.public_key_bytes(), key2.public_key_bytes());
    }

    #[tokio::test]
    async fn bind_with_persistent_key() {
        let key = SigningKey::generate().unwrap();
        let pub_bytes = *key.public_key_bytes();
        let cfg = Arc::new(SmrpConfig::default());
        let listener = SmrpListener::bind_with_config_and_key("127.0.0.1:0", cfg, key)
            .await
            .unwrap();
        // Listener bound successfully with a pre-supplied key.
        assert!(listener.local_addr().port() > 0);
        drop(listener);
        // The same PKCS8 bytes produce the same public key.
        let _ = pub_bytes;
    }

    // --- Pinned server key ---

    #[tokio::test]
    async fn connect_with_pinned_key_accepts_correct_key() {
        let key = SigningKey::generate().unwrap();
        let pinned = *key.public_key_bytes();
        let (addr, listener) = echo_server_with_key(key).await;
        spawn_echo(listener);
        let conn = SmrpConnection::connect_with_pinned_server_key(&addr.to_string(), &pinned)
            .await
            .unwrap();
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn connect_with_pinned_key_rejects_wrong_key() {
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let wrong_key = [0u8; 32];
        let result =
            SmrpConnection::connect_with_pinned_server_key(&addr.to_string(), &wrong_key).await;
        assert_eq!(result.err().unwrap(), SmrpError::AuthenticationFailure);
    }

    // --- Ordered delivery ---

    #[tokio::test]
    async fn ordered_delivery_burst() {
        // Send initial_cwnd (4) messages in a burst without waiting for replies,
        // then collect all replies and verify they arrive in send order.
        // This exercises the deliver_queue drain path: when multiple echoes have
        // arrived before the first recv() call, they are returned in seq order.
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();

        // 4 == SmrpConfig::default().initial_cwnd — all fit without blocking.
        const N: u8 = 4;
        for i in 0..N {
            conn.send(&[i]).await.unwrap();
        }
        for i in 0..N {
            let reply = conn.recv().await.unwrap().unwrap();
            assert_eq!(reply.as_slice(), &[i], "wrong reply at position {i}");
        }
        conn.close().await.unwrap();
    }

    // --- KEY_UPDATE ---

    #[tokio::test]
    async fn key_update_rotates_session_keys() {
        // Verify that data sent before and after a key update is correctly
        // encrypted and decrypted: the rekey must be transparent to the application.
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let mut conn = SmrpConnection::connect(&addr.to_string()).await.unwrap();

        // Send and receive a message with the initial session keys.
        conn.send(b"pre-rekey").await.unwrap();
        assert_eq!(conn.recv().await.unwrap().unwrap(), b"pre-rekey");

        // Initiate a key update; blocks until KEY_UPDATE_ACK is received and
        // the new keys are installed on both sides.
        conn.request_key_update().await.unwrap();

        // Send and receive with the rotated keys.
        conn.send(b"post-rekey").await.unwrap();
        assert_eq!(conn.recv().await.unwrap().unwrap(), b"post-rekey");

        conn.close().await.unwrap();
    }

    // --- Congestion window ---

    #[tokio::test]
    async fn congestion_window_limits_pending() {
        // With cwnd=2 the retransmit buffer must hold at most 2 unACKed packets.
        // ACKs are only processed inside recv_inner, so pending stays at cwnd
        // until the first recv() call drains them.
        let client_cfg = Arc::new(SmrpConfig {
            initial_cwnd: 2,
            ..SmrpConfig::default()
        });
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let mut conn = SmrpConnection::connect_with_config(&addr.to_string(), client_cfg)
            .await
            .unwrap();

        // Send exactly cwnd packets — both fit without blocking.
        conn.send(&[0]).await.unwrap();
        conn.send(&[1]).await.unwrap();

        // ACKs sit in data_rx until recv() is called, so pending must still be 2.
        let pending = conn.retransmit_buf.lock().await.pending.len();
        assert_eq!(
            pending, 2,
            "expected 2 in-flight with cwnd=2, got {pending}"
        );

        // Process echoes — recv() drains ACKs internally, opening the window.
        let r0 = conn.recv().await.unwrap().unwrap();
        let r1 = conn.recv().await.unwrap().unwrap();
        assert_eq!(r0, &[0]);
        assert_eq!(r1, &[1]);

        conn.close().await.unwrap();
    }

    // --- max_retransmits exceeded → session dead ---

    #[tokio::test]
    async fn max_retransmits_kills_session() {
        // Server accepts but never calls recv(), so DATA packets are never
        // ACKed. The client's retransmit task should declare the session dead
        // after max_retransmits exhausted and return Ok(None) from recv().
        let (addr, mut listener) = echo_server().await;

        tokio::spawn(async move {
            // Accept so the handshake completes, then hold the connection open
            // without ever processing it (no recv() call → no ACKs sent).
            let _conn = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let cfg = Arc::new(SmrpConfig {
            max_retransmits: 3,
            rto_initial: Duration::from_millis(20),
            rto_min: Duration::from_millis(20),
            rto_max: Duration::from_millis(100),
            recv_timeout: Duration::from_secs(10),
            ..SmrpConfig::default()
        });
        let mut conn = SmrpConnection::connect_with_config(&addr.to_string(), cfg)
            .await
            .unwrap();

        conn.send(b"never acked").await.unwrap();

        // The retransmit task fires dead_notify_tx after max_retransmits;
        // recv_inner catches it and returns Ok(None).
        let result = time::timeout(Duration::from_secs(5), conn.recv()).await;
        assert!(result.is_ok(), "test itself timed out");
        assert!(
            result.unwrap().unwrap().is_none(),
            "expected Ok(None) when session is declared dead"
        );
    }

    // --- initial_ssthresh is configurable ---

    #[tokio::test]
    async fn initial_ssthresh_from_config() {
        let cfg = Arc::new(SmrpConfig {
            initial_ssthresh: 8,
            ..SmrpConfig::default()
        });
        let (addr, listener) = echo_server().await;
        spawn_echo(listener);
        let conn = SmrpConnection::connect_with_config(&addr.to_string(), cfg)
            .await
            .unwrap();
        let state = conn.retransmit_buf.lock().await;
        assert_eq!(
            state.ssthresh, 8,
            "ssthresh should match initial_ssthresh in config"
        );
        drop(state);
        conn.close().await.unwrap();
    }
}
