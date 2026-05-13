use std::time::Duration;

/// Runtime-tunable parameters for the SMRP stack.
///
/// Build with [`SmrpConfig::default()`] and override fields as needed, then
/// pass to [`SmrpListener::bind_with_config`] or
/// [`SmrpConnection::connect_with_config`].
#[derive(Debug, Clone)]
pub struct SmrpConfig {
    /// How often to send a KEEPALIVE probe when the session is idle.
    /// Default: 15 s.
    pub keepalive_interval: Duration,

    /// If no packet is received for this long the session is declared dead
    /// and evicted. Should be ≥ 3 × `keepalive_interval`. Default: 45 s.
    pub session_dead_timeout: Duration,

    /// Maximum allowed clock difference for HELLO timestamp validation.
    /// HELLOs outside this window are rejected before any crypto runs.
    /// Default: 30 s.
    pub hello_clock_skew: Duration,

    /// Maximum HELLO packets accepted from one source IP per second.
    /// Excess packets are silently dropped. Default: 10.
    pub hello_rate_limit: u32,

    /// Hard cap on concurrent sessions. HELLOs that would exceed this limit
    /// receive an ERROR reply. Default: 100 000.
    pub max_sessions: usize,

    /// Timeout for [`SmrpConnection::connect`]. Default: 10 s.
    pub connect_timeout: Duration,

    /// Default timeout for [`SmrpConnection::recv`]. Default: 60 s.
    pub recv_timeout: Duration,

    /// How long [`SmrpConnection::close`] waits for a `FIN_ACK`. Default: 5 s.
    pub fin_ack_timeout: Duration,

    /// Capacity of the per-session packet channel. Default: 256 packets.
    pub session_channel_capacity: usize,

    /// Capacity of the new-connection queue returned by `accept()`. Default: 64.
    pub accept_queue_capacity: usize,

    // ---- Retransmission -------------------------------------------------------
    /// Maximum number of retransmission attempts per DATA packet before the
    /// session is declared dead. Default: 5.
    pub max_retransmits: u32,

    /// Initial retransmission timeout (RTO). The RTO is adjusted dynamically
    /// using the Jacobson/Karels algorithm. Default: 200 ms.
    pub rto_initial: Duration,

    /// Minimum retransmission timeout (floor for exponential backoff).
    /// Also used as the retransmit-task check interval. Default: 50 ms.
    pub rto_min: Duration,

    /// Maximum retransmission timeout (ceiling for exponential backoff).
    /// Default: 30 s.
    pub rto_max: Duration,

    // ---- Congestion control --------------------------------------------------
    /// Initial congestion window — maximum DATA packets in flight before the
    /// first ACK arrives. Uses slow-start from this value up to `initial_ssthresh`,
    /// then switches to AIMD congestion avoidance. Default: 4.
    pub initial_cwnd: usize,

    /// Initial slow-start threshold. Slow-start runs while `cwnd < ssthresh`;
    /// above this value the sender switches to AIMD congestion avoidance.
    /// Default: 64.
    pub initial_ssthresh: usize,

    // ---- Receive reorder buffer ---------------------------------------------
    /// Maximum out-of-order DATA packets held in the receive reorder buffer.
    /// Packets that would exceed this limit are dropped (and retransmitted by
    /// the peer). Default: 256.
    pub recv_buf_limit: usize,

    // ---- SACK ---------------------------------------------------------------
    /// Maximum number of SACK blocks included in a single `SackAck` packet.
    /// Each block is 16 bytes (two u64 sequence numbers). Default: 16.
    pub max_sack_blocks: usize,

    // ---- PMTUD (Path MTU Discovery) -----------------------------------------
    /// Enable probe-based path MTU discovery. When enabled the sender
    /// periodically probes larger payload sizes and backs off on loss.
    /// Default: true.
    pub pmtud_enabled: bool,

    /// How often to send a PMTUD probe when the current MTU estimate may be
    /// stale. Default: 5 s.
    pub pmtud_probe_interval: Duration,

    // ---- Pacing -------------------------------------------------------------
    /// Enable token-bucket send pacing. Spreads bursts evenly across the RTT
    /// to reduce queue build-up at bottleneck links. Default: true.
    pub pacing_enabled: bool,

    // ---- ECN ----------------------------------------------------------------
    /// Mirror IP ECN bits (ECT/CE) into the SMRP flags field and react to CE
    /// marks by reducing cwnd. Requires OS support; silently disabled at
    /// runtime if the socket option is unavailable. Default: false.
    pub ecn_enabled: bool,

    // ---- Multiplexed streams ------------------------------------------------
    /// Maximum number of concurrent logical streams per session.
    /// Stream IDs 0..max_streams are valid; 0 is the default (control) stream.
    /// Default: 256.
    pub max_streams: u16,

    // ---- Connection migration -----------------------------------------------
    /// Allow the remote peer to migrate the session to a new address via
    /// PATH_CHALLENGE / PATH_RESPONSE. Default: true.
    pub migration_enabled: bool,
}

impl Default for SmrpConfig {
    fn default() -> Self {
        Self {
            keepalive_interval: Duration::from_secs(15),
            session_dead_timeout: Duration::from_secs(45),
            hello_clock_skew: Duration::from_secs(30),
            hello_rate_limit: 10,
            max_sessions: 100_000,
            connect_timeout: Duration::from_secs(10),
            recv_timeout: Duration::from_mins(1),
            fin_ack_timeout: Duration::from_secs(5),
            session_channel_capacity: 256,
            accept_queue_capacity: 64,
            max_retransmits: 5,
            rto_initial: Duration::from_millis(200),
            rto_min: Duration::from_millis(50),
            rto_max: Duration::from_secs(30),
            initial_cwnd: 4,
            initial_ssthresh: 64,
            recv_buf_limit: 256,
            max_sack_blocks: 16,
            pmtud_enabled: true,
            pmtud_probe_interval: Duration::from_secs(5),
            pacing_enabled: true,
            ecn_enabled: false,
            max_streams: 256,
            migration_enabled: true,
        }
    }
}
