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

    /// How long [`SmrpConnection::close`] waits for a FIN_ACK. Default: 5 s.
    pub fin_ack_timeout: Duration,

    /// Capacity of the per-session packet channel. Default: 256 packets.
    pub session_channel_capacity: usize,

    /// Capacity of the new-connection queue returned by `accept()`. Default: 64.
    pub accept_queue_capacity: usize,
}

impl Default for SmrpConfig {
    fn default() -> Self {
        Self {
            keepalive_interval:      Duration::from_secs(15),
            session_dead_timeout:    Duration::from_secs(45),
            hello_clock_skew:        Duration::from_secs(30),
            hello_rate_limit:        10,
            max_sessions:            100_000,
            connect_timeout:         Duration::from_secs(10),
            recv_timeout:            Duration::from_secs(60),
            fin_ack_timeout:         Duration::from_secs(5),
            session_channel_capacity: 256,
            accept_queue_capacity:   64,
        }
    }
}
