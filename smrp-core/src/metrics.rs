use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters tracking the runtime state of an SMRP listener.
///
/// Obtain a handle via [`SmrpListener::metrics`] and read individual fields
/// with [`AtomicU64::load`]`(Ordering::Relaxed)` for cheap snapshots,
/// or call [`SmrpMetrics::snapshot`] for a consistent point-in-time copy.
///
/// All counters are monotonically increasing except `sessions_active`, which
/// is a gauge that increments on session establishment and decrements on close
/// or eviction.
#[derive(Debug, Default)]
pub struct SmrpMetrics {
    // ---- Session lifecycle ------------------------------------------------
    /// Currently active (established) sessions. Gauge — may decrease.
    pub sessions_active: AtomicU64,
    /// Total sessions fully established since startup.
    pub sessions_total: AtomicU64,
    /// Sessions evicted because `session_dead_timeout` elapsed with no traffic.
    pub sessions_evicted_dead: AtomicU64,

    // ---- HELLO rejection -------------------------------------------------
    /// HELLOs dropped by the per-IP rate limiter (before any crypto).
    pub hello_drops_rate_limit: AtomicU64,
    /// HELLOs dropped because the timestamp was outside `hello_clock_skew`.
    pub hello_drops_clock_skew: AtomicU64,
    /// HELLOs rejected because `max_sessions` was reached.
    pub hello_drops_capacity: AtomicU64,

    // ---- Data plane -------------------------------------------------------
    /// DATA packets successfully sent (first transmission only).
    pub packets_sent: AtomicU64,
    /// DATA packets successfully received and authenticated.
    pub packets_received: AtomicU64,
    /// Application bytes sent (plaintext).
    pub bytes_sent: AtomicU64,
    /// Application bytes received (plaintext).
    pub bytes_received: AtomicU64,
    /// DATA packets retransmitted due to missing ACK within RTO.
    pub packets_retransmitted: AtomicU64,

    // ---- Security events -------------------------------------------------
    /// Packets whose AEAD tag failed verification.
    pub auth_failures: AtomicU64,
    /// Packets rejected by the anti-replay window.
    pub replay_detections: AtomicU64,
}

impl SmrpMetrics {
    /// Creates a zeroed metrics instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a consistent point-in-time snapshot of all counters.
    ///
    /// Each field is read with `Ordering::Relaxed`; individual reads are
    /// not atomic with respect to each other, so the snapshot may reflect
    /// a mix of moments. For monitoring/dashboards this is acceptable.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            sessions_active: self.sessions_active.load(Ordering::Relaxed),
            sessions_total: self.sessions_total.load(Ordering::Relaxed),
            sessions_evicted_dead: self.sessions_evicted_dead.load(Ordering::Relaxed),
            hello_drops_rate_limit: self.hello_drops_rate_limit.load(Ordering::Relaxed),
            hello_drops_clock_skew: self.hello_drops_clock_skew.load(Ordering::Relaxed),
            hello_drops_capacity: self.hello_drops_capacity.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_retransmitted: self.packets_retransmitted.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            replay_detections: self.replay_detections.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time copy of all [`SmrpMetrics`] counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub sessions_active: u64,
    pub sessions_total: u64,
    pub sessions_evicted_dead: u64,
    pub hello_drops_rate_limit: u64,
    pub hello_drops_clock_skew: u64,
    pub hello_drops_capacity: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_retransmitted: u64,
    pub auth_failures: u64,
    pub replay_detections: u64,
}
