/// RFC 6479-style anti-replay sliding window.
///
/// Tracks received sequence numbers in a 128-bit bitmask.  Bit `N` set means
/// sequence number `highest - N` has already been accepted.
///
/// ## Two-phase API
///
/// The check and the mark are intentionally separated so that a failed AEAD
/// decryption does NOT permanently consume the sequence number slot.
/// This prevents a trivial `DoS` where an attacker injects a forged packet with
/// a valid-looking sequence number, causing the legitimate retransmission to
/// be rejected as a replay.
///
/// Correct call order in the data path:
/// ```text
/// 1. window.can_accept(seq)?          // reject if too old or already seen
/// 2. key.open(nonce, aad, ciphertext) // decrypt and verify AEAD tag
/// 3. window.mark_seen(seq)            // only reached on success
/// ```
use crate::error::SmrpError;

/// Number of sequence numbers tracked simultaneously.
/// 128 matches the minimum recommended in RFC 6479 §2.2.
const WINDOW_SIZE: u64 = 128;

/// Anti-replay sliding window keyed on sequence numbers.
#[derive(Debug)]
pub struct ReplayWindow {
    /// Highest sequence number successfully accepted so far.
    highest: Option<u64>,
    /// Bitmask: bit `k` set ↔ `(highest - k)` has been accepted.
    window: u128,
}

impl ReplayWindow {
    /// Creates a new, empty window (no packets seen yet).
    #[must_use]
    pub fn new() -> Self {
        Self {
            highest: None,
            window: 0,
        }
    }

    /// Returns `Ok(())` if `seq` is acceptable (not a replay, not too old).
    ///
    /// Does **not** modify state — call [`mark_seen`](Self::mark_seen) after
    /// successful AEAD decryption.
    ///
    /// # Errors
    /// Returns [`SmrpError::ReplayDetected`] if `seq` is:
    /// - more than `WINDOW_SIZE - 1` below the current highest (too old to track), or
    /// - within the window but already marked as seen.
    pub fn can_accept(&self, seq: u64) -> Result<(), SmrpError> {
        let Some(high) = self.highest else {
            return Ok(()); // first packet is always acceptable
        };

        if seq > high {
            return Ok(()); // new highest — always accept
        }

        let offset = high - seq;
        if offset >= WINDOW_SIZE {
            return Err(SmrpError::ReplayDetected); // too old
        }
        if self.window & (1u128 << offset) != 0 {
            return Err(SmrpError::ReplayDetected); // already seen
        }
        Ok(())
    }

    /// Records `seq` as seen.  Must only be called after a successful AEAD
    /// open to prevent an attacker from poisoning the window with forged packets.
    pub fn mark_seen(&mut self, seq: u64) {
        match self.highest {
            None => {
                self.highest = Some(seq);
                self.window = 1;
            }
            Some(high) => {
                if seq > high {
                    let shift = seq - high;
                    // Shift the bitmask left by `shift` positions and set bit 0
                    // for the new highest.  If the shift exceeds the window,
                    // only the new entry is tracked.
                    self.window = if shift >= WINDOW_SIZE {
                        1
                    } else {
                        (self.window << shift) | 1
                    };
                    self.highest = Some(seq);
                } else {
                    let offset = high - seq;
                    if offset < WINDOW_SIZE {
                        self.window |= 1u128 << offset;
                    }
                }
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::pedantic)]
mod tests {
    use super::*;

    fn window_with(seqs: &[u64]) -> ReplayWindow {
        let mut w = ReplayWindow::new();
        for &s in seqs {
            w.can_accept(s).unwrap();
            w.mark_seen(s);
        }
        w
    }

    // --- Basic accept / reject ---

    #[test]
    fn first_packet_always_accepted() {
        let w = ReplayWindow::new();
        assert!(w.can_accept(0).is_ok());
        assert!(w.can_accept(999).is_ok());
    }

    #[test]
    fn in_order_sequence_accepted() {
        let mut w = ReplayWindow::new();
        for seq in 0u64..200 {
            assert!(w.can_accept(seq).is_ok(), "seq={seq}");
            w.mark_seen(seq);
        }
    }

    #[test]
    fn replay_of_highest_is_rejected() {
        let w = window_with(&[42]);
        assert_eq!(w.can_accept(42), Err(SmrpError::ReplayDetected));
    }

    #[test]
    fn replay_of_earlier_seq_is_rejected() {
        let w = window_with(&[0, 1, 2, 3, 4, 5]);
        assert_eq!(w.can_accept(3), Err(SmrpError::ReplayDetected));
    }

    #[test]
    fn out_of_order_within_window_is_accepted_then_rejected() {
        let mut w = window_with(&[10]);
        assert!(w.can_accept(8).is_ok());
        w.mark_seen(8);
        // Replay of 8 must now be rejected
        assert_eq!(w.can_accept(8), Err(SmrpError::ReplayDetected));
        // 9 still not seen — should still be accepted
        assert!(w.can_accept(9).is_ok());
    }

    #[test]
    fn sequence_too_old_is_rejected() {
        let mut w = ReplayWindow::new();
        w.can_accept(0).unwrap();
        w.mark_seen(0);
        // Advance highest to 128
        w.can_accept(128).unwrap();
        w.mark_seen(128);
        // seq=0 is now 128 steps behind highest — outside the 128-wide window
        assert_eq!(w.can_accept(0), Err(SmrpError::ReplayDetected));
    }

    #[test]
    fn seq_at_exact_window_edge_is_rejected() {
        let mut w = window_with(&[127]);
        // Seq 0 is exactly WINDOW_SIZE - 1 = 127 steps behind: still inside.
        assert!(w.can_accept(0).is_ok());
        // Now advance to 128.
        w.mark_seen(128); // conceptually valid
                          // Seq 0 is now 128 steps behind: outside.
        let w2 = window_with(&[128]);
        assert_eq!(w2.can_accept(0), Err(SmrpError::ReplayDetected));
    }

    // --- Two-phase correctness ---

    #[test]
    fn failed_decrypt_does_not_poison_window() {
        let w = window_with(&[5]); // highest=5
        // Suppose seq=6 arrives but AEAD fails — we only called can_accept, not mark_seen.
        w.can_accept(6).unwrap();
        // Window state unchanged: seq=6 is still acceptable for the real retransmit.
        assert!(w.can_accept(6).is_ok());
    }

    #[test]
    fn mark_seen_after_success_prevents_replay() {
        let mut w = window_with(&[5]);
        w.can_accept(6).unwrap();
        w.mark_seen(6); // AEAD succeeded
        // Now replay of 6 is rejected
        assert_eq!(w.can_accept(6), Err(SmrpError::ReplayDetected));
    }

    // --- Window slide ---

    #[test]
    fn large_jump_resets_window_to_single_entry() {
        let mut w = window_with(&[0, 1, 2, 3]);
        // Jump far ahead
        w.can_accept(500).unwrap();
        w.mark_seen(500);
        // Old seqs are now too old
        assert_eq!(w.can_accept(1), Err(SmrpError::ReplayDetected));
        assert_eq!(w.can_accept(0), Err(SmrpError::ReplayDetected));
        // Seq 499 is one behind highest — still in window and not yet seen
        assert!(w.can_accept(499).is_ok());
    }

    #[test]
    fn full_window_cycle() {
        let mut w = ReplayWindow::new();
        for seq in 0u64..256 {
            assert!(w.can_accept(seq).is_ok(), "initial accept failed at seq={seq}");
            w.mark_seen(seq);
        }
        // All 256 seen; anything below 256-128=128 is now too old
        for seq in 0u64..128 {
            assert_eq!(
                w.can_accept(seq),
                Err(SmrpError::ReplayDetected),
                "expected replay at seq={seq}"
            );
        }
        // 128..=255 are within the window and already marked
        for seq in 128u64..256 {
            assert_eq!(
                w.can_accept(seq),
                Err(SmrpError::ReplayDetected),
                "expected replay at seq={seq}"
            );
        }
    }
}
