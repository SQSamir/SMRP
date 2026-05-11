/// Magic bytes identifying an SMRP datagram on the wire (`SMRP` in ASCII).
pub const SMRP_MAGIC: u32 = 0x534D_5250;

/// Protocol version carried in every packet header.
pub const SMRP_VERSION: u8 = 0x04;

/// Fixed size of the SMRP packet header in bytes.
pub const HEADER_LEN: usize = 54;

/// Maximum application-layer payload per packet in bytes.
pub const MAX_PAYLOAD: usize = 1280;

/// Length of the Poly1305 authentication tag appended to every ciphertext.
pub const AUTH_TAG_LEN: usize = 16;

/// Maximum total on-wire packet size: header + max payload + auth tag.
pub const MAX_PACKET: usize = 1350;

/// Length of a session identifier in bytes.
pub const SESSION_ID_LEN: usize = 8;

/// Length of the ChaCha20-Poly1305 nonce in bytes.
pub const NONCE_LEN: usize = 12;

/// Interval between keepalive probes when a session is idle, in seconds.
pub const KEEPALIVE_INTERVAL_SECS: u64 = 15;

/// Maximum number of concurrent sessions supported by a single server instance.
pub const MAX_SESSIONS: usize = 100_000;

#[cfg(test)]
#[allow(clippy::pedantic)]
mod tests {
    use super::*;

    #[test]
    fn max_packet_is_sum_of_parts() {
        assert_eq!(MAX_PACKET, HEADER_LEN + MAX_PAYLOAD + AUTH_TAG_LEN);
    }

    #[test]
    fn magic_is_ascii_smrp() {
        assert_eq!(&SMRP_MAGIC.to_be_bytes(), b"SMRP");
    }

    #[test]
    fn session_id_len_matches_wire_spec() {
        assert_eq!(SESSION_ID_LEN, 8);
    }

    #[test]
    fn nonce_len_matches_chacha20_spec() {
        assert_eq!(NONCE_LEN, 12);
    }
}
