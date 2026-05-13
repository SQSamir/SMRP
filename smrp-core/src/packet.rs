use crate::{
    constants::{HEADER_LEN, SMRP_MAGIC, SMRP_VERSION},
    error::SmrpError,
    session::SessionId,
};
use bytes::Buf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Returns the current time as microseconds since the Unix epoch.
#[must_use]
pub fn timestamp_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as u64)
}

/// Every packet type defined by the SMRP wire protocol (wire values 0x01–0x11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Initiates a new session and carries the sender's ephemeral public key.
    Hello = 0x01,
    /// Acknowledges a `Hello` and completes the key-exchange step.
    HelloAck = 0x02,
    /// Carries application-layer ciphertext after the handshake.
    Data = 0x03,
    /// Acknowledges receipt of one or more `Data` packets.
    Ack = 0x04,
    /// Probes session liveness when no data has been exchanged recently.
    Keepalive = 0x05,
    /// Response to a `Keepalive` probe.
    KeepaliveAck = 0x06,
    /// Initiates rekeying for forward secrecy.
    KeyUpdate = 0x07,
    /// Acknowledges completion of a key-update exchange.
    KeyUpdateAck = 0x08,
    /// Initiates graceful session teardown.
    Fin = 0x09,
    /// Signals a protocol-level error to the peer.
    Error = 0x0A,
    /// Acknowledges a FIN packet; completes graceful teardown.
    FinAck = 0x0B,
    /// Aborts a session immediately without waiting for acknowledgement.
    Reset = 0x0C,
    /// RTT measurement request.
    Ping = 0x0D,
    /// RTT measurement response.
    Pong = 0x0E,
    /// Selective acknowledgement; carries SACK blocks for out-of-order ranges.
    SackAck = 0x0F,
    /// Connection migration: challenges the peer to prove reachability at a new address.
    PathChallenge = 0x10,
    /// Connection migration: response proving reachability, echoes the challenge nonce.
    PathResponse = 0x11,
}

impl TryFrom<u8> for PacketType {
    type Error = SmrpError;

    fn try_from(value: u8) -> Result<Self, SmrpError> {
        match value {
            0x01 => Ok(Self::Hello),
            0x02 => Ok(Self::HelloAck),
            0x03 => Ok(Self::Data),
            0x04 => Ok(Self::Ack),
            0x05 => Ok(Self::Keepalive),
            0x06 => Ok(Self::KeepaliveAck),
            0x07 => Ok(Self::KeyUpdate),
            0x08 => Ok(Self::KeyUpdateAck),
            0x09 => Ok(Self::Fin),
            0x0A => Ok(Self::Error),
            0x0B => Ok(Self::FinAck),
            0x0C => Ok(Self::Reset),
            0x0D => Ok(Self::Ping),
            0x0E => Ok(Self::Pong),
            0x0F => Ok(Self::SackAck),
            0x10 => Ok(Self::PathChallenge),
            0x11 => Ok(Self::PathResponse),
            _ => Err(SmrpError::MalformedHeader),
        }
    }
}

/// Bitfield carried in the `flags` byte of every SMRP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags(pub u8);

impl Flags {
    /// Bit 0 — session teardown flag; set in `Fin` packets.
    pub const FIN: u8 = 0b0000_0001;
    /// Bit 1 — indicates the sender wants to begin a key-update exchange.
    pub const KEY_UPDATE_REQUESTED: u8 = 0b0000_0010;
    /// Bit 2 — this DATA packet carries a fragment of a larger message.
    pub const FRAGMENT: u8 = 0b0000_0100;
    /// Bit 3 — IP ECN-Capable Transport; mirrors the ECT(0) codepoint received on ingress.
    pub const ECT: u8 = 0b0000_1000;
    /// Bit 4 — IP Congestion Experienced; mirrors the CE codepoint received on ingress.
    pub const CE: u8 = 0b0001_0000;

    /// Returns `true` when the FIN bit is set.
    #[must_use]
    pub fn fin(self) -> bool {
        self.0 & Self::FIN != 0
    }

    /// Returns `true` when the `KEY_UPDATE_REQUESTED` bit is set.
    #[must_use]
    pub fn key_update_requested(self) -> bool {
        self.0 & Self::KEY_UPDATE_REQUESTED != 0
    }

    /// Returns `true` when this packet is a fragment of a larger message.
    #[must_use]
    pub fn fragment(self) -> bool {
        self.0 & Self::FRAGMENT != 0
    }

    /// Returns `true` when the ECN-Capable Transport bit is set.
    #[must_use]
    pub fn ect(self) -> bool {
        self.0 & Self::ECT != 0
    }

    /// Returns `true` when the Congestion Experienced bit is set.
    #[must_use]
    pub fn ce(self) -> bool {
        self.0 & Self::CE != 0
    }
}

/// Fixed 54-byte SMRP packet header.
///
/// Layout (all multi-byte integers are big-endian):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           magic (4)                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | version (1)   | type (1)      | flags (1)     | reserved (1)  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        session_id (8)                          |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       sequence_number (8)                      |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          ack_number (8)                        |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         timestamp_us (8)                       |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         payload_len (2)       |   frag_id (2) |fi(1)  |fc(1)  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       recv_window (2)         |    stream_id (2)  | rsvd2 (4) |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// Total: 4+1+1+1+1+8+8+8+8+2+2+1+1+2+2+4 = 54 bytes.
/// fi = `frag_index`, fc = `frag_count`, rsvd2 = bytes 50–53 (reserved).
#[derive(Debug, Clone)]
#[repr(C)]
pub struct SmrpHeader {
    /// Must equal [`SMRP_MAGIC`]; identifies the datagram as SMRP.
    pub magic: u32,
    /// Must equal [`SMRP_VERSION`] for this revision of the protocol.
    pub version: u8,
    /// Identifies the role and purpose of this packet.
    pub packet_type: PacketType,
    /// Per-packet control bits (FIN, `KEY_UPDATE_REQUESTED`, `FRAGMENT`, …).
    pub flags: Flags,
    /// Reserved for future use; senders MUST set to zero.
    pub reserved: u8,
    /// Identifies the session this packet belongs to.
    pub session_id: SessionId,
    /// Monotonically increasing per-session send counter.
    pub sequence_number: u64,
    /// Highest in-order sequence number received from the peer (cumulative ACK).
    pub ack_number: u64,
    /// Sender's clock at transmission time, in microseconds since Unix epoch.
    pub timestamp_us: u64,
    /// Length of the encrypted payload that follows this header, in bytes.
    pub payload_len: u16,
    /// Message fragmentation ID; groups all fragments of one application message.
    /// Zero when `Flags::FRAGMENT` is not set.
    pub frag_id: u16,
    /// Zero-based index of this fragment within its message.
    pub frag_index: u8,
    /// Total number of fragments in this message (1–255). Zero when not fragmented.
    pub frag_count: u8,
    /// Receiver's remaining buffer space in packets; used for flow control.
    pub recv_window: u16,
    /// Logical stream identifier within this session (0 = default stream).
    pub stream_id: u16,
}

/// Parses the first [`HEADER_LEN`] bytes of `src` into an [`SmrpHeader`].
///
/// # Errors
/// Returns [`SmrpError::MalformedHeader`] if `src` is shorter than
/// `HEADER_LEN`, [`SmrpError::InvalidMagic`] on a magic mismatch, and
/// [`SmrpError::UnsupportedVersion`] if the version byte is not `SMRP_VERSION`.
pub fn parse(src: &[u8]) -> Result<SmrpHeader, SmrpError> {
    if src.len() < HEADER_LEN {
        return Err(SmrpError::MalformedHeader);
    }

    let mut cursor = src;

    let magic = cursor.get_u32();
    if magic != SMRP_MAGIC {
        return Err(SmrpError::InvalidMagic);
    }

    let version = cursor.get_u8();
    if version != SMRP_VERSION {
        return Err(SmrpError::UnsupportedVersion);
    }

    let packet_type = PacketType::try_from(cursor.get_u8())?;
    let flags = Flags(cursor.get_u8());
    let reserved = cursor.get_u8();

    let mut sid_bytes = [0u8; 8];
    sid_bytes.copy_from_slice(&cursor[..8]);
    cursor.advance(8);
    let session_id = SessionId::from_bytes(sid_bytes);

    let sequence_number = cursor.get_u64();
    let ack_number = cursor.get_u64();
    let timestamp_us = cursor.get_u64();
    let payload_len = cursor.get_u16();
    let frag_id = cursor.get_u16();
    let frag_index = cursor.get_u8();
    let frag_count = cursor.get_u8();
    let recv_window = cursor.get_u16();
    let stream_id = cursor.get_u16();
    // bytes 50-53: reserved2 — skip

    Ok(SmrpHeader {
        magic,
        version,
        packet_type,
        flags,
        reserved,
        session_id,
        sequence_number,
        ack_number,
        timestamp_us,
        payload_len,
        frag_id,
        frag_index,
        frag_count,
        recv_window,
        stream_id,
    })
}

/// Serialises `header` into a fixed 54-byte big-endian buffer.
#[must_use]
pub fn serialize(header: &SmrpHeader) -> [u8; HEADER_LEN] {
    let mut buf = [0u8; HEADER_LEN];
    buf[0..4].copy_from_slice(&header.magic.to_be_bytes());
    buf[4] = header.version;
    buf[5] = header.packet_type as u8;
    buf[6] = header.flags.0;
    buf[7] = header.reserved;
    buf[8..16].copy_from_slice(header.session_id.as_bytes());
    buf[16..24].copy_from_slice(&header.sequence_number.to_be_bytes());
    buf[24..32].copy_from_slice(&header.ack_number.to_be_bytes());
    buf[32..40].copy_from_slice(&header.timestamp_us.to_be_bytes());
    buf[40..42].copy_from_slice(&header.payload_len.to_be_bytes());
    buf[42..44].copy_from_slice(&header.frag_id.to_be_bytes());
    buf[44] = header.frag_index;
    buf[45] = header.frag_count;
    buf[46..48].copy_from_slice(&header.recv_window.to_be_bytes());
    buf[48..50].copy_from_slice(&header.stream_id.to_be_bytes());
    // bytes 50-53: reserved2 — remain zero
    buf
}

#[cfg(test)]
#[allow(clippy::pedantic)]
mod tests {
    use super::*;
    use crate::{constants::HEADER_LEN, error::SmrpError};

    /// Builds a syntactically valid 54-byte SMRP header buffer.
    fn valid_buf() -> [u8; 54] {
        let mut b = [0u8; 54];
        b[0..4].copy_from_slice(&0x534D_5250u32.to_be_bytes()); // magic
        b[4] = 0x05; // version
        b[5] = 0x03; // Data
        b[6] = 0x01; // FIN flag
        b[7] = 0x00; // reserved
        b[8..16].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // session_id
        b[16..24].copy_from_slice(&42u64.to_be_bytes()); // seq
        b[24..32].copy_from_slice(&41u64.to_be_bytes()); // ack
        b[32..40].copy_from_slice(&1_000_000u64.to_be_bytes()); // timestamp_us
        b[40..42].copy_from_slice(&512u16.to_be_bytes()); // payload_len
                                                          // bytes 42-53: pad zeros
        b
    }

    // --- PacketType::try_from ---

    #[test]
    fn packet_type_all_valid_wire_codes() {
        let cases: &[(u8, PacketType)] = &[
            (0x01, PacketType::Hello),
            (0x02, PacketType::HelloAck),
            (0x03, PacketType::Data),
            (0x04, PacketType::Ack),
            (0x05, PacketType::Keepalive),
            (0x06, PacketType::KeepaliveAck),
            (0x07, PacketType::KeyUpdate),
            (0x08, PacketType::KeyUpdateAck),
            (0x09, PacketType::Fin),
            (0x0A, PacketType::Error),
            (0x0B, PacketType::FinAck),
            (0x0C, PacketType::Reset),
            (0x0D, PacketType::Ping),
            (0x0E, PacketType::Pong),
            (0x0F, PacketType::SackAck),
            (0x10, PacketType::PathChallenge),
            (0x11, PacketType::PathResponse),
        ];
        for (byte, expected) in cases {
            assert_eq!(PacketType::try_from(*byte).unwrap(), *expected);
        }
    }

    #[test]
    fn packet_type_zero_is_invalid() {
        assert_eq!(PacketType::try_from(0x00), Err(SmrpError::MalformedHeader));
    }

    #[test]
    fn packet_type_out_of_range_is_invalid() {
        // 0x12 and above are undefined; 0x11 (PathResponse) is the highest valid code.
        assert_eq!(PacketType::try_from(0x12), Err(SmrpError::MalformedHeader));
        assert_eq!(PacketType::try_from(0xFF), Err(SmrpError::MalformedHeader));
    }

    // --- Flags ---

    #[test]
    fn flags_default_has_no_bits_set() {
        let f = Flags::default();
        assert!(!f.fin());
        assert!(!f.key_update_requested());
    }

    #[test]
    fn flags_fin_bit() {
        let f = Flags(Flags::FIN);
        assert!(f.fin());
        assert!(!f.key_update_requested());
        assert!(!f.fragment());
    }

    #[test]
    fn flags_key_update_requested_bit() {
        let f = Flags(Flags::KEY_UPDATE_REQUESTED);
        assert!(!f.fin());
        assert!(f.key_update_requested());
        assert!(!f.fragment());
    }

    #[test]
    fn flags_fragment_bit() {
        let f = Flags(Flags::FRAGMENT);
        assert!(!f.fin());
        assert!(!f.key_update_requested());
        assert!(f.fragment());
    }

    #[test]
    fn flags_both_bits() {
        let f = Flags(Flags::FIN | Flags::KEY_UPDATE_REQUESTED);
        assert!(f.fin());
        assert!(f.key_update_requested());
    }

    #[test]
    fn flags_ect_bit() {
        let f = Flags(Flags::ECT);
        assert!(f.ect());
        assert!(!f.ce());
        assert!(!f.fin());
    }

    #[test]
    fn flags_ce_bit() {
        let f = Flags(Flags::CE);
        assert!(f.ce());
        assert!(!f.ect());
    }

    #[test]
    fn flags_ecn_bits_independent() {
        let f = Flags(Flags::ECT | Flags::CE);
        assert!(f.ect());
        assert!(f.ce());
        assert!(!f.fin());
    }

    // --- parse() ---

    #[test]
    fn parse_empty_buffer_returns_malformed() {
        assert_eq!(parse(&[]).unwrap_err(), SmrpError::MalformedHeader);
    }

    #[test]
    fn parse_short_buffer_returns_malformed() {
        let buf = [0u8; HEADER_LEN - 1];
        assert_eq!(parse(&buf).unwrap_err(), SmrpError::MalformedHeader);
    }

    #[test]
    fn parse_wrong_magic_returns_invalid_magic() {
        let mut buf = valid_buf();
        buf[0] = 0xFF;
        assert_eq!(parse(&buf).unwrap_err(), SmrpError::InvalidMagic);
    }

    #[test]
    fn parse_wrong_version_returns_unsupported_version() {
        let mut buf = valid_buf();
        buf[4] = 0x06;
        assert_eq!(parse(&buf).unwrap_err(), SmrpError::UnsupportedVersion);
    }

    #[test]
    fn parse_invalid_packet_type_returns_malformed() {
        let mut buf = valid_buf();
        buf[5] = 0x00;
        assert_eq!(parse(&buf).unwrap_err(), SmrpError::MalformedHeader);
    }

    #[test]
    fn parse_valid_header_fields_are_correct() {
        let buf = valid_buf();
        let hdr = parse(&buf).unwrap();

        assert_eq!(hdr.magic, 0x534D_5250);
        assert_eq!(hdr.version, 0x05);
        assert_eq!(hdr.packet_type, PacketType::Data);
        assert!(hdr.flags.fin());
        assert!(!hdr.flags.key_update_requested());
        assert_eq!(hdr.session_id.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(hdr.sequence_number, 42);
        assert_eq!(hdr.ack_number, 41);
        assert_eq!(hdr.timestamp_us, 1_000_000);
        assert_eq!(hdr.payload_len, 512);
        assert_eq!(hdr.stream_id, 0);
    }

    #[test]
    fn parse_stream_id_round_trips() {
        let mut buf = valid_buf();
        buf[48..50].copy_from_slice(&1234u16.to_be_bytes());
        let hdr = parse(&buf).unwrap();
        assert_eq!(hdr.stream_id, 1234);
    }

    #[test]
    fn parse_accepts_buffer_larger_than_header() {
        let mut buf = [0u8; 1350];
        buf[..54].copy_from_slice(&valid_buf());
        assert!(parse(&buf).is_ok());
    }
}
