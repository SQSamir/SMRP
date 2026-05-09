#![no_main]
use libfuzzer_sys::fuzz_target;
use smrp_core::{
    constants::{HEADER_LEN, SMRP_MAGIC, SMRP_VERSION},
    packet::{self, PacketType, Flags, SmrpHeader},
    session::SessionId,
};

// Craft a syntactically valid SMRP HELLO frame whose *payload* (ephemeral
// public key + Ed25519 signature bytes) comes from the fuzzer.
// Feeds into packet::parse to exercise the header path, and then any
// downstream HELLO parsing logic that touches the raw payload bytes.
// Must never panic regardless of payload contents.
fuzz_target!(|payload: &[u8]| {
    let payload_len = payload.len().min(u16::MAX as usize) as u16;

    let hdr = SmrpHeader {
        magic:           SMRP_MAGIC,
        version:         SMRP_VERSION,
        packet_type:     PacketType::Hello,
        flags:           Flags::default(),
        reserved:        0,
        session_id:      SessionId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]),
        sequence_number: 1,
        ack_number:      0,
        timestamp_us:    0,
        payload_len,
    };

    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&packet::serialize(&hdr));
    frame.extend_from_slice(payload);

    // Must not panic; error is fine.
    let _ = packet::parse(&frame);
});
