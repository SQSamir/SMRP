#![no_main]
use libfuzzer_sys::fuzz_target;
use smrp_core::packet;

// Feed arbitrary bytes into the packet parser; must never panic.
// Verifies: length guards, magic check, version check, packet-type decode,
//           field extraction — all reachable without any crypto.
fuzz_target!(|data: &[u8]| {
    if let Ok(hdr) = packet::parse(data) {
        // Round-trip: serialise what we parsed and parse again.
        let serialised = packet::serialize(&hdr);
        let _ = packet::parse(&serialised);
    }
});
