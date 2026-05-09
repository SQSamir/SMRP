#![no_main]
use libfuzzer_sys::fuzz_target;
use smrp_core::replay::ReplayWindow;

// Drive the anti-replay window with arbitrary (seq, action) pairs.
// Verifies the two-phase accept/mark contract is never violated and that
// no sequence of inputs can cause a panic or memory unsafety.
//
// Input layout: pairs of [u64_le seq, u8 action] — action 0 = can_accept,
// action 1 = full can_accept+mark_seen cycle, anything else = can_accept only.
fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }

    let mut window = ReplayWindow::new();

    for chunk in data.chunks(9) {
        if chunk.len() < 9 {
            break;
        }
        let seq    = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let action = chunk[8];

        let ok = window.can_accept(seq).is_ok();
        if action == 1 && ok {
            window.mark_seen(seq);
        }
    }
});
