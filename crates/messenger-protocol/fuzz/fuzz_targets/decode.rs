#![no_main]
use libfuzzer_sys::fuzz_target;
use messenger_protocol::{ApplicationEnvelope, TransportFrame};

fuzz_target!(|data: &[u8]| {
    let _ = TransportFrame::decode(data);
    let _ = ApplicationEnvelope::decode(data);
});
