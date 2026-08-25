use messenger_protocol::{FrameType, Id, PROTOCOL_VERSION, TransportFrame};
use std::time::Instant;

fn main() {
    let events = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100_000)
        .max(1);
    let frame = TransportFrame {
        version: PROTOCOL_VERSION,
        kind: FrameType::UploadEnvelope,
        client_message_id: Id([4; 16]),
        ttl_seconds: 604_800,
        body: vec![0xA5; 144],
    };
    let encoded = frame.encode().expect("canonical frame");
    let started = Instant::now();
    for _ in 0..events {
        let parsed = TransportFrame::decode(&encoded).expect("decode");
        std::hint::black_box(parsed);
    }
    let elapsed = started.elapsed();
    println!(
        "events={events} frame_bytes={} events_per_second={:.0} total_mebibytes={:.2}",
        encoded.len(),
        events as f64 / elapsed.as_secs_f64(),
        encoded.len() as f64 * events as f64 / 1_048_576.0
    );
}
