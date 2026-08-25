use messenger_protocol::{ApplicationEnvelope, ApplicationType, FrameType, Id, TransportFrame};
fn id(n: u8) -> Id {
    Id([n; 16])
}
fn row(name: &str, bytes: usize) {
    println!("| {name} | {bytes} |")
}
fn main() {
    println!("| Vector | Canonical-CBOR bytes |\n|---|---:|");
    for (name, text) in [
        ("OK", "OK"),
        ("Я дома", "Я дома"),
        ("Привет, ты где?", "Привет, ты где?"),
        ("160 ASCII", &"a".repeat(160)),
        ("160 Russian", &"я".repeat(160)),
    ] {
        let a = ApplicationEnvelope {
            kind: ApplicationType::TextMessage,
            event_id: id(1),
            conversation_id: id(2),
            encrypted_content: text.as_bytes().to_vec(),
        };
        row(name, a.encode().unwrap().len())
    }
    let ack = ApplicationEnvelope {
        kind: ApplicationType::DeliveryReceipt,
        event_id: id(1),
        conversation_id: id(2),
        encrypted_content: vec![],
    };
    row("one delivery ACK", ack.encode().unwrap().len());
    row("batch of 50 ACK", ack.encode().unwrap().len() * 50);
    let meta = ApplicationEnvelope {
        kind: ApplicationType::GroupMetadataUpdate,
        event_id: id(1),
        conversation_id: id(2),
        encrypted_content: vec![0; 32],
    };
    row("group metadata update", meta.encode().unwrap().len());
    let frame = TransportFrame {
        version: 1,
        kind: FrameType::UploadEnvelope,
        client_message_id: id(3),
        ttl_seconds: 604800,
        body: ack.encode().unwrap(),
    };
    row("ACK transport envelope", frame.encode().unwrap().len())
}
