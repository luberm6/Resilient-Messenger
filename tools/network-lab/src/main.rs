use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use messenger_protocol::{FrameType, Id, PROTOCOL_VERSION, TransportFrame};
use messenger_transport::{
    EndpointSender, RelayEndpoint, SignedRelayDirectory, TransportError, TransportManager,
};
use rand_core::OsRng;

struct LabSender;
#[async_trait]
impl EndpointSender for LabSender {
    async fn send_websocket(
        &self,
        endpoint: &RelayEndpoint,
        _: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let _ = endpoint;
        Err(TransportError::Unavailable)
    }
    async fn send_https(
        &self,
        endpoint: &RelayEndpoint,
        frame: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        if endpoint.endpoint_id == [1; 16] {
            Err(TransportError::Unavailable)
        } else {
            Ok(frame.to_vec())
        }
    }
}

#[tokio::main]
async fn main() {
    let now = messenger_transport::unix_time();
    let key = SigningKey::generate(&mut OsRng);
    let mut directory = SignedRelayDirectory {
        version: 1,
        issued_at: now.saturating_sub(1),
        expires_at: now + 3600,
        endpoints: vec![
            RelayEndpoint {
                endpoint_id: [1; 16],
                websocket_url: "wss://blocked-a.invalid/v1/ws".into(),
                https_url: "https://blocked-a.invalid/v1/relay".into(),
                priority: 1,
            },
            RelayEndpoint {
                endpoint_id: [2; 16],
                websocket_url: "wss://blocked-websocket.invalid/v1/ws".into(),
                https_url: "https://relay-b.invalid/v1/relay".into(),
                priority: 2,
            },
        ],
        signature: [0; 64],
    };
    directory.signature = key
        .sign(&directory.signing_bytes().expect("directory encoding"))
        .to_bytes();
    let mut manager =
        TransportManager::new(LabSender, directory, key.verifying_key().to_bytes(), now)
            .expect("signed directory");
    manager
        .enqueue(&TransportFrame {
            version: PROTOCOL_VERSION,
            kind: FrameType::UploadEnvelope,
            client_message_id: Id([9; 16]),
            ttl_seconds: 60,
            body: b"opaque MLS event".to_vec(),
        })
        .expect("frame");
    let response = manager.flush(now).await.expect("Relay B HTTPS fallback");
    println!(
        "failover=relay-a-to-relay-b pending={} replies={} counters={:?}",
        manager.pending_count(),
        response.len(),
        manager.counters()
    );
}
