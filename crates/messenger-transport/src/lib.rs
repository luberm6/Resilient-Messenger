#![forbid(unsafe_code)]
//! Signed relay selection with WebSocket primary and HTTPS-CBOR fallback.

use async_trait::async_trait;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use messenger_protocol::{MAX_FRAME_SIZE, TransportFrame};
use reqwest::header::CONTENT_TYPE;
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayEndpoint {
    pub endpoint_id: [u8; 16],
    pub websocket_url: String,
    pub https_url: String,
    pub priority: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRelayDirectory {
    pub version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub endpoints: Vec<RelayEndpoint>,
    pub signature: [u8; 64],
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum TransportError {
    #[error("relay directory signature is invalid")]
    InvalidDirectorySignature,
    #[error("relay directory is expired or not yet valid")]
    ExpiredDirectory,
    #[error("relay directory rollback was rejected")]
    DirectoryRollback,
    #[error("frame exceeds the protocol limit")]
    FrameTooLarge,
    #[error("all relay transports failed; outbox retained")]
    Unavailable,
    #[error("relay returned invalid data")]
    InvalidResponse,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ByteCounters {
    pub sent: u64,
    pub received: u64,
    pub attempts: u64,
    pub websocket_failures: u64,
    pub https_failures: u64,
    pub relay_switches: u64,
}

impl SignedRelayDirectory {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TransportError> {
        if self.endpoints.len() > 32 {
            return Err(TransportError::InvalidResponse);
        }
        let mut out = b"resilient/relay-directory/v1".to_vec();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&(self.endpoints.len() as u16).to_be_bytes());
        let mut endpoints = self.endpoints.clone();
        endpoints.sort_by_key(|value| (value.priority, value.endpoint_id));
        for endpoint in endpoints {
            out.extend_from_slice(&endpoint.endpoint_id);
            out.extend_from_slice(&endpoint.priority.to_be_bytes());
            put_string(&mut out, &endpoint.websocket_url)?;
            put_string(&mut out, &endpoint.https_url)?;
        }
        Ok(out)
    }

    pub fn verify(
        &self,
        public_key: &[u8; 32],
        now: u64,
        minimum_version: u64,
    ) -> Result<(), TransportError> {
        if self.version < minimum_version {
            return Err(TransportError::DirectoryRollback);
        }
        if self.issued_at > now.saturating_add(300)
            || self.expires_at <= now
            || self.issued_at >= self.expires_at
        {
            return Err(TransportError::ExpiredDirectory);
        }
        VerifyingKey::from_bytes(public_key)
            .map_err(|_| TransportError::InvalidDirectorySignature)?
            .verify(
                &self.signing_bytes()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| TransportError::InvalidDirectorySignature)
    }

    pub fn encode(&self) -> Result<Vec<u8>, TransportError> {
        let mut value = self.signing_bytes()?;
        value.extend_from_slice(&self.signature);
        Ok(value)
    }

    pub fn decode(value: &[u8]) -> Result<Self, TransportError> {
        let mut reader = DirectoryReader::new(value);
        if reader.take(b"resilient/relay-directory/v1".len())? != b"resilient/relay-directory/v1" {
            return Err(TransportError::InvalidResponse);
        }
        let version = reader.u64()?;
        let issued_at = reader.u64()?;
        let expires_at = reader.u64()?;
        let count = usize::from(reader.u16()?);
        if count > 32 {
            return Err(TransportError::InvalidResponse);
        }
        let mut endpoints = Vec::with_capacity(count);
        for _ in 0..count {
            let endpoint_id = reader.array()?;
            let priority = reader.u16()?;
            let websocket_url = reader.string()?;
            let https_url = reader.string()?;
            if !(websocket_url.starts_with("wss://") || websocket_url.starts_with("ws://"))
                || !(https_url.starts_with("https://") || https_url.starts_with("http://"))
            {
                return Err(TransportError::InvalidResponse);
            }
            endpoints.push(RelayEndpoint {
                endpoint_id,
                websocket_url,
                https_url,
                priority,
            });
        }
        let signature = reader.array()?;
        reader.finish()?;
        Ok(Self {
            version,
            issued_at,
            expires_at,
            endpoints,
            signature,
        })
    }
}

#[async_trait]
pub trait EndpointSender: Send + Sync {
    async fn send_websocket(
        &self,
        endpoint: &RelayEndpoint,
        frame: &[u8],
    ) -> Result<Vec<u8>, TransportError>;
    async fn send_https(
        &self,
        endpoint: &RelayEndpoint,
        frame: &[u8],
    ) -> Result<Vec<u8>, TransportError>;
}

pub struct NetworkSender {
    http: reqwest::Client,
    timeout: Duration,
}
impl NetworkSender {
    pub fn new(timeout: Duration) -> Result<Self, TransportError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()
            .map_err(|_| TransportError::Unavailable)?;
        Ok(Self { http, timeout })
    }
}

#[async_trait]
impl EndpointSender for NetworkSender {
    async fn send_websocket(
        &self,
        endpoint: &RelayEndpoint,
        frame: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let (mut socket, _) =
            tokio::time::timeout(self.timeout, connect_async(&endpoint.websocket_url))
                .await
                .map_err(|_| TransportError::Unavailable)?
                .map_err(|_| TransportError::Unavailable)?;
        socket
            .send(Message::Binary(frame.to_vec().into()))
            .await
            .map_err(|_| TransportError::Unavailable)?;
        match tokio::time::timeout(self.timeout, socket.next())
            .await
            .map_err(|_| TransportError::Unavailable)?
        {
            Some(Ok(Message::Binary(value))) if value.len() <= MAX_FRAME_SIZE => Ok(value.to_vec()),
            _ => Err(TransportError::InvalidResponse),
        }
    }
    async fn send_https(
        &self,
        endpoint: &RelayEndpoint,
        frame: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let response = self
            .http
            .post(&endpoint.https_url)
            .header(CONTENT_TYPE, "application/cbor")
            .body(frame.to_vec())
            .send()
            .await
            .map_err(|_| TransportError::Unavailable)?;
        if !response.status().is_success() {
            return Err(TransportError::Unavailable);
        }
        let value = response
            .bytes()
            .await
            .map_err(|_| TransportError::InvalidResponse)?;
        if value.len() > MAX_FRAME_SIZE {
            return Err(TransportError::FrameTooLarge);
        }
        Ok(value.to_vec())
    }
}

struct QueuedFrame {
    client_message_id: [u8; 16],
    bytes: Vec<u8>,
}
#[derive(Default)]
struct Health {
    failures: u32,
    retry_after: u64,
}

pub struct TransportManager<S: EndpointSender> {
    sender: S,
    directory: SignedRelayDirectory,
    verification_key: [u8; 32],
    outbox: VecDeque<QueuedFrame>,
    health: HashMap<[u8; 16], Health>,
    counters: ByteCounters,
    preferred_endpoint: Option<[u8; 16]>,
}

impl<S: EndpointSender> TransportManager<S> {
    pub fn new(
        sender: S,
        directory: SignedRelayDirectory,
        verification_key: [u8; 32],
        now: u64,
    ) -> Result<Self, TransportError> {
        directory.verify(&verification_key, now, 0)?;
        Ok(Self {
            sender,
            directory,
            verification_key,
            outbox: VecDeque::new(),
            health: HashMap::new(),
            counters: ByteCounters::default(),
            preferred_endpoint: None,
        })
    }
    pub fn update_directory(
        &mut self,
        next: SignedRelayDirectory,
        now: u64,
    ) -> Result<(), TransportError> {
        next.verify(&self.verification_key, now, self.directory.version)?;
        self.directory = next;
        Ok(())
    }
    pub fn enqueue(&mut self, frame: &TransportFrame) -> Result<(), TransportError> {
        let bytes = frame.encode().map_err(|_| TransportError::FrameTooLarge)?;
        if !self
            .outbox
            .iter()
            .any(|queued| queued.client_message_id == frame.client_message_id.0)
        {
            self.outbox.push_back(QueuedFrame {
                client_message_id: frame.client_message_id.0,
                bytes,
            });
        }
        Ok(())
    }
    pub fn pending_count(&self) -> usize {
        self.outbox.len()
    }
    pub fn counters(&self) -> ByteCounters {
        self.counters
    }

    /// A platform network-path change allows one immediate retry without polling.
    pub fn notify_network_change(&mut self) {
        for health in self.health.values_mut() {
            health.retry_after = 0;
        }
    }

    pub fn next_retry_at(&self) -> Option<u64> {
        self.health
            .values()
            .filter(|health| health.retry_after > 0)
            .map(|health| health.retry_after)
            .min()
    }

    pub async fn flush(&mut self, now: u64) -> Result<Vec<Vec<u8>>, TransportError> {
        let mut responses = Vec::new();
        while let Some(frame) = self.outbox.front() {
            let mut endpoints = self.directory.endpoints.clone();
            endpoints.sort_by_key(|endpoint| {
                (
                    self.preferred_endpoint != Some(endpoint.endpoint_id),
                    endpoint.priority,
                )
            });
            let highest_priority = endpoints.first().map(|endpoint| endpoint.endpoint_id);
            let mut delivered = None;
            for endpoint in &endpoints {
                let health = self.health.entry(endpoint.endpoint_id).or_default();
                if health.retry_after > now {
                    continue;
                }
                self.counters.attempts += 1;
                self.counters.sent += frame.bytes.len() as u64;
                let response = match self.sender.send_websocket(endpoint, &frame.bytes).await {
                    Ok(value) => Ok(value),
                    Err(_) => {
                        self.counters.websocket_failures += 1;
                        self.counters.attempts += 1;
                        self.counters.sent += frame.bytes.len() as u64;
                        self.sender.send_https(endpoint, &frame.bytes).await
                    }
                };
                match response {
                    Ok(value) => {
                        health.failures = 0;
                        health.retry_after = 0;
                        self.counters.received += value.len() as u64;
                        if self.preferred_endpoint != Some(endpoint.endpoint_id)
                            && (self.preferred_endpoint.is_some()
                                || highest_priority != Some(endpoint.endpoint_id))
                        {
                            self.counters.relay_switches += 1;
                        }
                        self.preferred_endpoint = Some(endpoint.endpoint_id);
                        delivered = Some(value);
                        break;
                    }
                    Err(_) => {
                        self.counters.https_failures += 1;
                        health.failures = health.failures.saturating_add(1);
                        let base = 1_u64 << health.failures.min(8);
                        let jitter = u64::from(endpoint.endpoint_id[0]) % base.max(1);
                        health.retry_after = now.saturating_add(base + jitter);
                    }
                }
            }
            match delivered {
                Some(value) => {
                    self.outbox.pop_front();
                    responses.push(value);
                }
                None => return Err(TransportError::Unavailable),
            }
        }
        Ok(responses)
    }
}

pub fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn put_string(out: &mut Vec<u8>, value: &str) -> Result<(), TransportError> {
    if value.len() > 2048 {
        return Err(TransportError::InvalidResponse);
    }
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

struct DirectoryReader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> DirectoryReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], TransportError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(TransportError::InvalidResponse)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(TransportError::InvalidResponse)?;
        self.position = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], TransportError> {
        self.take(N)?
            .try_into()
            .map_err(|_| TransportError::InvalidResponse)
    }
    fn u16(&mut self) -> Result<u16, TransportError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, TransportError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn string(&mut self) -> Result<String, TransportError> {
        let length = usize::from(self.u16()?);
        if length > 2048 {
            return Err(TransportError::InvalidResponse);
        }
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| TransportError::InvalidResponse)
    }
    fn finish(self) -> Result<(), TransportError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(TransportError::InvalidResponse)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use messenger_protocol::{FrameType, Id, PROTOCOL_VERSION};
    use rand_core::OsRng;
    use std::sync::Mutex;

    struct FakeSender {
        attempts: Mutex<Vec<([u8; 16], &'static str)>>,
        fail_a: bool,
        fail_ws: bool,
    }
    #[async_trait]
    impl EndpointSender for FakeSender {
        async fn send_websocket(
            &self,
            endpoint: &RelayEndpoint,
            frame: &[u8],
        ) -> Result<Vec<u8>, TransportError> {
            self.attempts
                .lock()
                .unwrap()
                .push((endpoint.endpoint_id, "ws"));
            if self.fail_ws || (self.fail_a && endpoint.endpoint_id == [1; 16]) {
                Err(TransportError::Unavailable)
            } else {
                Ok(frame.to_vec())
            }
        }
        async fn send_https(
            &self,
            endpoint: &RelayEndpoint,
            frame: &[u8],
        ) -> Result<Vec<u8>, TransportError> {
            self.attempts
                .lock()
                .unwrap()
                .push((endpoint.endpoint_id, "https"));
            if self.fail_a && endpoint.endpoint_id == [1; 16] {
                Err(TransportError::Unavailable)
            } else {
                Ok(frame.to_vec())
            }
        }
    }
    fn signed_directory(key: &SigningKey, now: u64) -> SignedRelayDirectory {
        let mut value = SignedRelayDirectory {
            version: 2,
            issued_at: now - 1,
            expires_at: now + 3600,
            endpoints: vec![
                RelayEndpoint {
                    endpoint_id: [1; 16],
                    websocket_url: "wss://a/ws".into(),
                    https_url: "https://a/sync".into(),
                    priority: 1,
                },
                RelayEndpoint {
                    endpoint_id: [2; 16],
                    websocket_url: "wss://b/ws".into(),
                    https_url: "https://b/sync".into(),
                    priority: 2,
                },
            ],
            signature: [0; 64],
        };
        value.signature = key.sign(&value.signing_bytes().unwrap()).to_bytes();
        value
    }
    fn frame() -> TransportFrame {
        TransportFrame {
            version: PROTOCOL_VERSION,
            kind: FrameType::UploadEnvelope,
            client_message_id: Id([8; 16]),
            ttl_seconds: 60,
            body: b"opaque".to_vec(),
        }
    }

    #[tokio::test]
    async fn relay_a_failure_switches_to_b_without_losing_or_duplicating_outbox() {
        let key = SigningKey::generate(&mut OsRng);
        let now = 1_000_000;
        let sender = FakeSender {
            attempts: Mutex::new(Vec::new()),
            fail_a: true,
            fail_ws: false,
        };
        let mut manager = TransportManager::new(
            sender,
            signed_directory(&key, now),
            key.verifying_key().to_bytes(),
            now,
        )
        .unwrap();
        manager.enqueue(&frame()).unwrap();
        manager.enqueue(&frame()).unwrap();
        assert_eq!(manager.pending_count(), 1);
        assert_eq!(manager.flush(now).await.unwrap().len(), 1);
        assert_eq!(manager.pending_count(), 0);
        assert_eq!(manager.counters().relay_switches, 1);
        assert_eq!(
            manager
                .sender
                .attempts
                .lock()
                .unwrap()
                .iter()
                .map(|x| x.0)
                .collect::<Vec<_>>(),
            vec![[1; 16], [1; 16], [2; 16]]
        );
        manager
            .enqueue(&TransportFrame {
                client_message_id: Id([9; 16]),
                ..frame()
            })
            .unwrap();
        manager.flush(now + 60).await.unwrap();
        assert_eq!(
            manager.sender.attempts.lock().unwrap().last().unwrap().0,
            [2; 16]
        );
        manager.notify_network_change();
    }
    #[tokio::test]
    async fn websocket_blocked_uses_https_and_invalid_directory_is_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let now = 2_000_000;
        let sender = FakeSender {
            attempts: Mutex::new(Vec::new()),
            fail_a: false,
            fail_ws: true,
        };
        let mut manager = TransportManager::new(
            sender,
            signed_directory(&key, now),
            key.verifying_key().to_bytes(),
            now,
        )
        .unwrap();
        let encoded_directory = manager.directory.encode().unwrap();
        assert_eq!(
            SignedRelayDirectory::decode(&encoded_directory).unwrap(),
            manager.directory
        );
        manager.enqueue(&frame()).unwrap();
        assert_eq!(manager.flush(now).await.unwrap().len(), 1);
        let mut tampered = signed_directory(&key, now);
        tampered.endpoints[0].priority = 9;
        assert_eq!(
            manager.update_directory(tampered, now),
            Err(TransportError::InvalidDirectorySignature)
        );
        let mut expired = signed_directory(&key, now);
        expired.expires_at = now;
        expired.signature = key.sign(&expired.signing_bytes().unwrap()).to_bytes();
        assert_eq!(
            manager.update_directory(expired, now),
            Err(TransportError::ExpiredDirectory)
        );
    }

    #[tokio::test]
    async fn real_websocket_and_https_binary_transports_round_trip() {
        use axum::{
            Router,
            body::Bytes,
            extract::{
                WebSocketUpgrade,
                ws::{Message as AxumMessage, WebSocket},
            },
            response::IntoResponse,
            routing::{get, post},
        };
        async fn https_echo(body: Bytes) -> Bytes {
            body
        }
        async fn ws_echo(upgrade: WebSocketUpgrade) -> impl IntoResponse {
            upgrade.on_upgrade(|mut socket: WebSocket| async move {
                if let Some(Ok(AxumMessage::Binary(value))) = socket.recv().await {
                    let _ = socket.send(AxumMessage::Binary(value)).await;
                }
            })
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/sync", post(https_echo))
                    .route("/ws", get(ws_echo)),
            )
            .await
            .unwrap();
        });
        let endpoint = RelayEndpoint {
            endpoint_id: [7; 16],
            websocket_url: format!("ws://{addr}/ws"),
            https_url: format!("http://{addr}/sync"),
            priority: 1,
        };
        let sender = NetworkSender::new(Duration::from_secs(3)).unwrap();
        let encoded = frame().encode().unwrap();
        assert_eq!(
            sender.send_websocket(&endpoint, &encoded).await.unwrap(),
            encoded
        );
        assert_eq!(
            sender.send_https(&endpoint, &encoded).await.unwrap(),
            encoded
        );
    }
}
