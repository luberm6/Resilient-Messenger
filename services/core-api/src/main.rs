#![forbid(unsafe_code)]

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use core_api::{ApiError, Backend, EVENT_NOTIFY_CHANNEL, MembershipOperation, UploadedEvent};
use messenger_identity::DeviceCertificate;
use messenger_protocol::{ErrorCode, FrameType, Id, PROTOCOL_VERSION, TransportFrame};
use sqlx::{
    PgPool,
    postgres::{PgListener, PgPoolOptions},
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing::{error, info};

#[derive(Clone)]
struct App {
    db: PgPool,
    backend: Backend,
    requests: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().json().init();
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        error!("DATABASE_URL missing");
        std::process::exit(2)
    });
    let db = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect_lazy(&url)
        .expect("database url");
    let backend = Backend::new(db.clone());
    if std::env::args().nth(1).as_deref() == Some("migrate") {
        backend.migrate().await.expect("migration failed");
        return;
    }
    let state = App {
        db,
        backend,
        requests: Arc::new(AtomicU64::new(0)),
        errors: Arc::new(AtomicU64::new(0)),
    };
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/v1/sync", post(binary_api))
        .route("/v1/long-poll", post(binary_long_poll))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(TraceLayer::new_for_http())
        .layer(CatchPanicLayer::new())
        .with_state(state);
    let addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()
        .expect("bind address");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    info!(%addr, "core api started");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server")
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    info!("graceful shutdown requested");
}

async fn readyz(State(app): State<App>) -> Response {
    match sqlx::query("SELECT 1").execute(&app.db).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(_) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            Id([0; 16]),
            ErrorCode::Malformed,
        ),
    }
}

async fn metrics(State(app): State<App>) -> String {
    format!(
        "resilient_api_up 1\nresilient_api_requests_total {}\nresilient_api_errors_total {}\n",
        app.requests.load(Ordering::Relaxed),
        app.errors.load(Ordering::Relaxed)
    )
}

async fn binary_api(State(app): State<App>, body: Bytes) -> Response {
    handle_binary(&app, body, false).await
}

async fn binary_long_poll(State(app): State<App>, body: Bytes) -> Response {
    handle_binary(&app, body, true).await
}

async fn handle_binary(app: &App, body: Bytes, long_poll: bool) -> Response {
    app.requests.fetch_add(1, Ordering::Relaxed);
    let frame = match TransportFrame::decode(&body) {
        Ok(frame) => frame,
        Err(_) => {
            app.errors.fetch_add(1, Ordering::Relaxed);
            return error_response(StatusCode::BAD_REQUEST, Id([0; 16]), ErrorCode::Malformed);
        }
    };
    info!(kind = ?frame.kind, frame_bytes = body.len(), "binary frame received");
    let mut rate_scope = b"frame/v1/".to_vec();
    rate_scope.extend_from_slice(&frame.client_message_id.0);
    if app
        .backend
        .check_rate_limit(&rate_scope, 120, 60)
        .await
        .is_err()
    {
        app.errors.fetch_add(1, Ordering::Relaxed);
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            frame.client_message_id,
            ErrorCode::RateLimited,
        );
    }
    if long_poll && frame.kind != FrameType::SyncRequest {
        app.errors.fetch_add(1, Ordering::Relaxed);
        return error_response(
            StatusCode::BAD_REQUEST,
            frame.client_message_id,
            ErrorCode::Malformed,
        );
    }
    // Subscribe before the first query so a concurrent commit cannot be lost
    // between observing an empty page and beginning to wait.
    let mut listener = if long_poll {
        match PgListener::connect_with(&app.db).await {
            Ok(mut listener) => match listener.listen(EVENT_NOTIFY_CHANNEL).await {
                Ok(()) => Some(listener),
                Err(_) => None,
            },
            _ => None,
        }
    } else {
        None
    };
    match dispatch(&app.backend, &frame).await {
        Ok(mut response) => {
            if response.kind == FrameType::SyncBatch
                && matches!(response.body.first(), Some(0 | 1))
                && response.body.get(1) == Some(&0)
                && let Some(listener) = listener.as_mut()
            {
                let _ = tokio::time::timeout(Duration::from_secs(20), listener.recv()).await;
                match dispatch(&app.backend, &frame).await {
                    Ok(retried) => response = retried,
                    Err(error) => {
                        app.errors.fetch_add(1, Ordering::Relaxed);
                        let (status, code) = map_error(&error);
                        return error_response(status, frame.client_message_id, code);
                    }
                }
            }
            cbor_response(StatusCode::OK, response)
        }
        Err(error) => {
            app.errors.fetch_add(1, Ordering::Relaxed);
            let (status, code) = map_error(&error);
            error_response(status, frame.client_message_id, code)
        }
    }
}

async fn dispatch(backend: &Backend, frame: &TransportFrame) -> Result<TransportFrame, ApiError> {
    let response = match frame.kind {
        FrameType::ClientHello => {
            let mut body = Reader::new(&frame.body);
            let account_id = body.array()?;
            let root_public_key = body.array()?;
            let cert = DeviceCertificate {
                device_id: body.array()?,
                device_public_key: body.array()?,
                issued_at: body.u64()?,
                signature: body.array()?,
            };
            body.finish()?;
            backend
                .register_account_device(account_id, root_public_key, &cert)
                .await?;
            (FrameType::ServerHello, Vec::new())
        }
        FrameType::AuthChallenge => {
            let mut body = Reader::new(&frame.body);
            let challenge = backend.begin_challenge(body.array()?).await?;
            body.finish()?;
            let mut encoded = challenge.challenge_id.to_vec();
            encoded.extend_from_slice(&challenge.challenge);
            (FrameType::AuthChallenge, encoded)
        }
        FrameType::AuthResponse => {
            let mut body = Reader::new(&frame.body);
            let tokens = if body.remaining_len() == 80 {
                backend
                    .complete_challenge(body.array()?, body.array()?)
                    .await?
            } else if body.remaining_len() == 112 {
                backend
                    .rotate_refresh(body.array()?, body.array()?, body.array()?)
                    .await?
            } else {
                return Err(ApiError::InvalidInput);
            };
            body.finish()?;
            let mut encoded = tokens.access_token.to_vec();
            encoded.extend_from_slice(&tokens.refresh_token);
            (FrameType::AuthAccepted, encoded)
        }
        FrameType::UploadEnvelope => {
            let mut body = Reader::new(&frame.body);
            let token = body.array()?;
            let author_device_id = backend.authenticate_access(token).await?;
            let operation = body.u8()?;
            let mut encoded = vec![operation];
            match operation {
                1 => {
                    let group_id = body.array()?;
                    let event_id = body.array()?;
                    let event_kind = body.i16()?;
                    let correlation_id = match body.u8()? {
                        0 => None,
                        1 => Some(body.array()?),
                        _ => return Err(ApiError::InvalidInput),
                    };
                    let ciphertext = body.rest().to_vec();
                    let accepted = backend
                        .upload_event(&UploadedEvent {
                            event_id,
                            group_id,
                            author_device_id,
                            client_message_id: frame.client_message_id.0,
                            event_kind,
                            ciphertext,
                            correlation_id,
                        })
                        .await?;
                    encoded.extend_from_slice(&(accepted.cursor as u64).to_be_bytes());
                    encoded.push(u8::from(accepted.duplicate));
                }
                2 => {
                    let package_id = body.array()?;
                    let package = body.rest();
                    backend
                        .publish_key_package(author_device_id, package_id, package)
                        .await?;
                }
                3 => {
                    let group_id = body.array()?;
                    body.finish()?;
                    let account_id = backend.device_account_id(author_device_id).await?;
                    backend
                        .create_group(group_id, author_device_id, account_id)
                        .await?;
                }
                4 => {
                    let request = MembershipOperation {
                        correlation_id: body.array()?,
                        group_id: body.array()?,
                        author_device_id,
                        target_device_id: body.array()?,
                        role: i16::from(body.u8()?),
                        remove: match body.u8()? {
                            0 => false,
                            1 => true,
                            _ => return Err(ApiError::InvalidInput),
                        },
                        signature: body.array()?,
                    };
                    body.finish()?;
                    encoded.push(u8::from(
                        backend.apply_membership_operation(&request).await?,
                    ));
                }
                5 => {
                    let target = body.array()?;
                    let group = body.array()?;
                    let welcome_id = body.array()?;
                    let welcome = body.rest();
                    backend
                        .upload_welcome(author_device_id, target, group, welcome_id, welcome)
                        .await?;
                }
                6 => {
                    let recovery_identifier = body.array()?;
                    let blob = body.rest();
                    let account_id = backend.device_account_id(author_device_id).await?;
                    backend
                        .store_recovery_package(account_id, recovery_identifier, blob)
                        .await?;
                }
                _ => return Err(ApiError::InvalidInput),
            }
            (FrameType::UploadAccepted, encoded)
        }
        FrameType::SyncRequest => {
            let mut body = Reader::new(&frame.body);
            let token = body.array()?;
            let device_id = backend.authenticate_access(token).await?;
            let operation = body.u8()?;
            let mut encoded = vec![operation];
            match operation {
                0 | 1 => {
                    let group_id = (operation == 0).then(|| body.array()).transpose()?;
                    let after = body.u64()? as i64;
                    let limit = i64::from(body.u8()?);
                    body.finish()?;
                    let events = if let Some(group_id) = group_id {
                        backend
                            .sync_group(device_id, group_id, after, limit)
                            .await?
                    } else {
                        backend.sync_global(device_id, after, limit).await?
                    };
                    encoded.push(events.len() as u8);
                    for event in events {
                        encoded.extend_from_slice(&(event.cursor as u64).to_be_bytes());
                        encoded.extend_from_slice(&event.event_id);
                        encoded.extend_from_slice(&event.event_kind.to_be_bytes());
                        encoded.extend_from_slice(&(event.ciphertext.len() as u32).to_be_bytes());
                        encoded.extend_from_slice(&event.ciphertext);
                    }
                }
                2 => {
                    let target = body.array()?;
                    body.finish()?;
                    match backend.fetch_key_package(target).await? {
                        Some((id, package)) => {
                            encoded.push(1);
                            encoded.extend_from_slice(&id);
                            encoded.extend_from_slice(&package);
                        }
                        None => encoded.push(0),
                    }
                }
                3 => {
                    let limit = i64::from(body.u8()?);
                    body.finish()?;
                    let welcomes = backend.fetch_welcomes(device_id, limit).await?;
                    encoded.push(welcomes.len() as u8);
                    for (welcome_id, group_id, welcome) in welcomes {
                        encoded.extend_from_slice(&welcome_id);
                        encoded.extend_from_slice(&group_id);
                        encoded.extend_from_slice(&(welcome.len() as u32).to_be_bytes());
                        encoded.extend_from_slice(&welcome);
                    }
                }
                _ => return Err(ApiError::InvalidInput),
            }
            (FrameType::SyncBatch, encoded)
        }
        FrameType::RelayDirectoryRequest => {
            let mut body = Reader::new(&frame.body);
            let operation = body.u8()?;
            if operation != 1 {
                return Err(ApiError::InvalidInput);
            }
            let recovery_identifier = body.array()?;
            body.finish()?;
            let mut encoded = vec![operation];
            match backend.fetch_recovery_package(recovery_identifier).await? {
                Some(blob) => {
                    encoded.push(1);
                    encoded.extend_from_slice(&blob);
                }
                None => encoded.push(0),
            }
            (FrameType::RelayDirectoryResponse, encoded)
        }
        FrameType::DeliveryReceiptBatch | FrameType::ReadReceiptBatch => {
            let mut body = Reader::new(&frame.body);
            let token = body.array()?;
            let device_id = backend.authenticate_access(token).await?;
            let count = usize::from(body.u8()?);
            if count > 50 {
                return Err(ApiError::InvalidInput);
            }
            let mut event_ids = Vec::with_capacity(count);
            for _ in 0..count {
                event_ids.push(body.array()?);
            }
            body.finish()?;
            backend
                .record_receipts(
                    device_id,
                    &event_ids,
                    if frame.kind == FrameType::DeliveryReceiptBatch {
                        1
                    } else {
                        2
                    },
                )
                .await?;
            (frame.kind, Vec::new())
        }
        FrameType::Ping => (FrameType::Pong, frame.body.clone()),
        _ => return Err(ApiError::InvalidInput),
    };
    Ok(TransportFrame {
        version: PROTOCOL_VERSION,
        kind: response.0,
        client_message_id: frame.client_message_id,
        ttl_seconds: 0,
        body: response.1,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], ApiError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(ApiError::InvalidInput)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ApiError::InvalidInput)?;
        self.position = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], ApiError> {
        self.take(N)?.try_into().map_err(|_| ApiError::InvalidInput)
    }
    fn u8(&mut self) -> Result<u8, ApiError> {
        Ok(self.take(1)?[0])
    }
    fn i16(&mut self) -> Result<i16, ApiError> {
        Ok(i16::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, ApiError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn rest(&mut self) -> &'a [u8] {
        let value = &self.bytes[self.position..];
        self.position = self.bytes.len();
        value
    }
    fn remaining_len(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }
    fn finish(self) -> Result<(), ApiError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ApiError::InvalidInput)
        }
    }
}

fn map_error(error: &ApiError) -> (StatusCode, ErrorCode) {
    match error {
        ApiError::Expired => (StatusCode::UNAUTHORIZED, ErrorCode::Replay),
        ApiError::Replay | ApiError::TokenReuse => (StatusCode::CONFLICT, ErrorCode::Replay),
        ApiError::Conflict => (StatusCode::CONFLICT, ErrorCode::Duplicate),
        ApiError::Unauthorized | ApiError::InvalidCredentials => {
            (StatusCode::UNAUTHORIZED, ErrorCode::Malformed)
        }
        ApiError::CursorRegression => (StatusCode::CONFLICT, ErrorCode::CursorRegression),
        ApiError::InvalidInput => (StatusCode::BAD_REQUEST, ErrorCode::Malformed),
        ApiError::Database => (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Malformed),
    }
}

fn cbor_response(status: StatusCode, frame: TransportFrame) -> Response {
    let body = frame.encode().unwrap_or_default();
    let mut response = Response::new(axum::body::Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/cbor"),
    );
    response
}

fn error_response(status: StatusCode, id: Id, code: ErrorCode) -> Response {
    cbor_response(
        status,
        TransportFrame {
            version: PROTOCOL_VERSION,
            kind: FrameType::Error,
            client_message_id: id,
            ttl_seconds: 0,
            body: vec![code as u8],
        },
    )
}
