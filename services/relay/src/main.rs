#![forbid(unsafe_code)]
use axum::{
    Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use messenger_protocol::TransportFrame;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tracing::{info, warn};

#[derive(Clone)]
struct RelayState {
    core_sync_url: Arc<str>,
    core_long_poll_url: Arc<str>,
    core_health_url: Arc<str>,
    http: reqwest::Client,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let core = std::env::var("CORE_API_URL")
        .unwrap_or_else(|_| "http://core-api:8080".into())
        .trim_end_matches('/')
        .to_string();
    let state = RelayState {
        core_sync_url: format!("{core}/v1/sync").into(),
        core_long_poll_url: format!("{core}/v1/long-poll").into(),
        core_health_url: format!("{core}/healthz").into(),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("HTTP client"),
    };
    let app = Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/readyz", get(ready))
        .route("/v1/relay", post(relay_https))
        .route("/v1/ws", get(relay_websocket))
        .layer(DefaultBodyLimit::max(messenger_protocol::MAX_FRAME_SIZE))
        .with_state(state);
    let addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8081".into())
        .parse()
        .expect("BIND_ADDR");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("relay bind");
    info!(%addr, "opaque relay started");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("relay server");
}

async fn ready(State(state): State<RelayState>) -> StatusCode {
    match state.http.get(state.core_health_url.as_ref()).send().await {
        Ok(value) if value.status().is_success() => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn relay_https(State(state): State<RelayState>, body: Bytes) -> Response {
    match forward(&state, &body, false).await {
        Ok(value) => cbor_response(StatusCode::OK, value),
        Err(status) => cbor_error(status),
    }
}

async fn relay_websocket(
    ws: WebSocketUpgrade,
    State(state): State<RelayState>,
) -> impl IntoResponse {
    ws.max_message_size(messenger_protocol::MAX_FRAME_SIZE)
        .on_upgrade(move |socket| websocket_loop(socket, state))
}

async fn websocket_loop(mut socket: WebSocket, state: RelayState) {
    while let Some(message) = socket.next().await {
        let bytes = match message {
            Ok(Message::Binary(value)) => value,
            Ok(Message::Ping(value)) => {
                if socket.send(Message::Pong(value)).await.is_err() {
                    return;
                }
                continue;
            }
            Ok(Message::Close(_)) | Err(_) => return,
            _ => continue,
        };
        let long_poll = TransportFrame::decode(&bytes)
            .is_ok_and(|frame| frame.kind == messenger_protocol::FrameType::SyncRequest);
        match forward(&state, &bytes, long_poll).await {
            Ok(response) => {
                if socket.send(Message::Binary(response.into())).await.is_err() {
                    return;
                }
            }
            Err(status) => {
                warn!(%status, frame_bytes=bytes.len(), "relay rejected frame");
                if socket.send(Message::Close(None)).await.is_err() {
                    return;
                }
                return;
            }
        }
    }
}

async fn forward(state: &RelayState, body: &[u8], long_poll: bool) -> Result<Vec<u8>, StatusCode> {
    let frame = TransportFrame::decode(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    info!(kind=?frame.kind, frame_bytes=body.len(), "forwarding opaque frame");
    let response = state
        .http
        .post(if long_poll {
            state.core_long_poll_url.as_ref()
        } else {
            state.core_sync_url.as_ref()
        })
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if !response.status().is_success() {
        return Err(StatusCode::BAD_GATEWAY);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    TransportFrame::decode(&bytes).map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(bytes.to_vec())
}

fn cbor_response(status: StatusCode, value: Vec<u8>) -> Response {
    let mut response = Response::new(axum::body::Body::from(value));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/cbor"),
    );
    response
}
fn cbor_error(status: StatusCode) -> Response {
    cbor_response(status, vec![0x82, 0x01, status.as_u16().min(255) as u8])
}
