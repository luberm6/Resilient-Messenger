# Architecture

Rust owns the protocol, anonymous identity, OpenMLS integration, encrypted local SQLite state, Axum backend and stateless relay. UniFFI is the only mobile boundary; SwiftUI and Compose must never write SQLite or manipulate MLS state directly. PostgreSQL is the durable server source of truth. Render is a deployment target, not a core dependency.

`messenger-protocol` defines v1 as a strict canonical RFC 8949 CBOR subset. A transport frame is a fixed six-element array; an encrypted application envelope is a fixed five-element array. The open frame carries only version, integer kind, 16-byte idempotency ID, TTL and opaque ciphertext/control bytes. It never carries display name, username, phone, email, plaintext, group title, preview or contacts.

Every 1:1 or group conversation is an MLS group; every device is an MLS member and the server is only a Delivery Service. `messenger-crypto` uses OpenMLS 0.9.0 and the X25519/ChaCha20-Poly1305/SHA-256/Ed25519 ciphersuite. Credential bytes bind device ID, account-root fingerprint and device-certificate fingerprint. OpenMLS storage snapshots and local message rows are encrypted before leaving their owning Rust component.

The delivery model stores one opaque `group_events` row regardless of recipient count. Per-device group/global cursors track progress. A committed row emits PostgreSQL `NOTIFY` only as a wake-up hint; reconnect, WebSocket and HTTPS long-poll all recover from database cursors. WebSocket over TLS/443 is primary, HTTPS CBOR over TLS/443 is fallback. A signed, anti-rollback relay directory drives automatic endpoint selection while the persistent outbox remains independent of any connection.
