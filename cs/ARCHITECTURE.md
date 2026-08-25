# Architecture

Rust owns shared protocol, identity, cryptographic integration, local SQLite state, Axum API and relay. Clients use UniFFI bindings with SwiftUI and Compose shells. PostgreSQL is server state. Canonical CBOR is the wire format. WebSocket/TLS is primary; HTTPS batch/sync is fallback. Render is deployment-only, never a core dependency.
