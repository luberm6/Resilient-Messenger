# Progress

## p01 — project foundation

Structure, documentation, CI and minimal Rust services are established. No user-facing messenger function is implemented. Local environment does not provide the Rust/Docker/Apple/Android toolchains, so only checks recorded as executed may be claimed as passed.

Executed: shell syntax check and repository policy/path inspection. Not executed: cargo fmt/clippy/test/build, cargo-deny, Docker Compose validation, SwiftLint and Detekt (their toolchains are unavailable locally). GitHub Actions is the authoritative clean-room CI runner for these checks.

## p02 — compact binary protocol

Implemented v1 deterministic canonical-CBOR profile, fixed compact IDs, 17 transport tags, 11 encrypted application tags, strict size/format validation, malformed/truncated/oversized/map rejection tests and deterministic fuzz corpus. Golden vector and size-report source are present. Native Swift/Kotlin conformance uses the future generated UniFFI binding to this one Rust codec; platform toolchains have not yet been installed or run.

## p03 — backend foundation

Added core-api process configuration, JSON structured logging without payload logging, liveness/readiness/metrics endpoints, graceful shutdown, bounded CBOR sync endpoint, SQLx pool and controlled migration mode. PostgreSQL migration defines the initial ciphertext-only schema and idempotency key for group events.

### Still missing after p03

- Challenge-response signature verification, short access tokens and rotating hashed refresh tokens.
- Transactional upload/cursor/receipt implementation and the requested PostgreSQL integration tests.
- Request IDs, durable distributed rate limiting, LISTEN/NOTIFY and real OpenAPI bootstrap/auth endpoints.
- Actual Rust/Docker/CI execution and dependency lockfile refresh after adding backend dependencies.
