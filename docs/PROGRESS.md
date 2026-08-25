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

## p04 — anonymous identity and recovery

Added client-side Ed25519 root/device key generation, root-signed device certificate, stable one-way Account ID, BIP-39 24-word recovery phrase, HKDF-derived XChaCha20-Poly1305 recovery blob encryption, normalized exact username primitive, and signed invite verification.

### Still missing after p04

- Backend registration, certificate persistence/verification, recovery-blob endpoint and client restore harness.
- Username claiming/changing/release cooldown, reserved-name policy, race-safe transactions, rate limiting and anti-enumeration responses.
- Access/refresh session implementation, device-bound challenge response and refresh-token reuse detection.
- QR serialization, CLI harness, all requested security/integration tests, Rust compilation and CI execution.

## p05 — OpenMLS CryptoEngine gate

No CryptoEngine has been integrated. This is intentional: the current environment lacks cargo/rustc, Xcode/Swift build tools and Android Gradle/NDK, so it cannot verify the exact stable OpenMLS release/changelog/advisories, resolve and commit Cargo.lock, run MLS interoperability tests, or prove real mobile bindings. No mock or substitute ratchet was added.

### Still missing after p05

- Verified stable OpenMLS selection and ADR, exact locked transitive dependency graph, and cargo-deny review.
- Real OpenMLS CryptoEngine with encrypted local storage, credential validation against root-signed device certificates, and lifecycle APIs.
- UniFFI-generated Swift/Kotlin bindings, XCFramework/AAR pipelines, real-device gates and all MLS interoperability/load/size measurements.
- Independent external security audit before any mass launch.
