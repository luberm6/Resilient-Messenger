# Progress

## p01 — project foundation

Structure, documentation, CI and minimal Rust services are established. No user-facing messenger function is implemented. Local environment does not provide the Rust/Docker/Apple/Android toolchains, so only checks recorded as executed may be claimed as passed.

Executed: shell syntax check and repository policy/path inspection. Not executed: cargo fmt/clippy/test/build, cargo-deny, Docker Compose validation, SwiftLint and Detekt (their toolchains are unavailable locally). GitHub Actions is the authoritative clean-room CI runner for these checks.

## p02 — compact binary protocol

Implemented v1 deterministic canonical-CBOR profile, fixed compact IDs, 17 transport tags, 11 encrypted application tags, strict size/format validation, malformed/truncated/oversized/map rejection tests and deterministic fuzz corpus. Golden vector and size-report source are present. Native Swift/Kotlin conformance uses the future generated UniFFI binding to this one Rust codec; platform toolchains have not yet been installed or run.

## Gap register — update after every prompt

### Still missing after p02

- Actual Rust compilation, rustfmt, clippy, unit/property/fuzz execution, size-report execution, cargo-deny and Docker validation.
- Confirmed GitHub Actions result; no workflow run has been observed yet.
- UniFFI binding generation and byte-for-byte conformance tests on real Swift and Kotlin clients.
- E2EE/MLS integration, key lifecycle, encrypted local persistence and server delivery implementation.
- Relay/API behavior, authentication, registration, username/QR/invite flows, push, offline queue, reconnect/failover, network-mode behavior, RU/EN interfaces and 1 Kbit/s acceptance tests.

This register is deliberately not a roadmap: an item leaves it only after it is implemented and a real relevant test or verification is recorded.
