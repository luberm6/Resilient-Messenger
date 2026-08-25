# Progress and gap register

Last updated: 2026-08-25. This file is cumulative and must be updated after every prompt. “Implemented” means code exists; only the verification section records checks that actually ran.

## p01 — foundation

Implemented the Rust monorepo, iOS/Android shells, PostgreSQL/SQLite boundaries, Docker Compose, Render-compatible images, pinned toolchain/lockfile, development commands, CI, dependency/license policy, secret scanning and required governance/security documents. Scope explicitly excludes hardware, LoRa, mesh, taxi relays, rescue/satellite links, calls, video, voice, media/files, public channels, stories, bots, payments, web messenger and federation.

## p02 — compact binary protocol

Implemented deterministic strict canonical CBOR v1 with 17 transport frame types, 11 encrypted application types, compact identifiers, limits/TTL/version/error rules, canonical golden vectors, malformed/truncated/oversized/noncanonical/map rejection, proptest/random corpus and byte reports. JSON is absent from the wire path. Swift/Kotlin integration tests call the generated Rust codec.

## p03 — backend foundation

Implemented Axum/Tokio/SQLx/PostgreSQL configuration, JSON structured metadata logging, request IDs, distinct health/readiness, metrics, body/rate limits, graceful shutdown, controlled migrations and transaction boundaries. The schema includes all requested tables and documented indexes. Challenge-response, short access sessions, hashed rotating refresh families and reuse revocation are implemented. PostgreSQL integration covers replay, expiry, invalid signatures, rotation, rollback, idempotent event upload and cursors.

## p04 — anonymous identity and recovery

Implemented locally generated Ed25519 Account Root/Device keys, root-signed Device Certificates, stable account ID, BIP-39 24-word recovery, HKDF/XChaCha encrypted server blob, clean-device identity restore, exact normalized/reserved/cooldown username operations, signed invite/QR verification and a CLI harness. Backend never receives the phrase or root private key; history is not restored automatically.

## p05 — OpenMLS CryptoEngine

Implemented real OpenMLS 0.9.0 with exact locked dependencies, X25519/ChaCha20-Poly1305/SHA-256/Ed25519, credential binding, encrypted state snapshots and the full group lifecycle API. No custom ratchet, libsignal or key-material debug feature is present. UniFFI provides pointer-free, Mutex-protected Swift/Kotlin APIs; XCFramework and AAR pipelines plus real language-call tests are CI gates. Rust covers 1:1, 10/100 members, add/remove, replay/out-of-order/loss and restart persistence. Independent external audit remains mandatory.

## p06 — encrypted delivery service

Implemented one-row opaque group events, per-device group/global cursors, KeyPackage consume-once flow, Welcome mailbox, signed membership operations correlated with MLS commits, access control, idempotent uploads/receipts, TTL cleanup, paging and reconnect sync. `LISTEN/NOTIFY` wakes long-poll across instances but tables remain durable authority. WebSocket SyncRequest and HTTPS long-poll use the same cursor query path.

## p07 — transports and relay failover

Implemented real WebSocket and HTTPS-CBOR senders, signed deterministic relay directories with offline signer/verifier CLI, bootstrap/cached anti-rollback validation, health/backoff/jitter/sticky failover, persistent deduplicated outbox and byte/retry/switch counters. Relay is stateless, payload-opaque, frame-limited and forwards over configurable core HTTPS. Network tests cover Relay A failure, Relay B fallback, invalid/expired directories and both real local transports.

## p08 — offline-first local core

Implemented encrypted SQLite migrations and local source of truth for account/device/conversations/messages/outbox/inbox/cursors/receipts/requests/blocks/network/directory/retry/tombstone/key state. Send persists encrypted message plus outbox atomically before network. Tests cover kill-after-send/restart, wrong key, corruption, duplicate input/acceptance, migration, key rotation, 10,000 messages, long offline state and concurrent UI/network access. UniFFI exposes the requested state APIs; UI has no direct SQLite write path.

## Verification executed in this workspace

- Rust 1.98.0: `cargo fmt`, `cargo check`, workspace clippy, workspace tests and all-targets build.
- Real OpenMLS and UniFFI host tests, protocol property tests and real local WebSocket/HTTPS failover tests.
- Protocol and crypto size-report generators.
- `cargo deny check` including advisories, bans, licenses and sources, plus `cargo audit`.
- Shell syntax, required-path inspection and local secret scan.

GitHub Actions run [#9](https://github.com/luberm6/Resilient-Messenger/actions/runs/32834174797) completed successfully on 2026-08-25. Its nine green jobs verified:

- Rust format, clippy, 32 workspace tests, build and size reports;
- clean PostgreSQL integration and controlled migrations;
- cargo-deny and cargo-audit dependency policy;
- 30 seconds of libFuzzer execution;
- Swift package tests, SwiftLint, real Rust/OpenMLS calls through generated Swift UniFFI bindings and XCFramework creation;
- generated Kotlin binding execution, Android unit tests/lint/app build and multi-ABI AAR creation;
- Docker Compose validation, image build, migration job, readiness and PostgreSQL restart recovery;
- full-history Gitleaks plus the repository-local secret scan.

The exact final command results for the current commit are recorded in the completion report; this section must be corrected if a later edit invalidates a run.

## Open gaps after p08

These are not silently treated as complete:

- Real 1 Kbit/s, DNS/TLS fault injection, failover latency, battery/probe frequency and mobile memory/CPU measurements require the network lab plus physical/simulator platform environment. Unit tests prove semantics, not those environmental numbers.
- XCFramework and AAR build gates are green, but runtime behavior, secure-key storage and resource measurements still require real iOS and Android devices.
- OpenMLS and the surrounding identity/storage/protocol/mobile integration require an independent external security audit before mass launch.
- RUSTSEC-2026-0173 is an unmaintained build-time transitive dependency with no patched release; `deny.toml` contains the documented temporary exception.
- Push-notification provider integration and user-facing RU/EN screens are outside p01–p08 and remain for later prompts; no placeholder implementation was added.

No excluded MVP feature has been added, even as a partial scaffold.
