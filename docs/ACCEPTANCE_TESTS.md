# Acceptance tests

CI must format, clippy-lint, test and build the locked Rust workspace without production secrets. It runs protocol vectors/property/fuzz tests, real OpenMLS group tests and PostgreSQL integration tests on a clean database. Dependency, license and secret gates use cargo-deny, cargo-audit and Gitleaks.

Platform gates generate UniFFI Swift/Kotlin bindings, call real Rust encryption/decryption, build the XCFramework and Android AAR, run SwiftLint and Android test/lint/assemble. Docker Compose must parse, build, reach distinct health/readiness endpoints and recover after PostgreSQL restart.

Network acceptance includes WebSocket/HTTPS round trips, automatic relay failover with a retained deduplicated outbox, invalid/expired/rollback directory rejection and long-poll cursor recovery. Real-device battery, memory and 1 Kbit/s throttled acceptance remains an explicit release gate, not a substituted unit test.
