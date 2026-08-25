# ADR 0001: OpenMLS for E2EE

Status: accepted for implementation; external audit required before production launch.

Use exact OpenMLS 0.9.0 with `openmls_rust_crypto` 0.6.0, `openmls_basic_credential` 0.6.0 and `openmls_traits` 0.6.0. It implements RFC 9420, supports the required X25519/ChaCha20-Poly1305/SHA-256/Ed25519 suite and avoids a proprietary ratchet. libsignal is not selected because production use requires a separate legal decision.

The prior 0.8.1 candidate was replaced after dependency audit found patched libcrux advisories in that graph. Version 0.9.0 resolves those vulnerabilities. The temporary `0-8-1-storage-format` feature enables controlled migration only; encrypted application snapshots, not upstream storage keys, are the durable boundary. RUSTSEC-2026-0173 remains an unmaintained build-time transitive advisory with no patched release and is explicitly tracked by `deny.toml`.

Consequences: every device is an MLS member; server fan-out is ciphertext-constant; membership commits can grow substantially for 100 members; iOS and Android builds are hard CI gates; security claims require an external audit.
