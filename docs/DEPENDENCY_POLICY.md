# Dependency policy

Use stable releases only and exact versions for critical dependencies. `Cargo.lock` is committed and CI uses `--locked`. Rust 1.98.0, UniFFI 0.32.0 and OpenMLS 0.9.0 are pinned. OpenMLS uses its `0-8-1-storage-format` compatibility feature only for controlled migration; its internal key/value representation is never a public application contract.

Every addition requires a license review and `cargo deny check`. `cargo audit` is an independent CI gate. `content-debug`, `crypto-debug` and other key-material debug features are prohibited. `libsignal` is excluded unless a separate legal decision approves it.

The lockfile currently has one explicit informational exception: RUSTSEC-2026-0173 marks build-time transitive `proc-macro-error2` as unmaintained and provides no patched version. It arrives through hax/libcrux, is not a runtime primitive, and must be reevaluated on every OpenMLS update. Vulnerabilities with patched releases are not waived.
