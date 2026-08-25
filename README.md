# Resilient Messenger

Resilient Messenger is an offline-first, private text messenger designed for weak, unstable and artificially throttled Internet. The repository contains the shared Rust core/protocol/OpenMLS engine, Axum/PostgreSQL Delivery Service, stateless relay, UniFFI mobile bindings and minimal SwiftUI/Compose application shells.

The current implementation covers engineering stages p01–p08. It is not externally audited and is not ready for mass production deployment. See `docs/PROGRESS.md` for executed checks and the persistent gap register.

## Development

Install Rust 1.98.0 and `just`, then run:

```sh
just bootstrap
just ci
just up
```

Protocol and MLS size reports are generated with `just protocol-size` and `just crypto-size`. No production secret is required for local tests or CI.

## Scope

The MVP is text-only on iOS and Android. It does not include mesh, LoRa, hardware/satellite links, calls, voice/video, media/files, public channels, bots, payments, web messenger or federation. See `docs/SCOPE.md` and `AGENTS.md` before contributing.
