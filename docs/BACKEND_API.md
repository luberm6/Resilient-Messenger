# Backend API foundation

`GET /healthz` reports process liveness; `GET /readyz` executes a database query and reports dependency readiness. `GET /metrics` exposes payload-free counters. `POST /v1/sync` and `POST /v1/long-poll` accept and emit `application/cbor` only, validate a versioned transport frame, enforce 64 KiB and never log its body. OpenAPI describes only these HTTP entry points; the binary schema remains owned by `messenger-protocol`.

Authentication uses an Ed25519 device challenge. An 80-byte `AuthResponse` completes a challenge; a 112-byte response performs device-bound refresh rotation. Access tokens last 15 minutes. Refresh tokens are stored only as domain-separated SHA-256 hashes; reuse revokes the token family.

`UploadEnvelope` control operation bytes are: `1` opaque group event, `2` KeyPackage publish, `3` group record creation, `4` signed membership operation, `5` Welcome upload and `6` encrypted recovery package storage. `SyncRequest` operations are: `0` group cursor, `1` global device cursor, `2` consume one target KeyPackage and `3` consume the authenticated device's Welcome mailbox. Username/recovery bootstrap uses backend identity methods and must not be embedded in an open relay transport envelope.

PostgreSQL is durable authority. `group_events` stores one ciphertext per `(author_device_id, client_message_id)` idempotency key; no ciphertext index, preview or plaintext column exists. Each write is transaction bounded and a failed membership/event correlation rolls back.

## Index rationale

- `devices_account_active_idx`: enumerate only active devices for account membership.
- `usernames_active_exact_idx` and `usernames_account_active_idx`: exact lookup and one active alias per account; no prefix index exists.
- `auth_challenges_live_idx`: find unconsumed short-TTL challenges.
- `access_sessions_device_idx` and `refresh_sessions_device_live_idx`: expire/revoke device sessions without scanning history.
- `key_packages_available_idx`: consume the oldest unused package with `SKIP LOCKED`.
- `group_members_device_active_idx`: authorize global/group sync for active device membership.
- `group_events_sync_idx`: ordered cursor pages per group; `group_events_retention_idx`: bounded TTL cleanup.
- `welcome_mailbox_pending_idx`: device-specific pending Welcome retrieval.

Production configuration is environment-only (`DATABASE_URL`, optional `BIND_ADDR` and `RUST_LOG`). No production secret is required by CI; Compose uses explicitly local-only values.
