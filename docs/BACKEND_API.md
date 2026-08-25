# Backend API foundation

`GET /healthz` reports process liveness; `GET /readyz` executes a database query and reports dependency readiness. `GET /metrics` is operational text. `POST /v1/sync` accepts and emits `application/cbor` only, validates the versioned transport frame and never logs body contents. HTTP bootstrap/admin endpoints may later be described in OpenAPI; binary sync remains specified by `messenger-protocol`.

PostgreSQL is durable authority. `group_events` stores one ciphertext per `(author_device_id, client_message_id)` idempotency key; no ciphertext index, preview or plaintext column exists. Refresh tokens are represented only by `token_hash`. Indexes support live devices, one-time challenges and ordered per-group sync without inspecting ciphertext.
