# Local storage contract

`messenger-core` is the sole writer to the per-account local SQLite database. Native UI supplies an app-private storage directory and a 32-byte master key only; iOS obtains it from Keychain and Android from Android Keystore wrapping. It is never written to preferences.

The database records a master-key version. Sensitive message, outbox, identity and relay-cache blobs use a maintained AEAD with a fresh nonce and authenticated row metadata. The UI never executes SQLite writes directly. A key rotation re-encrypts in recoverable batches and preserves the old version until successful completion.

`createMessage` is one transaction: allocate client message ID, persist encrypted payload or encrypting work item, and create outbox record before any network action. State transitions are transactional and monotonic; incoming events are idempotent by event ID. Wipe deletes database, sidecars and key references after closing all handles.
