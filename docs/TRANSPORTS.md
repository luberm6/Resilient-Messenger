# Transport Manager contract

The client tries WebSocket over TLS/443 first and HTTPS CBOR batch/sync over TLS/443 as identical-semantic fallback. There is no mesh, LoRa, Tor, domain fronting or censorship-evasion transport in MVP.

The manager persists its outbox before sending, uses the protocol client-message ID for deduplication, and never deletes pending work because an endpoint fails. It selects a signed, unexpired relay directory endpoint by priority and observed health. Failures use exponential backoff with full jitter and a cooldown; health probes are bounded and piggybacked on normal traffic where possible. Network changes reset only the current connection attempt, not the outbox or valid directory.

WebSocket carries active SyncRequest/notification waits; the relay forwards those waits to core-api long-poll. HTTPS batch uses the same frame and cursor semantics. Payloads are never logged. Counters record only bytes, endpoint outcome, retry count and relay switches. The network lab proves retained outbox, Relay A failure, Relay B HTTPS fallback and sticky recovery; physical-device battery and 1 Kbit/s measurements remain release-gate work recorded in `PROGRESS.md`.
