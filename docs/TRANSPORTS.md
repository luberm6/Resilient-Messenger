# Transport Manager contract

The client tries WebSocket over TLS/443 first and HTTPS CBOR batch/sync over TLS/443 as identical-semantic fallback. There is no mesh, LoRa, Tor, domain fronting or censorship-evasion transport in MVP.

The manager persists its outbox before sending, uses the protocol client-message ID for deduplication, and never deletes pending work because an endpoint fails. It selects a signed, unexpired relay directory endpoint by priority and observed health. Failures use exponential backoff with full jitter and a cooldown; health probes are bounded and piggybacked on normal traffic where possible. Network changes reset only the current connection attempt, not the outbox or valid directory.

WebSocket carries availability notifications and active sync; HTTPS long-poll/batch calls the same cursor-driven sync semantics. Payloads are never logged. Counters record only bytes, endpoint outcome, retry count and duration.
