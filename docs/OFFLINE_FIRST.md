# Offline-first contract

The local core is the source of truth. Send means durable local acceptance first, then optional upload. Restart, transport loss and long offline periods retain queued work. Retry state holds attempt count, next eligible time, TTL and permanent failure/cancel state; backoff uses jitter.

Inbox processing accepts out-of-order events, suppresses duplicate event IDs and maintains tombstones for deleted/expired records. Search happens only over locally decrypted data. Core publishes changes through FFI observers; UI reads state only through core APIs. Server acknowledgements move state forward idempotently and never discard an unsynced local message.
