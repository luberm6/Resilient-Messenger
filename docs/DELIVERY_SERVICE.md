# Delivery Service contract

The service is an opaque MLS Delivery Service, not an MLS group member. One `group_events` row stores each encrypted Welcome, Commit or application event exactly once. `device_group_cursors` holds each recipient device's progress; event fan-out never duplicates ciphertext.

Only an authenticated, active `group_members` device may sync a group. Sync uses stable event sequence/cursor ordering, pages at the protocol batch limit, and advances a device cursor transactionally and monotonically. Upload is idempotent on `(author_device_id, client_message_id)`; acknowledgements are idempotent. Expired events return an explicit gap/expired result, never a fabricated cursor advance.

Membership is an opaque device/account/role projection. A client supplies a root-authorized administrative operation correlated with an MLS Commit. Both records commit in one transaction; a reconciliation job detects and blocks incomplete correlations after failure. Group title, description and ciphertext are not interpreted or indexed.

WebSocket SyncRequest is forwarded to the same `/v1/long-poll` handler as HTTPS fallback. The handler subscribes before its first cursor query, waits up to 20 seconds only when the page is empty, then queries again. A committed upload emits `NOTIFY device_events`; it is best-effort cross-instance wake-up only. PostgreSQL rows remain the source of truth across disconnect or restart. Retention deletion occurs only after TTL and never decrypts or examines content.
