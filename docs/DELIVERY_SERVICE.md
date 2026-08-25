# Delivery Service contract

The service is an opaque MLS Delivery Service, not an MLS group member. One `group_events` row stores each encrypted Welcome, Commit or application event exactly once. `device_group_cursors` holds each recipient device's progress; event fan-out never duplicates ciphertext.

Only an authenticated, active `group_members` device may sync a group. Sync uses stable event sequence/cursor ordering, pages at the protocol batch limit, and advances a device cursor transactionally and monotonically. Upload is idempotent on `(author_device_id, client_message_id)`; acknowledgements are idempotent. Expired events return an explicit gap/expired result, never a fabricated cursor advance.

Membership is an opaque device/account/role projection. A client supplies a root-authorized administrative operation correlated with an MLS Commit. Both records commit in one transaction; a reconciliation job detects and blocks incomplete correlations after failure. Group title, description and ciphertext are not interpreted or indexed.

WebSocket and long-poll merely notify a device that new data may exist. Both resume by the same database cursor-driven sync flow; PostgreSQL is the source of truth. PostgreSQL `NOTIFY` is best-effort cross-instance wake-up only. Retention deletion occurs only after TTL and policy conditions; it never decrypts or examines content.
