# Threat model

Protect message plaintext from relays, API operators, passive network observers and database compromise. TLS protects links and OpenMLS protects application content end to end. Passing tests is not proof of security: an independent external audit of identity, storage, protocol, MLS integration and mobile packaging is mandatory before mass launch. A compromised or unlocked endpoint can read that endpoint's plaintext and remains outside server-side defenses.

Identity threats include device cloning, altered certificates, invite tampering, recovery-phrase theft, username enumeration and stolen refresh tokens. Root signatures bind devices; recovery uses client-side HKDF-derived encryption; username lookups must be exact, normalized, rate-limited and anti-enumeration; refresh tokens require device-bound authentication before use.

Delivery threats include replay, duplicate upload, cursor rollback, unauthorized group reads, relay rollback and retention gaps. Idempotency keys, monotonic cursors, root-signed membership operations correlated with MLS commits, signed relay directories, short-lived credentials and table-backed delivery address these threats. PostgreSQL `NOTIFY` is never trusted for durability.
