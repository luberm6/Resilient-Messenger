# Threat model

Protect message plaintext from relays, API operators, passive network observers, and database compromise. TLS protects transport; future audited MLS integration protects content. Metadata minimization, short retention, rate limits, replay defenses, and device-bound credentials are required. A compromised endpoint can read its own plaintext.

Identity threats include device cloning, altered certificates, invite tampering, recovery-phrase theft, username enumeration and stolen refresh tokens. Root signatures bind devices; recovery uses client-side HKDF-derived encryption; username lookups must be exact, normalized, rate-limited and anti-enumeration; refresh tokens require device-bound authentication before use.
