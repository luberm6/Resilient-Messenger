# Threat model

Protect message plaintext from relays, API operators, passive network observers, and database compromise. TLS protects transport; future audited MLS integration protects content. Metadata minimization, short retention, rate limits, replay defenses, and device-bound credentials are required. A compromised endpoint can read its own plaintext.
