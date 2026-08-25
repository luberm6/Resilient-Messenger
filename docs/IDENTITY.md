# Anonymous identity

Account Root Key is generated locally and derives the stable Account ID as SHA-256 over a domain separator and root public key. Each device has a distinct Ed25519 key and a root-signed certificate. Sessions are transport credentials only. Display names are encrypted client attributes; username is an optional exact alias and never a public directory.

Invites/QR contain protocol version, Account ID, fingerprint, optional expiry and root signature. They never contain recovery phrase, private key, phone or email.
