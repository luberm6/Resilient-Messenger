# Privacy model

Server records only routing and operational metadata necessary for delivery. It must not receive display names, usernames, phone/email, contact lists, titles, previews, or plaintext in a transport envelope. Phone discovery is opt-in and separate from the core path.

Anonymous identity has no phone, email, Apple ID or Google dependency. Root/device private keys and recovery phrases remain client-only. A recovery blob is encrypted with a client-derived key before upload, so the server cannot decrypt it.

The backend necessarily stores an optional exact canonical username for discovery, but it offers no directory or prefix search. Group titles, descriptions, display names and message text are MLS application data. Server logs contain request ID, frame kind, byte count and bounded operational outcome only; they never contain complete ciphertext, recovery material or a stable ciphertext hash prefix.
