# Privacy model

Server records only routing and operational metadata necessary for delivery. It must not receive display names, usernames, phone/email, contact lists, titles, previews, or plaintext in a transport envelope. Phone discovery is opt-in and separate from the core path.

Anonymous identity has no phone, email, Apple ID or Google dependency. Root/device private keys and recovery phrases remain client-only. A recovery blob is encrypted with a client-derived key before upload, so the server cannot decrypt it.
