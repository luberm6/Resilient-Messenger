# Account recovery

The client generates a 24-word BIP-39 phrase locally. It derives a recovery key with HKDF-SHA-256 and encrypts any server-stored recovery blob using XChaCha20-Poly1305. The server may store only the ciphertext and a one-way recovery identifier; it never receives the phrase or root secret. Restoring on a clean device restores identity only, not plaintext history; the future UI must state this explicitly.
