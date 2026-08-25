# Signed relay directory

An offline/config signing key signs a canonical directory containing version, issued time, expiry, endpoint public hostname, supported transports and priority. The verification public key and a small bootstrap relay list ship in mobile clients; the private signing key never does.

Clients accept only a signature-valid directory with a newer version and valid time window. They retain the last valid directory when a newer candidate is expired, invalid or lower-versioned. Relay endpoints are ordinary TLS/443 WebSocket/HTTPS hosts. The relay is stateless, frame-size-limited and forwards authenticated opaque bytes over authenticated TLS to core-api; it never stores history or decrypts payloads.

The offline operator CLI is `cargo run -p network-lab --bin relay-directory --`. `generate-key SECRET.bin PUBLIC.hex` creates a mode-0600 Ed25519 secret on Unix; only `PUBLIC.hex` ships in clients. `sign SECRET.bin DIRECTORY.bin VERSION ISSUED_AT EXPIRES_AT ENDPOINTS.txt` produces deterministic signed bytes. Endpoint lines contain `16-byte-id-hex priority wss-url https-url`. `verify PUBLIC.hex DIRECTORY.bin NOW MINIMUM_VERSION` checks signature, expiration and rollback floor. Secret files are ignored operational artifacts and must never be committed.
