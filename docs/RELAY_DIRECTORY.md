# Signed relay directory

An offline/config signing key signs a canonical directory containing version, issued time, expiry, endpoint public hostname, supported transports and priority. The verification public key and a small bootstrap relay list ship in mobile clients; the private signing key never does.

Clients accept only a signature-valid directory with a newer version and valid time window. They retain the last valid directory when a newer candidate is expired, invalid or lower-versioned. Relay endpoints are ordinary TLS/443 WebSocket/HTTPS hosts. The relay is stateless, frame-size-limited and forwards authenticated opaque bytes over authenticated TLS to core-api; it never stores history or decrypts payloads.
