# v1 golden vectors

The fixtures are lowercase hexadecimal encodings of complete canonical values:

- `v1-ping.hex` — backward-compatibility frame fixture;
- `v1-upload-envelope.hex` — steady transport fixture;
- `v1-text-message.hex` — encrypted application-envelope fixture with a two-byte test ciphertext.

Rust tests decode and re-encode every fixture byte-for-byte. Swift and Kotlin integration programs call the same Rust codec through generated UniFFI bindings and validate `v1-ping.hex`; those jobs are platform gates in CI.
