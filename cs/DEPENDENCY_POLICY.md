# Dependency policy

Use stable releases only. `Cargo.lock` is committed. OpenMLS is an isolated candidate pending a dedicated integration review; do not expose its internal storage format as a durable application contract. Review release notes and advisories before adoption. Licenses are enforced with cargo-deny.
