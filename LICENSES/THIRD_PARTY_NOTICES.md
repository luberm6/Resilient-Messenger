# Third-party notices

All dependencies remain subject to their upstream license texts. `cargo deny check`
validates the exact lock file in CI; this notice is not a substitute for those texts.

The allowed dependency license set is Apache-2.0, MIT, MIT-0, BSD-3-Clause,
Unicode-3.0, ISC, CC0-1.0, Zlib, MPL-2.0 and CDLA-Permissive-2.0.
CDLA-Permissive-2.0 applies to Mozilla/WebPKI root-certificate data. MPL-2.0 dependencies include
UniFFI and HPKE components; modifications to MPL-covered source files must be
made available under MPL-2.0 when distributed. OpenMLS itself is MIT licensed.

`libsignal` is not a dependency. No dependency may be added until its license
and distribution obligations have been reviewed and recorded here.

Known advisory exception: `RUSTSEC-2026-0173` marks the build-time
`proc-macro-error2` dependency unmaintained. It is pulled through hax/libcrux,
has no safe upgrade, and is not linked as a runtime cryptographic primitive.
Every OpenMLS update must attempt to remove this exception; vulnerabilities
with a fixed version are never waived by this policy.
