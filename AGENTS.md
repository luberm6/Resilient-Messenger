# Resilient Messenger engineering rules

Read this file and `docs/PROJECT_CONSTITUTION.md` before every stage. Never invent cryptographic algorithms. Do not use libsignal in production without a separate legal decision. Servers must never store or log message plaintext. Do not claim a test passed unless it ran. Do not leave mocks, TODOs, or placeholders on a production path. Never commit secrets.

New dependencies require a verified license; critical dependencies require an exact version and lockfile. Every database migration needs a test, every wire format needs test vectors, every send is idempotent, and local persistence happens before transmission. Work is complete only after tests, commit, and report.
