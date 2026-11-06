# Resilient Messenger engineering rules

Read this file and `docs/PROJECT_CONSTITUTION.md` before every stage. Never invent cryptographic algorithms. Do not use libsignal in production without a separate legal decision. Servers must never store or log message plaintext. Do not claim a test passed unless it ran. Do not leave mocks, TODOs, or placeholders on a production path. Never commit secrets.

New dependencies require a verified license; critical dependencies require an exact version and lockfile. Every database migration needs a test, every wire format needs test vectors, every send is idempotent, and local persistence happens before transmission. Work is complete only after tests, commit, and report.

## Permanent mobile SDK maintenance policy (all current and future projects)

This is a cross-project CI/CD standard, not a one-off Flutter upgrade.

- At least **monthly**, audit the latest stable and security/bugfix releases of each mobile app's **actual** framework and SDK: Flutter/Dart (only for Flutter projects); React Native/Expo/Node (for RN projects); Xcode/Swift/iOS deployment target and relevant packages (for native Swift); Kotlin/Android Gradle SDK (for native Android). Check app dependencies and native build tools as applicable.
- New mobile projects MUST adopt the same monthly dependency/SDK audit from inception. Record pinned toolchain versions and upgrade procedures in the repo.
- Prefer a single shared scheduled audit across repos instead of duplicate schedulers or expensive cloud builds. Keep a brief record with current pin, latest stable, relevant security/crash fixes, release notes, risk, recommendation, and date checked.
- When an update is worthwhile: create an isolated **PR**, update exact SDK pins and lockfiles, verify compatibility and run existing lint/typecheck/tests plus the platform-appropriate build where available. Do not silently upgrade production or auto-merge.
- **Flutter-specific:** inspect official Flutter stable release notes monthly; prioritize security and iOS graphics/startup/engine/WebView fixes. Never track beta/master as the default production SDK.
- For urgent vulnerabilities or app-crashing issues, evaluate promptly rather than waiting for the monthly review. Routine patch updates can be assessed within ~1–2 weeks; major versions are reviewed deliberately, generally every 2–3 months depending on risks.
- Preserve existing GitHub PR -> required CI -> controlled release -> smoke -> rollback pipeline. Backend/sites stay on Contabo. Do not replace working CI or introduce duplicate/paid CI just to implement the audit.
- **Never automatically trigger Xcode Cloud/TestFlight/App Store or a production deployment solely for a monthly SDK audit.** Run inexpensive checks first, and only approve a native cloud archive when needed for a validated mobile update; preserve last working pinned SDK for rollback.
- If the repository is web/server-only and has no Flutter/mobile app, do not install Flutter. Apply the same monthly *relevant runtime/SDK* version review when appropriate.
