# VaultGuard — Security & Release Posture

This document summarizes the engineering and security decisions made while
hardening VaultGuard for its first public release, and lists what still gates the
launch. Read it alongside:

- `docs/security-model.md` — the full security model
- `SECURITY.md` — how to report vulnerabilities
- `PRIVACY.md` — data handling
- `docs/release-checklist.md` and `docs/release-smoke-checklist.md` — release gates

## Project setup and CI

- **Single source of truth.** The Xcode project is generated from `project.yml`
  with XcodeGen; the generated `project.pbxproj` and schemes are git-ignored, so
  there is no committed project file to drift against. `Package.resolved` stays
  tracked so the dependency pin can be verified.
- **CI enforces hygiene** on every push / PR: clean `xcodegen generate` + build +
  tests, localization key parity (en == ru), no force-unwrapped `URL(string:)!`,
  no reintroduced legacy keychain/cache symbols, no misleading master-password
  copy, the Argon2Swift revision pin, and a guard against unexpected branch-based
  dependency pins, plus `.DS_Store` / placeholder / positioning checks. A
  tag / `workflow_dispatch` job adds release-readiness checks (README assets,
  version consistency, an unsigned archive smoke).
- **Dependabot** tracks the `github-actions` ecosystem. The SwiftPM updater is
  intentionally disabled: the project resolves Swift packages through the Xcode
  project (`Package.resolved`), not a `Package.swift` manifest.

## Security posture (summary)

The full model is in `docs/security-model.md`; in brief:

- The master password is never written to disk; only derived / wrapped material is
  held in memory for the session.
- Two Keychain access groups. Session secrets (tokens, wrapped key, KDF parameters,
  offline-cache key, account index, KeePass bookmarks, biometric secret) live in an
  app-private group the AutoFill extension is not entitled to; only minimal AutoFill
  state lives in a shared group.
- AutoFill works from a separate, minimal cache sealed under a key derived from a
  short-lived shared secret with an enforced, configurable TTL (default 4 hours).
  Reads are fail-closed; lock / logout / account removal / local-vault close /
  TTL expiry all revoke access. The extension never receives the real vault key or
  any token.
- Biometric unlock stores only a wrapped key behind a biometric-bound Keychain item.
- Self-signed servers require explicit SHA-256 fingerprint confirmation.

### Passkeys (preview)

FIDO2 registration and assertion are wired into the AutoFill flow. Private keys are
stored per account in the shared Keychain group behind a user-presence access
control and are deleted on logout / account removal / local-vault removal; the
extension obtains a pre-authenticated context before each operation and never falls
back to an unauthenticated read. One path can only be confirmed on a device —
whether the extension can read the user-presence-gated item across the
app/extension boundary after the user check. Until that is confirmed, passkeys are
a **preview** feature. The check and its fallback (Secure Enclave, or prompt-level
user-presence as a documented limitation) are tracked in
`docs/release-smoke-checklist.md`.

## UI / UX decisions

- **Design tokens.** A small design system (`VGDesign`: fonts, colors, spacing,
  radii, and card / field surfaces) backs the primary SwiftUI views. Token values
  match the previous literals, so the migration is a visual no-op.
- **Deliberately not tokenized.** A few non-standard corner radii and decorative
  colors (favourite-star, avatar gradients) were left as-is — changing them would
  move pixels and is a separate design decision, not a semantic-color change.
- **Settings** are organized into native tabs (Account / Security / Interface /
  Import-Export / About).
- **Accessibility.** Icon-only controls have tooltips and accessibility labels;
  this should still be verified with Accessibility Inspector during manual QA.
- **Empty states** distinguish no-search-results / empty trash / empty favourites /
  empty vault / default.

## Open items that gate the public release

- Screenshots and demo GIF in `docs/assets/` (see `docs/app-store-screenshots.md`).
- App icon refresh (design decision).
- Passkey assertion confirmed on-device (`docs/release-smoke-checklist.md`).
- Manual macOS visual QA in light / dark / high-contrast.
- Clean-clone build verified from a fresh checkout.

## Verifying from a clean checkout

```bash
xcodegen generate
xcodebuild build -scheme VaultGuard -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO
xcodebuild test  -scheme VaultGuard -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO
# the generated project is regenerated, not tracked:
git check-ignore VaultGuard.xcodeproj/project.pbxproj
```
