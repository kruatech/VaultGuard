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
  there is no committed project file to drift against. There are no remote Swift
  packages: the Argon2 implementation is vendored in `Packages/Argon2` (see
  *Dependencies* below), so there is no `Package.resolved` to track.
- **CI enforces hygiene** on every push / PR: clean `xcodegen generate` + build +
  tests, localization key parity (en == ru), no force-unwrapped `URL(string:)!`,
  no reintroduced legacy keychain/cache symbols, no misleading master-password
  copy, that every vendored Argon2 file matches `Packages/Argon2/SHA256SUMS` and no
  unlisted file has been added, plus `.DS_Store` / placeholder / positioning checks. A
  tag / `workflow_dispatch` job adds release-readiness checks (README assets,
  version consistency, an unsigned archive smoke).
- **Dependabot** tracks the `github-actions` ecosystem. Actions are pinned to full
  commit SHAs with the version in a comment, which Dependabot updates in place. There is
  nothing for the SwiftPM updater to track.

## Dependencies

The project previously depended on the `Argon2Swift` package for a single function. That
package declared `phc-winner-argon2` on a floating `master` branch **and** carried it as a
git submodule; the submodule was never compiled, but SwiftPM cloned it anyway, and that
clone failed from a fresh checkout, so the project did not build without a warm cache.

The reference implementation is now vendored in `Packages/Argon2` at a pinned upstream
commit, with the source set upstream's own manifest compiles. Before the switch the same
files were compiled and checked against upstream's test suite and against vectors produced
independently with `argon2-cffi`; after it, the existing key-derivation tests and real KDBX
fixtures pass unchanged, which means vault keys are unchanged.
`Packages/Argon2/PROVENANCE.md` records the commit, the file list and why each exclusion.

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

## Changes since the first hardening pass

A second review found and fixed the following. Each fix has tests where the code can be
reached by the test target.

**Data loss**

- Registering a passkey could silently delete every other passkey for the account: a
  failed keychain read was treated as "none stored", and the new set was written over the
  old. Registration now refuses when the existing set cannot be read.
- The account index, the trusted-certificate map and the password templates had the same
  read-then-overwrite shape. Each now refuses to write back a set it failed to read.
- KeePass snapshot rotation kept the last ten snapshots across all vaults, sorted by file
  name — so saving one vault deleted the *newest* snapshots of any vault whose name
  sorted earlier. Rotation is now per vault and by time.

**Security**

- A copied password stayed on the pasteboard after the vault locked. Lock now clears it.
- Items marked for master-password reprompt were offered by AutoFill, which cannot
  reprompt. They are now excluded, as are URIs whose match rule is *never*.
- Concurrent requests could each start a token refresh with the same refresh token;
  where the server rotates refresh tokens, the second one failed and signed the user out.
  Refreshes are now single-flight.
- The zip attachment preview could be crashed by an archive with one very deeply nested
  path, and could be made to misreport a file's extension with a right-to-left override.
- The secure random index generator spun forever if the system random source failed. It
  now stops.
- Old KeePass snapshots could not be deleted, although they remain openable with the
  password the file had when each was taken. They can now be deleted from Settings.
- The sign-in screen now warns when a server address uses plain HTTP.

**Responsiveness**

- Every KeePass save ran the file's key-derivation function twice on the main thread —
  once to encrypt and once to verify — freezing the window for each edit. Saves now run
  off the main thread from a snapshot of the document, one at a time, so a later edit is
  never overwritten by an earlier save finishing last.
- Signing in to a server, and the master-password reprompt, also ran the KDF on the main
  thread. Both now run it off the main thread.

**Correctness**

- A server address with capitals in its path worked for the first sign-in and failed on
  the next biometric unlock, because the whole address was stored lowercased. The path now
  keeps its case; account ids are unchanged.

**Documentation**

- `docs/security-model.md` and `SECURITY.md` said decrypted attachment previews were
  written to a temporary directory and cleaned up on lock. No such directory exists:
  previews are held in memory only. Both now say so.

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
