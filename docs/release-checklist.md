# VaultGuard Release Checklist

Run through this before tagging a public release. Items are grouped; nothing here
has to pass on every pull request — CI already enforces the per-PR gates.

## Build & tests

- [ ] `xcodegen generate` succeeds from a clean clone.
- [ ] Build and test pass on macOS (unsigned is fine):
      `xcodebuild test -scheme VaultGuard -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO`
- [ ] All unit tests green (crypto, KDBX, TOTP, localization).
- [ ] Verified from a fresh `git clone` — no reliance on local-only files.

## Hygiene (CI also enforces these)

- [ ] `en.lproj` and `ru.lproj` localization keys are in parity.
- [ ] No force-unwrapped `URL(string:)!`.
- [ ] No reintroduced legacy keychain/cache symbols.
- [ ] No misleading "master password saved" copy.
- [ ] `Argon2Swift` pinned to the audited revision; no unexpected branch pins.

## Secrets & signing

- [ ] `Config/Signing.local.xcconfig` is git-ignored and NOT tracked
      (`git ls-files | grep -i signing` shows no `*.local.*`).
- [ ] No real Team ID, certificates, provisioning profiles, or `xcuserdata` committed.
- [ ] `Config/Signing.example.xcconfig` is present and current.

## Manual QA

- [ ] Unlock, browse, search, generator, TOTP, attachments on a real vault.
- [ ] Send: create, list, and delete an encrypted Send.
- [ ] KeePass: open an existing `.kdbx`, create a new one, edit, save, reopen.
- [ ] Import (Bitwarden JSON / CSV) and export to KeePass.
- [ ] Light, dark, and high-contrast appearances.
- [ ] Close the main window, then restore it with **Window → Show VaultGuard** / `⌘0`.
- [ ] With Settings left open, close and restore the main window; no duplicate window is created.
- [ ] Close the main window and click the Dock icon; the same main window becomes key.
- [ ] English and Russian; Settings tabs are not truncated.
- [ ] AutoFill from Safari while unlocked; stops serving after the key TTL.
- [ ] Self-hosted server: login, unlock, search, and copy on a user-provided compatible server.
- [ ] Device security checks in [release-smoke-checklist.md](release-smoke-checklist.md) pass
      (keychain isolation, AutoFill revocation on lock/logout/removal/TTL, passkey assertion).

## Docs & metadata

- [ ] README status badge and "Current status" reflect the release (alpha / beta / x.y).
- [ ] "Known limitations" is accurate (passkeys preview status, audit status, notarization).
- [ ] Screenshots in `docs/assets/` are current and show both vault types (local KDBX and
      self-hosted server), using only fake data.
- [ ] Version/build are consistent across `project.yml` (`MARKETING_VERSION` /
      `CURRENT_PROJECT_VERSION`), the App Store listing, README, and the changelog.
- [ ] Release notes / changelog drafted.
- [ ] App icon finalised.

## Owner decisions before the first public tag

- [ ] Passkeys: confirm the assertion path on-device ([release-smoke-checklist.md](release-smoke-checklist.md)); then keep as preview or promote to a listed feature.
- [ ] Independent security review: done, scheduled, or explicitly deferred.
- [ ] Distribution: build-from-source only, or a signed/notarized artifact.
- [ ] Tag the release and publish notes.
