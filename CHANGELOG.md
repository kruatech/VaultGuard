# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.1.0] - 2026-09-23

A second hardening pass: several data-loss and security fixes, key derivation moved off the
main thread, the Argon2 dependency vendored, and a set of everyday features. The summary of
what was found and why is in `docs/audit-response.md`.

### Added

- **Import from 1Password** (`.1pux`): logins, cards, identities and notes with their custom
  fields, one folder per 1Password vault; archived items are skipped.
- **Export a KeePass vault to Bitwarden JSON.**
- **Password health report** — reused, weak, empty and long-unchanged passwords, computed on
  the device. No breach lookup: that would mean sending something about each password to a
  third party.
- **Search across scripts and keyboard layouts**: a Cyrillic query finds a Latin entry and
  vice versa, and text typed on the wrong layout still matches.
- **Multiple selection** with bulk delete, move and favourite; bulk restore and permanent
  delete in a KeePass trash. On KeePass a bulk action is one save, not one per entry.
- **Recently used** section in the sidebar, ordered by last copy.
- **Adjustable text size** — `Command-+`, `Command-−`, `Command-0` and a slider in Settings.
  macOS has no system-wide Dynamic Type.
- Keyboard: `Command-L` locks, `Command-Shift-G` opens the generator, `Command-R` syncs, and
  `Delete` in the list deletes the selection.
- KeePass: entry expiry and tags are shown; KeePassXC TOTP settings are imported; KDBX 3.1
  attachments are readable.
- **Settings → KeePass snapshots**: list, save a copy of, and delete the pre-save snapshots.
- Send: remove the password from an existing Send.
- A progress bar for long imports and bulk actions.
- A security-audit log channel recording unlock, lock, failed sign-in, export and snapshot
  deletion — events only, never content.
- `docs/development.md` (building, tests, fixtures, and the rules for code that derives keys)
  and `docs/export-compliance.md` (the cryptography shipped, and the project's position under
  U.S. export controls). The security model gains sections on the clipboard and screen
  capture, pre-save snapshots, unprotected metadata, plain HTTP, and QuickType identities
  kept while locked.

### Changed

- **Window → Show VaultGuard** moves from `Command-0` to `Command-Shift-0`; `Command-0` now
  resets the text size, as it does across macOS.
- Key derivation no longer runs on the main thread. Signing in, the master-password reprompt,
  opening a KeePass file and saving one all used to freeze the window for the length of the
  KDF — twice per save on KeePass, once to encrypt and once to verify. Saves now run from a
  snapshot of the document, one at a time, so an earlier save can never finish last and
  overwrite a later edit.
- The Argon2 reference implementation is **vendored** in `Packages/Argon2` at a pinned
  upstream commit. The build fetches nothing from the network.
- A revealed password or hidden field is masked again after 30 seconds.
- Auto-lock is no longer postponed by the pointer merely moving over the window.
- Attachments are limited to 100 MB, checked before the file is read.
- Saving a KDBX 3.1 file, which converts it to KDBX 4.1 (KeePass 2.48 / KeePassXC 2.7 or
  later needed to open it), is now announced once per session instead of happening silently.
- The zip attachment preview is parsed once, off the main thread; the outline no longer
  collapses whenever the screen redraws.
- The sign-in screen warns when the server address uses plain `http://`.

### Removed

- The `Argon2Swift` package. It was used for one function and pulled the same library in
  twice — on a floating branch and as a git submodule that broke builds from a fresh clone.
- UI tests. They are replaced by acceptance tests of the KeePass write path, which check the
  same behaviour without a signed runner, an accessibility grant or a sandboxed fixture.

### Fixed

- **Registering a passkey could delete every other passkey** for the account: a failed
  keychain read was taken as "none stored" and the new set was written over the old. Passkeys
  created here are not synchronised anywhere, so the loss was permanent.
- **KeePass snapshot rotation deleted the newest snapshots** of any vault whose name sorted
  before another's: it kept ten across all vaults, ordered by file name. Rotation is now per
  vault and by time.
- The account index, the trusted-certificate list and the password templates could be
  overwritten with an empty set after a failed read.
- A server address with capitals in its path worked for the first sign-in and failed on the
  next Touch ID unlock. Account ids are unchanged.
- Saving a KDBX 3.1 file stored every attachment twice, doubling the file's size.
- Signing out left the account's folder order and recently used list behind.
- Switching accounts kept the previous account's folder order.
- With several logins for one site, AutoFill now offers the most recently modified.
- Two concurrent requests could each refresh the session token with the same refresh token,
  signing the user out where the server rotates them.
- `SECURITY.md` and `docs/security-model.md` said decrypted attachment previews were written
  to a temporary directory and cleaned up on lock. No such directory exists: previews are held
  in memory only.

### Security

- A copied password is cleared from the pasteboard when the vault locks, not only after the
  timeout.
- Items marked for master-password reprompt are no longer offered by AutoFill, which cannot
  reprompt; URIs whose match rule is *never* are excluded from AutoFill and QuickType.
- A corrupt protected value in a KeePass file is reported instead of silently read as empty
  and written back over the real one.
- Decompression of a KeePass payload is capped, so a crafted file cannot exhaust memory.
- The first fingerprint seen for a self-signed server persists across restarts, so a changed
  certificate is still flagged.
- `otpauth://hotp/` URIs are rejected rather than generating codes that never match, and
  non-web schemes such as `androidapp://` no longer match each other in AutoFill.
- A crafted zip attachment can no longer crash the preview with a deeply nested path, or
  disguise a file's extension with a right-to-left override.
- The password generator stops if the system random source fails, instead of hanging.
- KeePass snapshots, which stay encrypted with the password a file had when each was taken,
  can now be deleted — for use after a master-password change.
- CI verifies every vendored Argon2 file against recorded hashes and rejects any remote
  Swift package.

## [2.0.0] - 2026-07-14

Repositions VaultGuard from an unofficial Bitwarden client into a standalone,
open-source password manager with two vault types (local KeePass/KDBX and a
user-provided self-hosted Bitwarden/Vaultwarden-compatible server), and reworks
the local security model. Build 3; deployment target raised to macOS 14.

### Changed

- Repositioned the app and all public docs (README, PRIVACY, SECURITY, NOTICE,
  TRADEMARKS, security model, App Store listing / review notes) as a standalone,
  multi-vault manager; the developer operates no hosted service.
- Minimum macOS raised from 13 to 14.
- AutoFill now serves from a separate, minimal per-account/per-kind cache instead
  of the offline sync cache; publish path unified for server and KeePass vaults.
- Migrated the item editor and Settings to `Form`/`Section`; reworked the Send
  screen (separate create sheet, richer rows, private note, expiry in seconds);
  unified the list+detail header with search.

### Added

- Persistent main-window lifecycle: **Window → Show VaultGuard** (`Command-0`),
  Dock/Finder reopen, and the AutoFill unlock deep link restore the same window.
- Signed App Store release workflow and a tag-gated release-readiness CI job.

### Security

- Split Keychain items into two access groups: an app-private group (tokens,
  wrapped user key, KDF parameters, offline-cache key, account index, KeePass
  bookmarks, biometric secret) that the AutoFill extension cannot read, and a
  shared group holding only minimal AutoFill state. A one-time migration wipes
  the shared group on first launch after upgrade.
- The shared AutoFill secret is a fresh per-publish random value (never the vault
  key) with an enforced, configurable TTL (default 4 hours); the AutoFill cache
  key is HKDF-derived from it and scoped to the account and vault kind. Reads are
  fail-closed; lock / logout / account removal / local-vault close / TTL expiry
  all revoke access. AutoFill username fallback is scoped to the service host.
- Passkey private keys are stored behind a user-presence access control and read
  only via a pre-authenticated context; passkeys remain a preview feature pending
  on-device confirmation of the cross-process read.
- KeePass biometric unlock stores the SHA-256 password component of the composite
  key, never the raw master password; legacy secrets are migrated on first unlock.
- Rejected AES-128-CBC+HMAC (EncType 1) explicitly and required a MAC key for
  authenticated AES-256 decryption.

### Fixed

- Restored the closed main window from **Window → Show VaultGuard**, `Command-0`,
  the Dock, and the AutoFill unlock deep link without creating duplicate windows.
- Kept the main window lifecycle independent from Settings and locked the active
  vault on explicit application termination.
- Fixed two FIDO2 unit-test call sites after `createCredential` became throwing.
- Fixed a potential TOTP runtime trap for 10-digit codes (modulo widened to 64-bit).

## [1.0.0] - 2026-06-30

Initial public release (build 2). VaultGuard is a standalone, open-source
password manager for macOS supporting local KeePass/KDBX databases and
user-provided self-hosted Bitwarden/Vaultwarden-compatible servers. The developer
operates no hosted service.

### Added

- **Local KeePass (`.kdbx`) vaults** — a full local vault mode, no server required:
  open an existing database, create a new one, edit, save, and reopen; optional key
  file; standard and custom entry icons; nested folder/group tree; security-scoped
  bookmarks stored in the Keychain; biometric unlock; trash restore / permanent
  delete; read-only handling and a save block when the database contains attachments
  not yet preservable.
- **Self-hosted server vaults** — connect to a user-provided Bitwarden/Vaultwarden-
  compatible server: login (incl. 2FA), unlock, vault list, item details, search,
  copy username/password, and an encrypted offline cache for fast startup / offline
  read.
- **Password generator** with reusable templates, and built-in TOTP code generation.
- **AutoFill** credential provider extension for Safari and other apps, with a real,
  configurable key time-to-live.
- **Send** — create, list, edit, enable/disable, and delete text and file Sends;
  encrypted share links (HKDF-derived Send key + base64url access fragment).
- **Import**: Bitwarden JSON, and CSV (LastPass / Bitwarden / generic
  url/username/password layouts). **Export**: the active vault to a KeePass `.kdbx`.
- **Multi-account / multi-vault** support with per-source isolation, and **Remove
  account** from the account switcher.
- English and Russian localization.

### Security

- **Keychain access-group split.** Session secrets (tokens, wrapped user key, KDF
  parameters, offline-cache key, account index, KeePass bookmarks, biometric secret)
  live in an app-private group the AutoFill extension is not entitled to; only
  minimal AutoFill state lives in a shared group.
- **AutoFill key TTL is a real control.** The shared AutoFill secret is stored with
  an enforced expiry (default 4 hours; configurable) read from a setting shared via
  the App Group. Expired / malformed / legacy values are dropped (fail-closed).
- **Separate minimal AutoFill cache.** AutoFill reads a dedicated cache containing
  only the fields it needs, sealed under a key derived (HKDF-SHA256) from the
  short-lived shared secret and scoped to the account and vault kind. The extension
  never receives the real vault/user key, the offline-cache key, or any token.
- **Sensitive-data cleanup.** Lock, logout, account removal, and local-vault
  close/removal clear the relevant decrypted state, shared AutoFill secret, AutoFill
  cache, and passkeys for the affected source.
- **Passkeys (preview).** FIDO2 registration and assertion are wired into AutoFill;
  private keys are stored per account behind a user-presence access control and are
  deleted on logout / account removal / local-vault removal. One cross-process read
  path is pending on-device confirmation (see
  `docs/release-smoke-checklist.md`); until confirmed, passkeys are a preview feature.
- **Transport** (server mode). Self-signed certificates require explicit SHA-256
  fingerprint confirmation (trust-on-first-use); a later change is flagged.
- The master password is never written to disk in any form.

[Unreleased]: https://github.com/kruatech/VaultGuard/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/kruatech/VaultGuard/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/kruatech/VaultGuard/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/kruatech/VaultGuard/releases/tag/v1.0.0
