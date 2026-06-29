# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Fixed

- Restored the closed main window from **Window → Show VaultGuard**, `Command-0`,
  the Dock, and the AutoFill unlock deep link without creating duplicate windows.
- Kept the main window lifecycle independent from Settings and locked the active
  vault on explicit application termination.
- Fixed two FIDO2 unit-test call sites after `createCredential` became throwing.

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

[Unreleased]: https://github.com/kruatech/VaultGuard/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/kruatech/VaultGuard/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/kruatech/VaultGuard/releases/tag/v1.0.0
