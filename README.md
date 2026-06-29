# VaultGuard

[![CI](https://github.com/kruatech/VaultGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/kruatech/VaultGuard/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![macOS 14+](https://img.shields.io/badge/macOS-14%2B-lightgrey.svg)](README.md)
[![Status: beta](https://img.shields.io/badge/status-beta-orange.svg)](#current-status)

**VaultGuard is an open-source password manager for macOS** with support for local
[KeePass](https://keepass.info/) (`.kdbx`) databases and user-provided self-hosted
[Bitwarden](https://bitwarden.com/) / [Vaultwarden](https://github.com/dani-garcia/vaultwarden)-compatible
servers.

<p align="center">
  <img src="docs/assets/hero.png" alt="VaultGuard main window" width="860">
</p>

VaultGuard is a standalone, multi-vault, privacy-first app. It can work fully
locally with a KeePass/KDBX file (no server at all), or connect to a
Bitwarden/Vaultwarden-compatible server that **you** run or have access to. The
developer operates no hosted service and receives no vault content; secrets live
only in the local database you select, on the server you configure, and locally in
the macOS Keychain and encrypted on-disk caches.

> **Trademarks / affiliation.** VaultGuard is an independent project and is **not
> affiliated with, endorsed by, or sponsored by Bitwarden Inc.** "Bitwarden" is a
> trademark of Bitwarden Inc.; "Vaultwarden" belongs to its respective authors.
> These names are used only to describe server compatibility — VaultGuard is not an
> official Bitwarden client.
> License: [Apache License 2.0](LICENSE).

## Current status

VaultGuard is in active development (**beta**). The core flows — choosing a vault
type, opening a local KDBX file or signing in to a self-hosted server, unlock/lock,
browse, search, item details, copy, password generator, TOTP, and AutoFill — are
implemented, and the security-sensitive paths are covered by unit tests. Expect
rough edges; it is not yet recommended as your only password manager. See
**Feature status** and **Known limitations**.

## Supported vault types

- **Local KeePass/KDBX vault** — open a `.kdbx` file (optional key file), decrypted
  locally with the KeePass KDF. No server required.
- **Self-hosted server vault** — connect to a Bitwarden/Vaultwarden-compatible
  server you provide. Bring your own endpoint; the developer does not host one.

## Features

- View and manage logins, cards, identities, and secure notes; organize with
  folders, favorites, and trash.
- Built-in password generator with reusable templates, and TOTP code generation.
- AutoFill credential provider extension for Safari and other apps.
- Search, item details, and one-tap copy of username/password.
- Biometric unlock (Touch ID) without ever storing the master password.
- Encrypted offline cache for fast startup and read access (server mode).
- **Send** — share encrypted text or files via a link (server mode).
- Import from Bitwarden JSON / CSV, and export to KeePass.
- TLS certificate fingerprint pinning with explicit confirmation for self-signed
  servers (server mode).
- Multi-account / multi-vault support with per-source isolation.
- English and Russian localization.

## Feature status

**Stable**

- Local KeePass/KDBX open, unlock, browse, search, item details, copy.
- Self-hosted server login, unlock, vault list, item details, search, copy.
- Password generator and TOTP.
- AutoFill with a configurable, enforced shared-key TTL.
- Biometric unlock; lock / logout / account removal / local-vault close cleanup.

**In progress / limitations**

- **Passkeys / FIDO2** are implemented and wired into AutoFill (registration +
  assertion), with private keys stored behind a user-presence access control. One
  cross-process read path is pending on-device confirmation
  (see [docs/release-smoke-checklist.md](docs/release-smoke-checklist.md)); until
  confirmed, treat passkeys as preview.
- KeePass (`.kdbx`) is read-write, but some advanced KDBX features may not be
  preserved on save.
- No independent security audit has been performed.
- Builds are not yet signed or notarized for distribution — build from source.
- Manual light/dark/high-contrast visual QA is ongoing.

## Screenshots

<table>
  <tr>
    <td><img src="docs/assets/vault-type.png" alt="Vault type selection" width="420"></td>
    <td><img src="docs/assets/keepass-unlock.png" alt="Local KeePass unlock" width="420"></td>
  </tr>
  <tr>
    <td><img src="docs/assets/item-detail.png" alt="Item detail" width="420"></td>
    <td><img src="docs/assets/password-generator.png" alt="Password generator" width="420"></td>
  </tr>
  <tr>
    <td><img src="docs/assets/server-login.png" alt="Self-hosted server login" width="420"></td>
    <td><img src="docs/assets/settings.png" alt="Settings" width="420"></td>
  </tr>
</table>

<p align="center">
  <img src="docs/assets/demo.gif" alt="VaultGuard demo" width="720">
</p>

## Security model

- **Master password is never written to disk.** Server login derives the vault key
  (Argon2id or PBKDF2, matching the server's KDF); a local KDBX file is opened with
  the KeePass KDF (Argon2 / AES-KDF). Only derived/wrapped material is kept in
  memory for the session.
- **Two Keychain access groups.** Session secrets (tokens, wrapped user key, KDF
  params, offline-cache key, account index, KeePass bookmarks) live in an
  app-private group the AutoFill extension is **not** entitled to; only minimal
  AutoFill state lives in a shared group.
- **Biometric unlock** stores the wrapped vault key and a password hash in the
  data-protection Keychain behind a `SecAccessControl` bound to the current
  biometric set; the raw master password is never stored.
- **AutoFill** serves credentials from a separate, minimal cache sealed under a key
  derived from a short-lived shared secret (configurable TTL). The extension never
  receives the real vault key or any token. Lock / logout / account removal / local
  vault close / TTL expiry all revoke access.
- **Passkeys** private keys are stored behind a user-presence access control and are
  deleted on logout / account removal / local-vault removal.
- **Transport** (server mode). System-trusted certificates are validated normally;
  self-signed certificates require explicit SHA-256 fingerprint confirmation
  (trust-on-first-use), and a later change is flagged.

See [docs/security-model.md](docs/security-model.md) for the full model.

## Requirements

- macOS 14 or later
- Xcode 15 or later
- [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`)
- A paid Apple Developer account is needed to build the AutoFill extension (App
  Group + AutoFill Credential Provider capability).

## Build and run

```bash
# 1. Optional: only needed for locally signed builds.
cp Config/Signing.example.xcconfig Config/Signing.local.xcconfig
# then edit Config/Signing.local.xcconfig and set your DEVELOPMENT_TEAM (Apple Team ID)

# 2. Generate the Xcode project. This works even without Signing.local.xcconfig.
xcodegen generate

# 3. Open and build:
open VaultGuard.xcodeproj
```

Swift package dependencies are pinned by the Xcode project and `Package.resolved`.
`Argon2Swift` is pinned by audited revision because its published package manifest
uses a branch-based transitive dependency; Xcode resolves it automatically.

### Tests

```bash
xcodegen generate
xcodebuild test \
  -scheme VaultGuard \
  -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY=
```

Before a public release, run through [docs/release-checklist.md](docs/release-checklist.md)
and the device checks in [docs/release-smoke-checklist.md](docs/release-smoke-checklist.md).

### AutoFill setup

The AutoFill extension requires an App Group (`group.com.kruatech.vaultguard`) and
the AutoFill Credential Provider capability on the extension's App ID. With
automatic signing and a paid team, Xcode usually provisions these on first build;
otherwise enable them for the App IDs in the Apple Developer portal.

After installing, enable VaultGuard under **System Settings → General → AutoFill &
Passwords → AutoFill source**, then use it from the password field in Safari. If the
vault is locked, the extension asks you to open VaultGuard and unlock it.

## Privacy

VaultGuard collects nothing. No analytics, no telemetry, no crash reporting, no
tracking, no ads. The developer operates no hosted service and receives no vault
content; in server mode it connects only to the server you configure, and in local
KDBX mode it makes no network connection for vault data. See [PRIVACY.md](PRIVACY.md).

## Reporting security issues

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not
open public issues for security reports.

## Contributing

Issues and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
and [SECURITY.md](SECURITY.md) first.

## Disclaimer

VaultGuard is an independent, open-source project. It is not affiliated with,
endorsed by, sponsored by, or officially connected to Bitwarden Inc. "Bitwarden" and
related marks are trademarks of Bitwarden Inc.; "Vaultwarden" belongs to its
respective authors. These names are used solely to describe server compatibility.
The software is provided "as is", without warranty of any kind.

## License

VaultGuard is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE)
and [NOTICE](NOTICE).
