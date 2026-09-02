# VaultGuard

[![CI](https://github.com/kruatech/VaultGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/kruatech/VaultGuard/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Apple Platforms](https://img.shields.io/badge/Apple-macOS%20%7C%20iOS%20%7C%20iPadOS%20%7C%20watchOS-lightgrey.svg)](https://apps.apple.com/kz/app/vaultguard-secure/id6784213427)

# [VaultGuard Secure — App Store](https://apps.apple.com/kz/app/vaultguard-secure/id6784213427)

**VaultGuard is an open-source password manager for macOS, iOS, iPadOS, and watchOS** with support for local [KeePass](https://keepass.info/) (`.kdbx`) databases and user-provided self-hosted [Bitwarden](https://bitwarden.com/) / [Vaultwarden](https://github.com/dani-garcia/vaultwarden)-compatible servers.

VaultGuard is a standalone, multi-vault, privacy-first app. It can work fully locally with a KeePass/KDBX file (no server at all), or connect to a Bitwarden/Vaultwarden-compatible server that **you** run or have access to.

The developer operates no hosted service and receives no vault content. Secrets live only in the local database you select, on the server you configure, and in the platform's protected local storage and encrypted on-device caches.

> **Trademarks / affiliation.** VaultGuard is an independent project and is **not affiliated with, endorsed by, or sponsored by Bitwarden Inc.** "Bitwarden" is a trademark of Bitwarden Inc.; "Vaultwarden" belongs to its respective authors. These names are used only to describe server compatibility — VaultGuard is not an official Bitwarden client.
>
> License: [Apache License 2.0](LICENSE).

## Download

**VaultGuard Secure** is available on the App Store for supported Apple platforms:

**[Download VaultGuard Secure on the App Store](https://apps.apple.com/kz/app/vaultguard-secure/id6784213427)**

Supported platforms:

* macOS
* iOS
* iPadOS
* watchOS

## Supported vault types

* **Local KeePass/KDBX vault** — open a `.kdbx` file with an optional key file. The database is decrypted locally using the KeePass KDF. No server is required.
* **Self-hosted server vault** — connect to a Bitwarden/Vaultwarden-compatible server you provide. Bring your own endpoint; the developer does not operate a hosted vault service.

## Features

* View and manage logins, cards, identities, and secure notes.
* Organize vault items with folders, favorites, and trash.
* Built-in password generator with reusable templates.
* TOTP code generation.
* AutoFill credential provider integration.
* Search, item details, and one-tap copy of usernames and passwords.
* Biometric unlock without storing the master password.
* Encrypted offline cache for fast startup and read access in server mode.
* **Send** — share encrypted text or files via a link in server mode.
* Import from Bitwarden JSON / CSV and export to KeePass.
* TLS certificate fingerprint pinning with explicit confirmation for self-signed servers.
* Multi-account and multi-vault support with per-source isolation.
* English and Russian localization.
* Native support across macOS, iOS, iPadOS, and watchOS.

## Feature status

**Stable**

* Local KeePass/KDBX open, unlock, browse, search, item details, and copy.
* Self-hosted server login, unlock, vault list, item details, search, and copy.
* Password generator and TOTP.
* AutoFill with a configurable, enforced shared-key TTL.
* Biometric unlock.
* Lock, logout, account removal, and local-vault cleanup.

**In progress / limitations**

* **Passkeys / FIDO2** are implemented and wired into AutoFill (registration + assertion), with private keys stored behind a user-presence access control. One cross-process read path is pending on-device confirmation (see [docs/release-smoke-checklist.md](docs/release-smoke-checklist.md)); until confirmed, treat passkeys as preview.
* KeePass (`.kdbx`) is read-write, but some advanced KDBX features may not be preserved on save.
* No independent security audit has been performed.
* Manual light/dark/high-contrast visual QA is ongoing.

## Security model

* **Master password is never written to disk.** Server login derives the vault key using Argon2id or PBKDF2, matching the server's KDF. A local KDBX file is opened with the KeePass KDF (Argon2 / AES-KDF). Only derived or wrapped material is kept in memory for the session.
* **Protected credential storage.** Sensitive session material is stored using Apple platform security facilities and is isolated from components that do not require access to it.
* **Biometric unlock** stores wrapped key material behind platform authentication controls; the raw master password is never stored.
* **AutoFill** serves credentials from a separate, minimal cache sealed under a key derived from a short-lived shared secret. The extension never receives the real vault key or server token. Lock, logout, account removal, local-vault close, and TTL expiry revoke access.
* **Passkeys** private keys are stored behind a user-presence access control and are deleted on logout, account removal, or local-vault removal.
* **Transport security** in server mode uses normal system certificate validation. Self-signed certificates require explicit SHA-256 fingerprint confirmation (trust-on-first-use), and subsequent certificate changes are flagged.

See [docs/security-model.md](docs/security-model.md) for the full security model.

## Requirements

For installation from the App Store, use a supported Apple device running a compatible version of macOS, iOS, iPadOS, or watchOS.

For building from source:

* Xcode 15 or later
* [XcodeGen](https://github.com/yonaskolb/XcodeGen)
* A paid Apple Developer account is required for capabilities such as App Groups and AutoFill Credential Provider when building and signing those targets.

## Build and run

```bash
# 1. Optional: only needed for locally signed builds.
cp Config/Signing.example.xcconfig Config/Signing.local.xcconfig
# then edit Config/Signing.local.xcconfig and set your DEVELOPMENT_TEAM (Apple Team ID)

# 2. Generate the Xcode project.
xcodegen generate

# 3. Open the project:
open VaultGuard.xcodeproj
```

Swift package dependencies are pinned by the Xcode project and `Package.resolved`.

`Argon2Swift` is pinned by audited revision because its published package manifest uses a branch-based transitive dependency; Xcode resolves it automatically.

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

Before a public release, run through [docs/release-checklist.md](docs/release-checklist.md) and the device checks in [docs/release-smoke-checklist.md](docs/release-smoke-checklist.md).

### AutoFill setup

On supported Apple platforms, enable VaultGuard as an AutoFill credential provider in the system password and AutoFill settings.

If the vault is locked when credentials are requested, VaultGuard will require the vault to be unlocked before protected credentials can be accessed.

## Privacy

VaultGuard collects nothing.

No analytics, no telemetry, no tracking, and no ads.

The developer operates no hosted vault service and receives no vault content. In server mode, VaultGuard connects only to the server you configure. In local KDBX mode, your vault data remains local.

See [PRIVACY.md](PRIVACY.md) for details.

## Reporting security issues

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

Do not open public issues for security reports.

## Contributing

Issues and pull requests are welcome.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) first.

## Disclaimer

VaultGuard is an independent, open-source project. It is not affiliated with, endorsed by, sponsored by, or officially connected to Bitwarden Inc.

"Bitwarden" and related marks are trademarks of Bitwarden Inc.; "Vaultwarden" belongs to its respective authors. These names are used solely to describe server compatibility.

The software is provided "as is", without warranty of any kind.

## License

VaultGuard is licensed under the Apache License, Version 2.0.

See [LICENSE](LICENSE) and [NOTICE](NOTICE).
