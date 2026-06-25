# VaultGuard

[![CI](https://github.com/kruatech/VaultGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/kruatech/VaultGuard/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![macOS 13+](https://img.shields.io/badge/macOS-13%2B-lightgrey.svg)](README.md)

An **unofficial, third-party** native macOS client for [Bitwarden](https://bitwarden.com/) / [Vaultwarden](https://github.com/dani-garcia/vaultwarden) servers.

VaultGuard talks to a Bitwarden-compatible server that **you** choose — the official Bitwarden cloud, the EU instance, or your own self-hosted Vaultwarden. It stores nothing about you anywhere except on that server and, locally, in the macOS Keychain and an encrypted on-disk cache.

> **Unofficial project.** VaultGuard is an independent client and is **not affiliated with, endorsed by, or sponsored by Bitwarden Inc.** "Bitwarden" is a trademark of Bitwarden Inc.; it is used here only to describe compatibility.
> License: [Apache License 2.0](LICENSE).

## Features

- Connects to any Bitwarden / Vaultwarden server (cloud, EU, or self-hosted).
- View and manage logins, cards, identities, and secure notes.
- Biometric unlock (Touch ID) without ever storing the master password.
- TLS certificate fingerprint pinning with explicit confirmation for self-signed servers.
- Encrypted offline cache for fast startup and read access.
- AutoFill credential provider extension for Safari and other apps.
- Multi-account support with per-account isolation.
- English and Russian localization.

## Security model

- **Master password is never written to disk.** Login derives the vault key (Argon2id or PBKDF2, matching the server's KDF settings); only the derived/wrapped material is kept in memory for the session.
- **Biometric unlock** stores the wrapped vault key and a password hash in the data-protection Keychain behind a `SecAccessControl` bound to the current biometric set (`WhenUnlockedThisDeviceOnly`). Unlocking requires a biometric check against that item; the raw master password is never stored.
- **Transport.** System-trusted certificates are validated normally. Self-signed certificates are not silently accepted: the SHA-256 fingerprint is shown and must be confirmed once per host (trust-on-first-use pinning), and a later fingerprint change is flagged.
- **Offline cache.** The last sync is sealed on disk with AES-GCM under a random per-account key kept in the Keychain. The individual cipher fields inside remain Bitwarden-encrypted as well, so the cache never exposes plaintext vault data.
- **AutoFill.** While the vault is unlocked, the app shares the vault key with its extension through a shared Keychain group so the extension can serve credentials. On lock/logout the shared key is removed; the extension then prompts the user to open and unlock VaultGuard.

## Requirements

- macOS 13 or later
- Xcode 15 or later
- [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`)
- A paid Apple Developer account is needed to build the AutoFill extension (App Group + AutoFill Credential Provider capability).

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

Swift package dependencies are pinned by the Xcode project and `Package.resolved`. `Argon2Swift` is pinned by audited revision because its published package manifest uses a branch-based transitive dependency; Xcode resolves it automatically.

### Verify before publishing

```bash
xcodegen generate
xcodebuild test \
  -scheme VaultGuard \
  -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY=
```

Before a public release, run through [docs/release-checklist.md](docs/release-checklist.md).

### AutoFill setup

The AutoFill extension requires an App Group (`group.com.kruatech.vaultguard`) and the AutoFill Credential Provider capability on the extension's App ID. With automatic signing and a paid team, Xcode usually provisions these on first build; otherwise enable them for the App IDs in the Apple Developer portal.

After installing, enable VaultGuard under **System Settings → General → AutoFill & Passwords → AutoFill source**, then use it from the password field in Safari. If the vault is locked, the extension asks you to open VaultGuard and unlock it.

## Privacy

VaultGuard collects nothing. No analytics, no telemetry, no crash reporting, no tracking, no ads. It connects only to the server you configure. See [PRIVACY.md](PRIVACY.md).

## Reporting security issues

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not open public issues for security reports.

## Contributing

Issues and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) first.

## Disclaimer

VaultGuard is an unofficial, third-party project, developed independently. It is not affiliated with, endorsed by, sponsored by, or in any way officially connected to Bitwarden Inc. "Bitwarden" and related marks are trademarks of Bitwarden Inc.; "Vaultwarden" belongs to its respective authors. These names are used solely to describe server compatibility. The software is provided "as is", without warranty of any kind.

## License

VaultGuard is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
