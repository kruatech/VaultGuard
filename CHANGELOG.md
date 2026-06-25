# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-25

First public release.

### Added

- Native macOS client for Bitwarden / Vaultwarden servers (cloud, EU, or self-hosted).
- Vault browsing and management for logins, cards, identities, and secure notes.
- Multi-account support with per-account secret isolation.
- Biometric unlock (Touch ID) that stores only a vault key wrapped behind a biometric-protected Keychain item — the master password is never written to disk.
- TLS certificate fingerprint pinning: self-signed servers require explicit, per-host SHA-256 confirmation, and fingerprint changes are flagged.
- Encrypted offline cache (AES-GCM, per-account key in the Keychain).
- AutoFill credential provider extension for Safari and other apps; serves credentials only while the vault is unlocked, otherwise prompts to open VaultGuard.
- English and Russian localization.

### Security

- Master password is never persisted.
- Keychain write/delete failures during login and logout are surfaced instead of being silently ignored; logout fully wipes per-account secrets, including biometric material.

[1.0.0]: https://github.com/kruatech/VaultGuard/releases/tag/v1.0.0
