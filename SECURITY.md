# Security Policy

## Supported versions

VaultGuard is actively developed. Security fixes are applied to the latest released version (currently 1.0.0) and the `main` branch. Older versions are not maintained.

## Reporting a vulnerability

Please report security issues **privately**. Do **not** open a public GitHub issue, pull request, or discussion for a vulnerability.

- Email: **a@krutilin.pro**
- Telegram: **@kruatech**

If possible, include:

- A description of the issue and its impact.
- Steps to reproduce, or a proof of concept.
- The affected version / commit, and your environment (macOS version, server type — Bitwarden cloud or self-hosted Vaultwarden).
- Any suggested remediation.

## What to expect

Reports are handled on a best-effort basis by a small project. You can expect an acknowledgement of your report and, once a fix is available, coordination on disclosure timing. Please allow reasonable time for a fix before any public disclosure.

## Security model summary

- The master password is never persisted. Biometric unlock stores biometric-protected vault key material, not the raw master password.
- Self-signed TLS certificates require explicit SHA-256 fingerprint confirmation and are pinned per host.
- Decrypted attachment previews are written only to an isolated temporary directory, older previews are removed before a new preview, and previews are cleaned up when the app locks.
- AutoFill can serve credentials only while the main app has published the temporary shared vault key for the currently unlocked account.

## Scope

In scope:

- The VaultGuard macOS app and its AutoFill credential provider extension (this repository).
- Local handling of secrets: Keychain usage, the encrypted offline cache, biometric unlock, and certificate trust.

Out of scope:

- The Bitwarden / Vaultwarden server itself — report those to the respective projects.
- Issues that require a compromised local account (an attacker who already has full access to the user's logged-in macOS session).
- General Bitwarden protocol design.
