# Security Policy

## Supported versions

VaultGuard is actively developed and currently pre-release (no published builds yet — see the README build instructions). Security fixes land on the `main` branch; once versioned releases exist, only the latest release and `main` will be maintained.

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
- Keychain items are split into two access groups: an app-private group (tokens, wrapped user key, KDF params, offline-cache key, account index, KeePass bookmarks) that the AutoFill extension is not entitled to, and a shared group holding only minimal AutoFill state.
- Self-signed TLS certificates require explicit SHA-256 fingerprint confirmation and are pinned per host.
- Decrypted attachment previews are written only to an isolated temporary directory, older previews are removed before a new preview, and previews are cleaned up when the app locks.
- AutoFill serves credentials from a separate, minimal cache sealed under a key derived from a short-lived shared secret; lock / logout / account removal / local vault close / TTL expiry all revoke access. The extension never receives the real vault key or any token.
- Passkey private keys are stored behind a user-presence access control and are deleted on logout / account removal / local vault removal.

## Scope

In scope:

- The VaultGuard macOS app and its AutoFill credential provider extension (this repository).
- Local handling of secrets: Keychain usage, the encrypted offline cache, biometric unlock, and certificate trust.

Out of scope:

- The Bitwarden / Vaultwarden server itself — report those to the respective projects.
- Issues that require a compromised local account (an attacker who already has full access to the user's logged-in macOS session).
- General Bitwarden protocol design.
