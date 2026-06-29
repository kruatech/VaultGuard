# VaultGuard — App Store Connect listing (v1.0.0)

Copy each field into the matching App Store Connect input. Character counts are
pre-checked against Apple's limits. Text is grounded in the project README; nothing
is invented. macOS only (no iOS/iPadOS build).

> Note on trademarks (Apple Guideline 5.2.1): "Bitwarden" / "Vaultwarden" are
> third-party names. They are used **referentially** to describe server
> compatibility, never as the product identity, and the description includes a clear
> "independent / not affiliated" statement. Keywords are kept trademark-free by
> default to reduce rejection risk.

---

## App Name  (limit 30 — using 10)
```
VaultGuard
```

## Subtitle  (limit 30 — using 28)
```
Open-source password manager
```

## Keywords  (limit 100 — using 95, comma-separated, no spaces after commas)
Trademark-free by default:
```
password manager,keepass,kdbx,vault,autofill,totp,2fa,self-hosted,passwords,touch id,encryption
```
Adding `vaultwarden` or `bitwarden` can improve discoverability but raises 5.2.1
risk; if you add one, drop a lower-value term to stay ≤100.

## Promotional Text  (limit 170 — using 162; editable later without review)
```
Open-source Mac password manager. Use a local KeePass/KDBX file, or your own self-hosted Bitwarden/Vaultwarden server. Touch ID, AutoFill, TOTP. Collects nothing.
```

## Description  (limit 4000)
```
VaultGuard is an open-source password manager for macOS. It supports local KeePass/KDBX databases and user-provided self-hosted Bitwarden/Vaultwarden-compatible servers. It is an independent app and is not affiliated with, endorsed by, or sponsored by Bitwarden Inc.

VaultGuard is privacy-first and local-first: open a KeePass (.kdbx) file with no server at all, or connect to a Bitwarden/Vaultwarden-compatible server that you run or have access to. The developer operates no hosted service and never receives your vault content.

VAULT TYPES
- Local KeePass/KDBX database (optional key file), decrypted on your Mac — no server needed
- Self-hosted Bitwarden/Vaultwarden-compatible server you provide

WHAT YOU CAN DO
- View and manage logins, cards, identities, and secure notes
- Organize with folders, favorites, and trash
- Generate strong passwords with reusable templates
- Built-in TOTP (two-factor) code generation
- Fill credentials in Safari and other apps with the AutoFill extension
- Search, open item details, and copy username/password
- Unlock quickly with Touch ID
- Work offline with a fast, encrypted local cache (server mode)
- Switch between multiple vaults and accounts, kept isolated
- Available in English and Russian

SECURITY BY DESIGN
- Your master password is never written to disk. The vault key is derived at unlock (Argon2id/PBKDF2 for a server, the KeePass KDF for a .kdbx file) and kept only in memory for the session.
- Touch ID unlock stores only a wrapped key behind a biometric-bound Keychain item — never the master password.
- Session secrets stay in an app-private Keychain group the AutoFill extension cannot read; AutoFill works from a separate minimal cache sealed under a short-lived key.
- Self-signed certificates are never trusted silently: VaultGuard shows the SHA-256 fingerprint for you to confirm once per server, and flags any later change.

PRIVACY
VaultGuard collects nothing. No analytics, no telemetry, no crash reporting, no tracking, and no ads. The developer runs no server and receives no vault content. In server mode it connects only to the server you configure; in local KDBX mode it makes no network connection for your vault.

REQUIREMENTS
None for local KDBX mode. Server mode requires your own Bitwarden/Vaultwarden-compatible server — the developer does not provide one.

VaultGuard is open source under the Apache License 2.0.

"Bitwarden" is a trademark of Bitwarden Inc.; "Vaultwarden" belongs to its respective authors. These names are used only to describe server compatibility. VaultGuard is provided "as is", without warranty of any kind.
```

## What's New (release notes for 1.0.0)  (limit 4000)
```
Initial public release of VaultGuard.

- Local KeePass/KDBX vaults — open a .kdbx file with no server required
- Self-hosted Bitwarden/Vaultwarden-compatible server vaults (bring your own server)
- Logins, cards, identities, and secure notes with folders, favorites, and trash
- Password generator with templates and built-in TOTP codes
- AutoFill extension for Safari and other apps, with a configurable key TTL
- Touch ID unlock without storing your master password
- Encrypted offline cache and multi-vault / multi-account isolation
- SHA-256 certificate pinning for self-signed servers
- English and Russian localization
```

---

## Other App Store Connect fields

- **Primary category:** Utilities
- **Secondary category (optional):** Productivity
- **Age rating:** 4+ (no objectionable content)
- **Copyright:** `© 2026 kruatech` — replace with your legal name/entity if you want the legal owner shown instead.
- **Support URL:** `https://github.com/kruatech/VaultGuard`
- **Marketing URL (optional):** `https://github.com/kruatech/VaultGuard`
- **Privacy Policy URL (required):** `https://github.com/kruatech/VaultGuard/blob/main/PRIVACY.md`
  - A GitHub-rendered Markdown page is accepted. If you prefer a cleaner page, host PRIVACY as plain HTML and use that URL instead.

## App Privacy (Data Collection) questionnaire
- Answer: **Data Not Collected** for every category. (Matches PRIVACY.md — no analytics, telemetry, crash reporting, tracking, or ads; the developer runs no server, and in server mode network traffic goes only to the user's own server.)

## Export Compliance (encryption)
- `ITSAppUsesNonExemptEncryption` is set to `false` in the app Info.plist.
- In App Store Connect this corresponds to: app uses encryption, but only standard/exempt encryption (TLS, and standard algorithms — AES-GCM, HKDF, Argon2/PBKDF2 — for authentication and protecting the user's own data). No custom or proprietary cryptography is added.
- Depending on your jurisdiction an annual self-classification report may still apply. This is not legal advice — confirm for your situation.

## Assets you still need to produce (not text)
- **App icon:** included as a complete macOS AppIcon set in `Assets.xcassets`; verify it visually in Xcode before submission.
- **Screenshots:** at least one per required macOS display size. Show both vault types (local KDBX and self-hosted server). Use only fake/demo data — no real credentials, emails, URLs, or filesystem paths.
- **Sample review database:** a small KeePass `.kdbx` with only fake test data, for the local review path in `docs/app-store-review-notes.md`. Provide its master password in App Store Connect, not in the repo.

## Pre-submission sanity checks
- Both targets share the Team ID (via `Config/Signing.local.xcconfig`) and bundle IDs `com.kruatech.vaultguard` + `com.kruatech.vaultguard.autofill`.
- After building, confirm the `.app` and the embedded `.appex` both report version **1.0.0 (current build)** — they derive from `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` in `project.yml`.
- App Store distribution signing/provisioning selected; the app entitlements include both keychain access groups (`…vaultguard` and `…vaultguard.private`) and the extension only the shared one.
- Passkeys are not advertised in this listing; confirm the passkey assertion path on-device (see `docs/release-smoke-checklist.md`) before listing it as a feature.
