# VaultGuard — App Store Connect listing (v1.0.0)

Copy each field into the matching App Store Connect input. Character counts are pre‑checked against Apple's limits. Text is grounded in the project README; nothing is invented.

> Note on trademarks (Apple Guideline 5.2.1): "Bitwarden" is a third‑party trademark. Using it *referentially* to describe compatibility, together with a clear "unofficial / not affiliated" statement, is the approach taken below. There is still some review risk in the **Subtitle** and **Keywords** specifically. Two options are provided for the subtitle; keywords are kept trademark‑free by default.

---

## App Name  (limit 30 — using 10)
```
VaultGuard
```

## Subtitle  (limit 30)
Primary, lower-risk subtitle (23 chars):
```
Unofficial vault client
```

Compatibility with Bitwarden-compatible servers is described in the full description with a clear unofficial/non-affiliation statement.

## Keywords  (limit 100 — using 97, comma‑separated, no spaces after commas)
Trademark‑free by default to reduce rejection risk:
```
password manager,vault,autofill,totp,2fa,self-hosted,passwords,login,touch id,encryption,security
```
Adding `vaultwarden` or `bitwarden` here is at your discretion — it can improve discoverability but raises 5.2.1 risk. If you add one, drop a lower‑value term to stay ≤100.

## Promotional Text  (limit 170 — using 164; editable later without review)
```
A fast, native, unofficial Mac client for compatible password vault servers. Touch ID unlock, AutoFill, TOTP, and an encrypted offline cache. It collects nothing.
```

## Description  (limit 4000 — using ~1962)
```
VaultGuard is an unofficial, third-party macOS client for Bitwarden and Vaultwarden servers. It is an independent app and is not affiliated with, endorsed by, or sponsored by Bitwarden Inc.

Connect VaultGuard to the Bitwarden-compatible server you choose — the official Bitwarden cloud, the EU instance, or your own self-hosted Vaultwarden — and manage your vault from a fast, native Mac app.

WHAT YOU CAN DO
- View and manage logins, cards, identities, and secure notes
- Organize with folders, favorites, and trash
- Generate strong passwords with reusable templates
- Built-in TOTP (two-factor) code generation
- Fill credentials in Safari and other apps with the AutoFill extension
- Unlock quickly with Touch ID
- Work offline with a fast, encrypted local cache
- Switch between multiple accounts, fully isolated
- Available in English and Russian

SECURITY BY DESIGN
- Your master password is never written to disk. The vault key is derived at login (Argon2id or PBKDF2, matching your server) and kept only in memory for the session.
- Touch ID unlock stores only a wrapped key behind a biometric-bound Keychain item — never the master password.
- Self-signed certificates are never trusted silently: VaultGuard shows the SHA-256 fingerprint for you to confirm once per server, and flags any later change.
- The offline cache is sealed with AES-GCM under a random per-account key, and the vault data inside stays end-to-end encrypted.

PRIVACY
VaultGuard collects nothing. No analytics, no telemetry, no crash reporting, no tracking, and no ads. It connects only to the server you configure.

REQUIREMENTS
A Bitwarden-compatible account on a server you control or have access to.

VaultGuard is open source under the Apache License 2.0.

"Bitwarden" is a trademark of Bitwarden Inc.; "Vaultwarden" belongs to its respective authors. These names are used only to describe server compatibility. VaultGuard is provided "as is", without warranty of any kind.
```

## What's New (release notes for 1.0.0)  (limit 4000 — using ~489)
```
Initial release of VaultGuard.

- Connect to Bitwarden or Vaultwarden servers (cloud, EU, or self-hosted)
- Logins, cards, identities, and secure notes with folders, favorites, and trash
- Password generator with templates and built-in TOTP codes
- AutoFill extension for Safari and other apps
- Touch ID unlock without storing your master password
- SHA-256 certificate pinning for self-signed servers
- Encrypted offline cache and multi-account support
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
  - A GitHub‑rendered Markdown page is accepted. If you prefer a cleaner page, host PRIVACY as plain HTML and use that URL instead.

## App Privacy (Data Collection) questionnaire
- Answer: **Data Not Collected** for every category. (Matches PRIVACY.md — no analytics, telemetry, crash reporting, tracking, or ads; network traffic goes only to the user's configured server.)

## Export Compliance (encryption)
- `ITSAppUsesNonExemptEncryption` is already set to `false` in the app Info.plist.
- In App Store Connect this corresponds to: app uses encryption, but only standard/exempt encryption (TLS, and Apple/standard algorithms for authentication and protecting the user's own data). No custom or proprietary cryptography is added.
- Depending on your jurisdiction an annual self‑classification report may still apply. This is not legal advice — confirm for your situation.

## Assets you still need to produce (not text)
- **App icon:** included as a complete macOS AppIcon set in `Assets.xcassets`; verify it visually in Xcode before submission.
- **Screenshots:** at least one for the required macOS display size(s). Avoid showing real credentials; use a demo vault.

## Pre‑submission sanity checks
- Both targets share the Team ID (via optional `Config/Signing.local.xcconfig`) and bundle IDs `com.kruatech.vaultguard` + `com.kruatech.vaultguard.autofill`.
- After building, confirm the `.app` and the embedded `.appex` both report version **1.0.0 (1)** — they now derive from `MARKETING_VERSION` / `CURRENT_PROJECT_VERSION` in `project.yml`.
- App Store distribution signing/provisioning selected (notarization is only needed if you also ship a DMG outside the App Store).
