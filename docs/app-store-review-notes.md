# App Store review notes

Paste/adapt the following into **App Store Connect → App Review Information →
Notes** when submitting. It gives the reviewer everything needed to exercise a
login-gated, server-backed app.

> Do not submit this file with placeholders. Replace the demo server, email, and
> master password with a real temporary review account before uploading a build.

---

VaultGuard is an unofficial, third-party client for Bitwarden-compatible servers
(Bitwarden cloud or self-hosted Vaultwarden). It is not affiliated with Bitwarden
Inc. The app stores nothing about the user except locally (macOS Keychain + an
encrypted on-disk cache) and on the server the user configures. We (the
developer) collect no data.

## How to sign in (demo)

A login is required because the app talks to a vault server. Please use this demo
server and account:

- Server URL: REPLACE_BEFORE_SUBMISSION_DEMO_SERVER_URL
- Email: REPLACE_BEFORE_SUBMISSION_DEMO_EMAIL
- Master password: REPLACE_BEFORE_SUBMISSION_DEMO_PASSWORD

(If the demo server uses a self-signed certificate, the app will show its SHA-256
fingerprint and ask you to trust it once — tap Trust to continue.)

## How to test AutoFill

1. Sign in and unlock the vault (above).
2. Enable the provider under **System Settings → General → AutoFill & Passwords
   → AutoFill source**, and turn on VaultGuard.
3. In Safari, focus a username/password field and choose VaultGuard to fill.
4. While the vault is locked, the extension asks you to open and unlock VaultGuard
   first (it never serves credentials while locked).

## Encryption / export compliance

Uses only standard encryption (TLS, AES-GCM, Argon2/PBKDF2) to authenticate and
protect the user's own data. `ITSAppUsesNonExemptEncryption` is set to `false`.

## Privacy

No analytics, telemetry, crash reporting, tracking, or ads. Network traffic goes
only to the server the user configures. App Privacy: Data Not Collected.

## Links

- Support: https://github.com/kruatech/VaultGuard
- Privacy policy: https://github.com/kruatech/VaultGuard/blob/main/PRIVACY.md
