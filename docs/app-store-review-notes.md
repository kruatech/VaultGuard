# App Store review notes

Paste/adapt the following into **App Store Connect → App Review Information →
Notes** when submitting.

> This public file contains **no credentials**. VaultGuard does not operate a
> hosted service, so there is no developer account to share. The primary review
> path is fully local and needs no server. For the optional server path, provide
> any sample-database master password (or a throwaway self-hosted account) in the
> App Store Connect review-notes field or as a review attachment — never commit
> real secrets to this repository.

---

VaultGuard is a standalone, open-source password manager for macOS. It is **not** a
hosted service: the developer operates no server and receives no vault content.
Users either open a local KeePass/KDBX database (no server at all) or connect the
app to their own self-hosted Bitwarden/Vaultwarden-compatible server. VaultGuard is
not affiliated with Bitwarden Inc.

The app stores nothing about the user except locally (macOS Keychain + encrypted
on-disk caches) and, in server mode, on the user-provided server. The developer
collects no data.

## Main-window lifecycle fix (Guideline 4)

Build 3 adds a persistent **Window → Show VaultGuard** command (`Command-0`). After
closing the main window with the red close button, reviewers can restore the same
window from that menu item or by clicking VaultGuard in the Dock. The behavior also
works while the separate Settings window remains open; reopening does not create a
duplicate main window.

Verification:

1. Launch VaultGuard.
2. Close the main window using the red close button.
3. Choose **Window → Show VaultGuard**, press `Command-0`, or click the app icon in
   the Dock.
4. The main window reappears and becomes the key window.

## Primary review path — local KeePass/KDBX vault (no server needed)

This path exercises the full app without any server or developer account. A small
sample KeePass database containing only fake test data (sample logins, a secure
note, a folder) is provided with this submission; its master password is given in
the App Store Connect review-notes field / attachment.

1. Open the app.
2. Choose the local KeePass/KDBX storage option.
3. Open the provided sample `.kdbx` database.
4. Enter the sample master password.
5. The local vault unlocks and the item list appears.
6. Open an item to see its details.
7. Use search to filter items.
8. Copy a username and a password.
9. Use the password generator.
10. Lock the local vault, then unlock it again, then close it.

No hosted account is required for any of the above.

## Optional review path — self-hosted server vault (bring-your-own server)

Server mode is for users who already run or can access a Bitwarden/Vaultwarden-
compatible server. The developer does **not** provide or operate the server.

1. Open the app and choose the Bitwarden/Vaultwarden-compatible server option.
2. Enter the URL of a compatible server (any test server you control).
3. Sign in with an existing account on that server.
4. Unlock the vault and work with the items.

(If the server uses a self-signed certificate, the app shows its SHA-256
fingerprint and asks you to trust it once — tap Trust to continue.)

## How to test AutoFill

1. Unlock a vault (local or server, above).
2. Enable the provider under **System Settings → General → AutoFill & Passwords
   → AutoFill source**, and turn on VaultGuard.
3. In Safari, focus a username/password field and choose VaultGuard to fill.
4. While the vault is locked, the extension asks you to open and unlock VaultGuard
   first; it never serves credentials while locked.

## Encryption / export compliance

Uses only standard encryption (TLS, AES-GCM, HKDF, Argon2/PBKDF2) to protect the
user's own data and, in server mode, to authenticate to a user-provided server. No
proprietary cryptography is added. `ITSAppUsesNonExemptEncryption` is set to
`false`.

## Privacy

No analytics, telemetry, crash reporting, tracking, or ads. The developer operates
no server and receives no vault content. In server mode, network traffic goes only
to the user-provided server; in local KDBX mode there is no network access for
vault data. App Privacy: Data Not Collected.

## Links

- Support: https://github.com/kruatech/VaultGuard
- Privacy policy: https://github.com/kruatech/VaultGuard/blob/main/PRIVACY.md
