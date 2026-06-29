# Privacy Policy

**VaultGuard collects no data.** There is no analytics, no telemetry, no crash reporting, no advertising, and no tracking of any kind. The developer operates no server, runs no hosted service, and receives nothing about you, your usage, or your vault contents.

## What VaultGuard is

VaultGuard is a standalone, open-source password manager for macOS. It is an independent app and is not affiliated with, endorsed by, or sponsored by Bitwarden Inc. It supports two vault types, both chosen and controlled by you:

- **Local KeePass/KDBX database** — a `.kdbx` file you select on your Mac. It is decrypted locally; its contents are never sent to the developer and, in this mode, VaultGuard makes no network connection for your vault.
- **Self-hosted Bitwarden/Vaultwarden-compatible server** — a server you run or have access to. VaultGuard talks only to the server URL you enter. The developer does not provide or operate this server and never receives your vault content.

## Network connections

- In **local KDBX mode**, VaultGuard makes no network request for your vault data.
- In **server mode**, VaultGuard connects **only** to the server you configure. It makes no other network requests — no third-party services, no developer-controlled endpoints, no analytics.

## What is stored on your device

- **Keychain (app-private):** authentication tokens, account metadata, your account's wrapped encryption key, KDF parameters, the offline-cache key, KeePass file bookmarks, and — if you enable biometric unlock — the vault key wrapped behind a biometric-protected Keychain item. The master password itself is never stored. These items are in a Keychain access group that the AutoFill extension cannot read.
- **Keychain (shared with AutoFill):** only the minimal state the AutoFill extension needs — a short-lived AutoFill secret with an expiry, the active account id and vault kind, and passkeys (behind a user-presence access control).
- **Encrypted caches:** the most recent server sync is cached on disk, sealed with AES-GCM under a random key kept in the app-private Keychain (server mode). AutoFill uses a separate, minimal cache sealed under a key derived from the short-lived AutoFill secret.

This data never leaves your device except as normal, encrypted requests to your own server in server mode. Use **Log out and delete all local data** to remove the account's local Keychain items, encrypted caches, the AutoFill secret/cache, passkeys, and local metadata from this Mac. Closing or removing a local KDBX vault clears its in-memory state and AutoFill data. Deleting the app also removes the app sandbox, but in-app cleanup is best done first.

## AutoFill extension

The AutoFill extension never receives your master password, your vault key, your server tokens, or the offline cache. It reads only a separate, minimal AutoFill cache (item name, username, password, URIs), which it can open only while the main app has published a short-lived secret. When the vault is locked, you log out, the account is removed, the local vault is closed, or the secret's time-to-live expires, that secret is removed and the extension can no longer serve credentials.

## Third parties

None. VaultGuard does not embed analytics, advertising SDKs, crash-reporting SDKs, or third-party tracking frameworks, and does not share data with anyone.

## Contact

Questions about privacy: **a@krutilin.pro** (Telegram **@kruatech**).
