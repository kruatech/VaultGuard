# Privacy Policy

**VaultGuard collects no data.** There is no analytics, no telemetry, no crash reporting, no advertising, and no tracking of any kind. The developer receives nothing about you or your usage.

## What VaultGuard does

VaultGuard is an unofficial, third-party client (not affiliated with Bitwarden Inc.) for a Bitwarden-compatible server that you choose (the Bitwarden cloud or your own self-hosted Vaultwarden). All of your vault data lives on that server. VaultGuard only talks to the server URL you configure.

## Network connections

VaultGuard connects **only** to the server you enter when signing in. It makes no other network requests — no third-party services, no developer-controlled endpoints.

## What is stored on your device

- **Keychain:** authentication tokens, account metadata, your account's encryption key material, and — if you enable biometric unlock — the vault key wrapped behind a biometric-protected Keychain item. The master password itself is never stored.
- **Encrypted cache:** the most recent sync is cached on disk, sealed with AES-GCM under a random key kept in the Keychain, so the app can start quickly and work offline. The cipher fields inside remain encrypted by your server's keys as well.

This data never leaves your device except as normal, encrypted requests to your own server. Use **Log out and delete all local data** to remove the account's local Keychain items, encrypted cache, AutoFill shared key, and local account metadata from this Mac. Deleting the app also removes the app sandbox, but Keychain/App Group cleanup is best done from inside the app first.

## AutoFill extension

The AutoFill extension reads only the local encrypted cache and the temporary shared vault key that the main app publishes while the vault is unlocked. When the vault is locked or the user logs out, that shared key is removed.

## Third parties

None. VaultGuard does not embed analytics, advertising SDKs, crash-reporting SDKs, or third-party tracking frameworks, and does not share data with anyone.

## Contact

Questions about privacy: **a@krutilin.pro** (Telegram **@kruatech**).
