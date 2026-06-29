# VaultGuard Security Model

> Scope of this document: how VaultGuard handles secrets locally on macOS — key
> material, the Keychain, biometric unlock, the offline cache, the AutoFill cache,
> passkeys, and transport trust. It covers both supported vault types: a
> user-provided self-hosted Bitwarden/Vaultwarden-compatible server, and a local
> KeePass/KDBX database. It does **not** cover the server software itself or the
> Bitwarden protocol.

VaultGuard is a standalone, open-source macOS password manager. It connects to a
server only if the user configures one (their own Bitwarden/Vaultwarden-compatible
endpoint) and otherwise works fully locally with a KeePass/KDBX file. VaultGuard
operates no hosted service and receives no vault content; secrets live only on the
user-configured server (server mode), in the local KDBX file the user selects
(local mode), and locally in the macOS Keychain and encrypted on-disk caches.

## Threat model

**In scope**

- The VaultGuard app and its AutoFill credential provider extension.
- Local handling of secrets: Keychain usage, the encrypted offline cache, the
  AutoFill cache, biometric unlock, passkey storage, and certificate trust.

**Out of scope**

- A user-provided Bitwarden/Vaultwarden-compatible server (report server issues
  upstream).
- An attacker who already has full access to the user's unlocked macOS session.
- General Bitwarden protocol design.

The design goal is that secrets at rest are bound to the device and the unlocked
session, that the master password is never written to disk in any form, and that
the AutoFill extension can reach only the minimum it needs — never the app's
session secrets.

## Keychain access groups

Keychain items are split across two access groups, and `KeychainService` sets
`kSecAttrAccessGroup` explicitly on every item so placement is deterministic:

- **App-private group** (`<team>.com.kruatech.vaultguard.private`) — the app is
  entitled to it; the AutoFill extension is **not**. Holds all session secrets:
  access/refresh tokens, the wrapped (encrypted) user key, KDF parameters, the
  offline-cache key, the account index, server URL / email, KeePass bookmarks,
  the device id, and the biometric-unlock secret.
- **Shared group** (`<team>.com.kruatech.vaultguard`) — readable by both the app
  and the extension. Holds only the minimal AutoFill state: the shared AutoFill
  secret (with its TTL), the active account id, the active vault kind, and
  passkeys.

A one-time migration on first launch after upgrading from a pre-split build wipes
the shared group, so legacy items written before the split (when everything lived
in a single group) cannot be read by the extension. Tokens are intentionally not
migrated into the private group; the user logs in again and AutoFill state is
recreated on unlock.

## Secrets and where they live

| Secret | Location | Protection |
| --- | --- | --- |
| Master password | Never persisted | Held only transiently in memory during login to derive the vault key |
| Derived vault (user) key | In-memory for the session; optionally in Keychain (app-private) for biometric unlock | See "Biometric unlock" |
| Tokens, wrapped user key, KDF params, account index, server/email, KeePass bookmarks | Keychain, app-private group | `WhenUnlockedThisDeviceOnly`, not readable by the extension |
| Offline cache key | Keychain, app-private group | Random per-account key; cache sealed with AES-GCM; not readable by the extension |
| Shared AutoFill secret (fresh random per publish — never the vault key) | Keychain, shared group | `WhenUnlockedThisDeviceOnly`; carries a TTL; fail-closed reads (see "AutoFill") |
| Active account id / active vault kind | Keychain, shared group | `WhenUnlockedThisDeviceOnly`; minimal metadata the extension needs |
| Passkey private keys | Keychain, shared group, data-protection keychain | User-presence access control (see "Passkeys") |

Non-protected items use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, so they
are available only while the device is unlocked and are **not** synchronised to
iCloud Keychain or migrated to other devices.

## Key derivation

On server login the client derives the vault key from the master password using
the KDF advertised by the server — Argon2id or PBKDF2. For a local KDBX database
the master password (and optional key file) derive the composite key through the
KeePass KDF declared in the file header (Argon2 or AES-KDF). In both cases only
the derived/wrapped material is kept in memory for the session; the raw master
password is not retained after derivation.

> Implementation of the KDF and symmetric primitives lives in `CryptoService.swift`
> (server) and `Services/KeePass/*` (KDBX). This document does not restate
> parameter choices; treat those files as the source of truth.

## Data at rest

### Offline cache (main app only)

The last successful server sync is sealed on disk with AES-GCM under a random,
per-account key kept in the app-private Keychain group. The individual cipher
fields inside the cache remain Bitwarden-encrypted as well. This cache is used
only by the main app (e.g. for offline read); the AutoFill extension does **not**
read it and is not entitled to its key.

### AutoFill cache (shared with the extension)

AutoFill uses a separate, minimal cache — not the offline cache above. After
unlock/sync the main app decrypts the vault itself and writes only the fields the
extension needs (item id, name, username, password, URIs) to a per-account file in
the shared App Group container. The file is sealed with AES-GCM under a key
**derived** (HKDF-SHA256) from the shared AutoFill secret, scoped to the account id
and vault kind. Because the key is derived from the shared secret rather than
stored, removing the secret (lock / logout / account removal / local vault close /
TTL expiry) makes the cache unopenable. The extension never receives the real
vault/user key: the shared secret is a fresh random value generated on each
publish, used only to derive the AutoFill cache key.

### Attachment previews

Decrypted attachment previews are written only to an isolated temporary directory.
Older previews are removed before a new preview is produced, and previews are
cleaned up when the app locks.

## Biometric unlock

Biometric unlock (Touch ID) stores, behind a biometric-protected Keychain item in
the app-private group:

- the derived vault key, and
- a hash of the master password (not the master password itself).

The access control is created with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
and the `.biometryCurrentSet` flag, so the OS releases the item only after a
successful biometric check bound to the item, and enrolling/removing a
fingerprint/Face invalidates it (re-enabling biometric unlock then requires the
master password again). A separate, unprotected marker tracks whether biometric
unlock is configured. Logout / "forget biometric" deletes both the protected
secret and the marker.

## AutoFill model

The AutoFill credential provider extension can serve credentials only while the
main app has published a valid **shared AutoFill secret** for the active account:

- The secret is stored in the shared Keychain group with
  `WhenUnlockedThisDeviceOnly` and carries an absolute expiry. The extension reads
  the secret, checks the TTL, derives the AutoFill cache key, and decrypts only the
  minimal AutoFill cache.
- The TTL is configurable (15 minutes / 1 hour / 4 hours / 8 hours; default 4
  hours) via a setting shared between the app and the extension through the App
  Group.
- Reads are **fail-closed**: a secret that is missing, malformed, legacy (no
  expiry), or past its TTL is deleted and treated as absent; a cache that cannot be
  decrypted is invalidated. In all these cases the extension stops serving
  credentials and prompts the user to open and unlock VaultGuard.
- On lock / logout / account removal / local vault close the main app removes the
  shared secret, the active-vault metadata, and the AutoFill cache file.

The extension never reads the offline-cache key, the wrapped user key, or any
token: those live in the app-private group it is not entitled to.

## Passkeys (WebAuthn / FIDO2)

VaultGuard implements passkeys as discoverable credentials, scoped per account:

- A passkey's private key (a P-256 scalar) is stored per account in the shared
  Keychain group, in the data-protection keychain, behind a **user-presence**
  access control. Reading the raw key requires an explicit user check
  (Touch ID or device password); the AutoFill extension obtains a pre-authenticated
  context before each registration or assertion and never falls back to an
  unauthenticated read.
- Passkeys are scoped to the account that created them (keyed by account id), so a
  passkey of one account/vault is not offered under another after an account
  switch.
- Logout, account removal, and local-vault removal delete the account's passkey
  private keys; they do not remain readable afterwards.

> Verification note: reading a user-presence-gated item from the extension process
> across the app/extension boundary is validated on-device (see
> `docs/release-smoke-checklist.md`). If a device shows the assertion failing after
> a successful user check, the project will either move passkey keys to the Secure
> Enclave or document user-presence as enforced only at the prompt level; this
> document will be updated to match whichever holds.

## KeePass (.kdbx) vaults

A KeePass database is a local file, not a server account. VaultGuard opens it
through a security-scoped bookmark, so file access is scoped to what the user
explicitly selected.

- The decrypted vault and the file bytes are held in memory only for the duration
  of the unlocked session. On lock or logout the in-memory backend and the file
  bookmark are cleared.
- The KDBX master/composite key is never shared with the extension. AutoFill for a
  KeePass vault uses the same minimal AutoFill cache as server vaults, sealed under
  a key derived from a fresh shared AutoFill secret; closing the local vault removes
  the secret and deletes the cache file.
- Optional Touch ID for a KeePass account uses the same biometric-protected
  Keychain model as above. What is stored is the SHA-256 password component of the
  KDBX composite key (the format derives the composite key as
  SHA256(SHA256(password) ‖ keyfileKey)), which is sufficient to re-open the
  database and cannot be reversed back to the password — the raw master password
  itself is never persisted. Secrets written by pre-release builds that contained
  the raw password are replaced with the hashed component on the first successful
  biometric unlock.

## Data in transit

- System-trusted server certificates are validated normally.
- Self-signed certificates are **not** silently accepted. The SHA-256 fingerprint
  is shown and must be confirmed once per host (trust-on-first-use). A later
  fingerprint change for a trusted host is flagged.
- **Scope of the pin (accepted trade-off):** the fingerprint pin gates only the
  self-signed path. Any certificate that passes normal system trust evaluation is
  accepted for the host even when a pin exists, so the pin does not defend against
  an attacker presenting a CA-valid certificate for the host (e.g. via a compromised
  or coerced CA, or a trusted enterprise root installed on the Mac). Full
  pin-always-wins enforcement is a possible future hardening.
- Pinned fingerprints are stored in the app's `UserDefaults` (they are public
  certificate hashes, not secrets). Any code running unsandboxed as the same user —
  which is out of scope per the threat model above — could alter them; they are not
  integrity-protected beyond the app sandbox.
- In local KDBX mode no network connection is made for vault access.

## Memory handling (best-effort)

Key material on the server path is held in `SecureBytes` / `SecureString` wrappers
whose primary buffers are zeroed with `memset_s` on wipe/deinit. This is
best-effort containment, not a proof of erasure: Swift's ARC/copy-on-write means
copies produced by accessors (`data`, `string`), bridging, or intermediate
`Data`/`String` values are outside the wrappers' control and are not zeroed. The
KeePass (KDBX) code path currently keeps its derived keys in plain `Data` for the
duration of the unlocked session; they are dropped (not explicitly zeroed) on lock.
An attacker able to read the app's memory is inside the "compromised local
session" case that the threat model already excludes.

## What VaultGuard explicitly does not do

- It does not write the master password to disk in any form.
- It does not synchronise local secrets to iCloud or other devices.
- It operates no hosted service and receives no vault content; it connects only to
  the server the user configures, or to nothing at all in local KDBX mode.
- It collects no analytics, telemetry, crash reports, or tracking.

## Reporting

Report suspected vulnerabilities privately per [SECURITY.md](../SECURITY.md). Do
not open public issues for security reports.

---

### Provenance

Statements above reflect the implementation in `KeychainService.swift`
(two-group access split with explicit `kSecAttrAccessGroup`; AutoFill shared
secret with TTL payload and fail-closed reads; biometric and passkey access
controls; per-account/global teardown), `AutoFillCache.swift` (HKDF-derived,
account/kind-scoped minimal cache), the `AutoFillSecretPayload` struct in
`KeychainService.swift` (TTL encode / validate), `PasskeyStore.swift` and `CredentialProviderViewController+Passkey.swift`
(user-presence-gated passkey storage and the assertion/registration flow), and the
publish/teardown paths in `AppState+Sync.swift`, `AppState+KeePass.swift`, and
`AppState+Auth.swift`. KDF parameters and AES-GCM nonce/tag handling in
`CryptoService` / KDBX readers are treated as the source of truth for those
primitives. The passkey cross-process read is pending on-device confirmation as
noted in the Passkeys section.
