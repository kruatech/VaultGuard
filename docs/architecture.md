# VaultGuard Architecture

> A map of how the codebase is organised: the build targets, the layers, the
> central `AppState` hub, the service layer, and how Bitwarden and KeePass vaults
> share one interface. Security-sensitive details (key handling, Keychain,
> AutoFill secret sharing) live in [security-model.md](security-model.md); building,
> testing and the rules for concurrency-sensitive code live in
> [development.md](development.md).

## Targets

The project is generated from `project.yml` by XcodeGen and has three targets:

- **VaultGuard** — the macOS app (SwiftUI).
- **AutoFillProvider** (`VaultGuard/AutoFillProvider/`) — the credential provider
  extension, a separate process that serves credentials to Safari and other apps.
  It compiles an explicit subset of the app's sources. It never sees the vault key:
  it reads a short-lived shared secret — a fresh random value published by the app
  while unlocked — and derives from it the key to a separate, minimal AutoFill cache.
- **VaultGuardTests** — unit and acceptance tests. The target compiles an explicit
  list of app sources rather than hosting the app; see *Testing* below.

One local Swift package, `Packages/Argon2`, provides the `CArgon2` module — the
Argon2 reference implementation, vendored. There are no remote packages.

## Layers

```
Views (SwiftUI)            AuthView, MainView, SidebarView, ItemsListView,
        │                  DetailView, EditItemView, GeneratorView, SendsView,
        │                  SettingsView, PasswordHealthView, ZipPreview
        ▼
AppState (@MainActor)  ◄── AccountManager / Account   (multi-account state)
        │                  LocalizationManager (L10n), TextScaleManager
        ▼
Services               APIService, CryptoService, Argon2KDF, KeychainService,
        │              VaultCache, AutoFillCache, VaultDecryptor,
        │              VaultBackend(+KeePassBackend), VaultMigrator,
        │              OnePasswordImporter, ZipArchive, TOTPService,
        │              NetworkDelegate, CredentialIdentityStore, PasskeyStore,
        │              Fido2, SecureData, Logger, KeePass/*
        │              — pure logic, extracted for testing:
        │              VaultListPipeline, RecentCiphersStore, SearchTranslit,
        │              PasswordAudit, KeePassBackupPolicy, ZipListing,
        │              BitwardenEndpoints, AutoFillHostMatcher (Shared/)
        ▼
Models                 VaultCipher and friends, sync/token responses
        ▼
Packages/Argon2        CArgon2 — vendored C, reached only through Argon2KDF
```

Views observe `AppState` (and `AccountManager`, `LocalizationManager`,
`TextScaleManager`) as `@EnvironmentObject`s. State flows down; user actions call
methods on `AppState`, which talks to the service layer.

## AppState — the central hub

`AppState` is a single `@MainActor final class AppState: ObservableObject`. It is
the coupling point of the app: UI state, session lifecycle, vault operations,
sync, clipboard, sends, attachments, KeePass, and migration all hang off it. The
implementation is split across one core file plus topical extensions:

| File | Responsibility |
| --- | --- |
| `AppState.swift` | Published state surface; `recomputeDerived`, which delegates to `VaultListPipeline`; the crypto session (`wipeCryptoSession`, `installCryptoSession`); the recently-used list; per-account preferences (`forgetAccountPreferences`); `AppTheme`, `ToastMessage` |
| `AppState+Auth.swift` | Login (KDF run off the main actor via `deriveSession`), certificate-trust prompt, 2FA, session establishment, biometric unlock, lock, logout, account removal |
| `AppState+Vault.swift` | Folder CRUD; cipher save / delete / duplicate / favourite / move; bulk delete / move / favourite for a selection; `encryptCipherRequest` |
| `AppState+Sync.swift` | `syncVault`, apply sync data, `applyDecryptedVault`, `refresh` |
| `AppState+Session.swift` | Sleep observers, auto-lock timer, activity tracking, theme application |
| `AppState+Clipboard.swift` | Copy with timed clear, cleared again on lock; marks copies concealed/transient; records use for the recently-used list |
| `AppState+Navigation.swift` | Vault/org switching, folder reordering, next/previous selection, copy selected field |
| `AppState+Reprompt.swift` | Master-password reprompt gate; `verifyMasterPassword` (KDF off the main actor, constant-time compare) |
| `AppState+Send.swift` | Bitwarden Send create / load / update / delete (text and file); remove a Send's password |
| `AppState+Attachments.swift` | Attachment upload / download / delete, with a size limit checked before reading and encryption off the main actor; preview-type helpers |
| `AppState+KeePass.swift` | Open / create / unlock / save / delete for local KeePass vaults; bulk operations; pre-save snapshots; export to Bitwarden JSON; publish to AutoFill |
| `AppState+Migration.swift` | Export to KDBX; import KDBX / Bitwarden JSON / CSV / 1Password `.1pux`; batch progress |

### State surface

The published state groups into: unlock/loading/error flags; vault data
(`ciphers`, `folders`, `collections`, `organizations`, profile); list controls
(`filter`, `sort`, `searchText`, `selectedCipherIds` — a set, for multiple
selection, with `selectedCipherId` kept as a single-selection view of it); batch
progress; a large set of sheet/dialog toggles (edit, delete, bulk delete,
generator, settings, sends, password health, 2FA, cert trust, folder dialogs);
`toasts`; and folder ordering / password-template preferences. Several setters
trigger `recomputeDerived()` to refresh the filtered list and the sidebar counts.

> Architectural note: because `AppState` concentrates this much responsibility,
> it is the main thing to understand before changing behaviour, and the main
> candidate for future decomposition. The extension split keeps files readable
> but does not reduce the coupling.
>
> It also cannot be unit-tested: it depends on the network client and the Keychain,
> which the test target does not build. Logic that needs tests is moved out into a
> type the test target can build — the *pure logic* group in the diagram above —
> and `AppState` keeps the state and calls it. `recomputeDerived` is the model:
> the filtering, search, sort and counting now live in `VaultListPipeline`.

## Multi-account

- `Account` (`ViewModels/Account.swift`) — a `Codable` account record. Its id is
  derived from server URL + email; `VaultKind` distinguishes Bitwarden-backed
  from KeePass-backed accounts. Two normalisations of the server URL exist on
  purpose: `identityKey` lowercases everything and is used only for the id, which
  keys the account's Keychain items and must never change; `normalizeServer`
  lowercases only scheme and host, keeping the path's case, and is what gets stored
  and used for requests.
- `AccountManager` (`ViewModels/AccountManager.swift`) — `ObservableObject` that
  owns the account set, the active-account pointer, and their persistence
  (`load` / `persist`), plus `upsert` / `setLabel` / `setActive` / `remove`. A
  stored index that fails to decode is never overwritten.

## Service layer

| Service | Role |
| --- | --- |
| `APIService` (`actor`) | Bitwarden / Vaultwarden REST client; token refresh is single-flight |
| `BitwardenEndpoints` | Region table for Bitwarden cloud hosts, dependency-free |
| `CryptoService` | `EncType`, `EncString`, `SymmetricCryptoKey` — encrypted-string parsing, symmetric primitives, PBKDF2, password generation |
| `Argon2KDF` | The only caller of the vendored `CArgon2` module; used for both Bitwarden and KeePass Argon2 |
| `KeychainService` | Low-level Keychain store, per-account scoped store, biometric helpers, the shared AutoFill secret, passkey storage |
| `VaultCache` | Encrypted on-disk cache of the last successful sync (main app only) |
| `AutoFillCache` | The minimal cache the extension reads, sealed under a key derived from the shared AutoFill secret |
| `VaultDecryptor` | Produces a `DecryptedVault` off the main thread |
| `VaultBackend` (protocol) + `KeePassBackend` | Abstraction so Bitwarden and KeePass vaults present one interface |
| `VaultMigrator` | Pure transforms between formats: decrypted vault ↔ KeePass document, Bitwarden JSON import/export, CSV import, and the `.1pux` entry point (no I/O) |
| `OnePasswordImporter` | 1Password `.1pux` export → importable entries |
| `ZipArchive` | Minimal, bounds-checked ZIP reader used to extract `export.data` from a `.1pux` |
| `ZipListing` | Lists a zip attachment's entries for preview, without extracting anything |
| `TOTPService` | TOTP with `otpauth://` and `steam://` support; HOTP URIs are rejected |
| `PasswordAudit` | Password health findings — reused, weak, empty, stale |
| `SearchTranslit` | Expands a search query into its transliterated and wrong-layout spellings |
| `VaultListPipeline` | Filter, search, sort and sidebar counts; also defines `VaultFilter` and `VaultSort` |
| `RecentCiphersStore` | The recently-used list: ordering, de-duplication, cap, per-account persistence |
| `KeePassBackupPolicy` | Naming and per-vault rotation of KeePass pre-save snapshots |
| `NetworkDelegate` | `CertTrustStore` (trust-on-first-use pin policy) + `PinnedCertDelegate` (URLSession delegate) |
| `CredentialIdentityStoreManager` | Mirrors logins into the system credential-identity store for the QuickType bar |
| `PasskeyStore` | Local per-account passkey storage in the shared Keychain group (JSON array of `Fido2.Credential`); refuses to write back a set it could not read |
| `Fido2` | WebAuthn / FIDO2 crypto core (P-256 / ES256, CBOR/COSE byte construction); independent of AutoFill wiring |
| `SecureData` | `SecureBytes` / `SecureString` — zero-on-dealloc wrappers for secret material |
| `LocalizationManager` | `AppLanguage`, the `L10n` key namespace, runtime language switching |
| `TextScaleManager` | The app's own text size, applied through `VGFont` — macOS has no Dynamic Type |
| `Logger` | `Log` logging facade, including the always-on `audit` channel |
| `SendModels` | Codable request/response models for Send |

## Vault backends

The app supports two kinds of vault behind the `VaultBackend` protocol:

- **Bitwarden / Vaultwarden** — `APIService` fetches sync data, `VaultCache`
  seals it on disk, and `VaultDecryptor` turns it into a `DecryptedVault` that
  `AppState` publishes.
- **KeePass** — `KeePassBackend` plus the `Services/KeePass/` subsystem operates
  on a local `.kdbx` file. `AppState+KeePass.swift` drives open / unlock / save.

### Saving a KeePass file

A save runs the file's KDF twice — once to encrypt, once to prove the written
file opens — which is far too slow for the main actor, but the backend's document
is edited there. `KeePassBackend` therefore splits a save in three:

- `makeSaveSnapshot()` — on the main actor, before anything suspends: a private
  copy of the document and the values a save needs.
- `build(_:)` and `verify(_:against:)` — pure, run off the main actor on the
  snapshot.
- `currentVault()` — the synchronous re-read after an edit, on the main actor.

`AppState.writeKeePassToDisk` chains saves so they finish in the order they were
requested; an older snapshot can never land after a newer one. Before each write
the previous file is kept as a snapshot, rotated per vault by `KeePassBackupPolicy`.

### KeePass subsystem (`Services/KeePass/`)

| File | Role |
| --- | --- |
| `KDBXReader.swift` | Parse a `.kdbx` database (`KDBXDatabase`), KDBX 3.1 and 4.x; decompression is capped |
| `KDBXVaultMapper.swift` | Map a parsed KDBX into the app's vault model, including KeePassXC TOTP settings, expiry and tags |
| `KDBXWriter.swift` | `KDBXEditor` / `KDBXWriter` — edit the document and build an encrypted `.kdbx` (always KDBX 4; a converted 3.1 file becomes 4.1) |
| `KeePassKDF.swift` | KeePass key derivation: AES-KDF, and Argon2 through `Argon2KDF` |
| `KeePassStreamCiphers.swift` | Inner stream ciphers (`ChaCha20Cipher`, `Salsa20Cipher`) |

## AutoFill extension

`VaultGuard/AutoFillProvider/` is a separate process:

- `CredentialProviderViewController` (`ASCredentialProviderViewController`) — the
  password AutoFill flow (`prepareCredentialList`, `provideCredentialWithoutUserInteraction`, etc.).
- `CredentialProviderViewController+Passkey.swift` — passkey registration and
  assertion (macOS 14+), kept as an extension so the password flow stays untouched.
- `AutoFillVault.swift` — reads the shared AutoFill secret for the active account,
  opens the minimal `AutoFillCache` with it, and matches credentials to the request.
  It never opens the vault itself.
- `Shared/AutoFillHostMatcher.swift` — the host parsing and matching that decides
  whose password is offered, kept dependency-free so it can be tested.

The extension works only while the app has published a valid shared secret; see
[security-model.md](security-model.md) for the trust and lifetime rules.

## App entry point and shared configuration

- `App/VaultGuardApp.swift` — `AppLauncher` is the real `@main`: under XCTest it
  starts an empty stand-in app so unit tests do not launch the UI, otherwise it
  starts `VaultGuardApp`. `VaultGuardApp` declares the menu commands and keyboard
  shortcuts (new item, lock, generator, sync, search, text size, show window) and
  installs the local event monitor that feeds the auto-lock activity timer.
- `App/MainWindowController.swift` — owns the single main window so it can be
  closed and restored without creating duplicates.
- `Shared/SharedConfig.swift` — the identifiers shared by the app and the extension:
  the App Group and its container and defaults, the AutoFill secret's TTL setting,
  and the two Keychain access groups (shared and app-private).

## Models

`Models/Models.swift` holds the domain types: `VaultCipher` and its sub-types
(`CipherLogin`, `CipherCard`, `CipherIdentity`, `CipherSecureNote`,
`CipherAttachment`, `CipherField`, `CipherUri`), `VaultFolder` /
`VaultCollection` / `VaultOrganization`, and the server response shapes
(`PreloginResponse`, `TokenResponse`, `SyncResponse`, and friends).

## Testing

`VaultGuardTests` compiles an explicit list of app sources — everything it needs,
and nothing that pulls in the network client or the Keychain. Besides unit tests it
contains acceptance tests of the KeePass write path (`KeePassVaultAcceptanceTests`,
`KeePassSaveSnapshotTests`) and real `.kdbx` fixtures for each container variant,
generated by the scripts in `scripts/`. There are no UI tests. See
[development.md](development.md).

---

### Notes for maintainers

- Provenance: every component above was taken from the corresponding source
  file's declarations and doc comments — type kinds, method names, and the stated
  responsibilities are as written in the code.
- An earlier version of this document said the AutoFill extension reads a shared
  *vault key*. It never did: it reads a separate random secret and a separate
  minimal cache, which is what keeps the vault key out of the extension.
- `CryptoService` internals (KDF parameters, AES specifics) are named here but not
  detailed — treat `CryptoService.swift` and `Argon2KDF.swift` as authoritative.
