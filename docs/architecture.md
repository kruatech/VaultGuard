# VaultGuard Architecture

> A map of how the codebase is organised: the two build targets, the layers, the
> central `AppState` hub, the service layer, and how Bitwarden and KeePass vaults
> share one interface. Security-sensitive details (key handling, Keychain,
> AutoFill key sharing) live in [security-model.md](security-model.md).

## Targets

VaultGuard ships two targets that share source under `VaultGuard/`:

- **VaultGuard** — the macOS app (SwiftUI).
- **AutoFill credential provider extension** (`VaultGuard/AutoFillProvider/`) — a
  separate process that serves credentials to Safari and other apps. It reuses
  a subset of the app's services and reads a temporary shared vault key from a
  shared Keychain access group.

## Layers

```
Views (SwiftUI)            AuthView, MainView, SidebarView, ItemsListView,
        │                  DetailView, EditItemView, GeneratorView, SendsView,
        │                  SettingsView, ZipPreview
        ▼
AppState (@MainActor)  ◄── AccountManager / Account   (multi-account state)
        │                  LocalizationManager (L10n)
        ▼
Services               APIService, CryptoService, KeychainService, VaultCache,
        │              VaultDecryptor, VaultBackend(+KeePassBackend),
        │              VaultMigrator, TOTPService, NetworkDelegate,
        │              CredentialIdentityStore, PasskeyStore, Fido2, SecureData,
        │              Logger, KeePass/*
        ▼
Models                 VaultCipher and friends, sync/token responses
```

Views observe `AppState` (and `AccountManager`, `LocalizationManager`) as
`@EnvironmentObject`s. State flows down; user actions call methods on `AppState`,
which talks to the service layer.

## AppState — the central hub

`AppState` is a single `@MainActor final class AppState: ObservableObject`. It is
the coupling point of the app: UI state, session lifecycle, vault operations,
sync, clipboard, sends, attachments, KeePass, and migration all hang off it. The
implementation is split across one core file plus topical extensions:

| File | Responsibility |
| --- | --- |
| `AppState.swift` | Published state surface; derived/filtered list (`recomputeDerived`); core enums (`VaultFilter`, `VaultSort`, `AppTheme`, `ToastMessage`) |
| `AppState+Auth.swift` | Login, certificate-trust prompt, 2FA, session establishment, biometric unlock |
| `AppState+Vault.swift` | Folder CRUD; cipher save / delete / duplicate / favourite / move; `encryptCipherRequest` |
| `AppState+Sync.swift` | `syncVault`, apply sync data, `applyDecryptedVault`, `refresh` |
| `AppState+Session.swift` | Sleep observers, auto-lock timer, activity tracking, theme application |
| `AppState+Clipboard.swift` | Copy with timed clear; toast presentation |
| `AppState+Navigation.swift` | Vault/org switching, folder reordering, next/previous selection, copy selected field |
| `AppState+Reprompt.swift` | Master-password reprompt gate; `verifyMasterPassword` (constant-time compare) |
| `AppState+Send.swift` | Bitwarden Send create / load / update / delete (text and file) |
| `AppState+Attachments.swift` | Attachment upload / download / delete; preview-type helpers |
| `AppState+KeePass.swift` | Open / create / unlock / save / delete for local KeePass vaults; publish to AutoFill |
| `AppState+Migration.swift` | Export to KDBX; import KDBX / Bitwarden JSON / CSV |

### State surface

The published state groups into: unlock/loading/error flags; vault data
(`ciphers`, `folders`, `collections`, `organizations`, profile); list controls
(`filter`, `sort`, `searchText`, `selectedCipherId`); a large set of
sheet/dialog toggles (edit, delete, generator, settings, sends, 2FA, cert trust,
folder dialogs); `toasts`; and folder ordering / password-template preferences.
Several setters trigger `recomputeDerived()` to refresh the filtered list.

> Architectural note: because `AppState` concentrates this much responsibility,
> it is the main thing to understand before changing behaviour, and the main
> candidate for future decomposition. The extension split keeps files readable
> but does not reduce the coupling.

## Multi-account

- `Account` (`ViewModels/Account.swift`) — a `Codable` account record. Its id is
  derived from server URL + email; `VaultKind` distinguishes Bitwarden-backed
  from KeePass-backed accounts; `normalizeServer` canonicalises the server URL.
- `AccountManager` (`ViewModels/AccountManager.swift`) — `ObservableObject` that
  owns the account set, the active-account pointer, and their persistence
  (`load` / `persist`), plus `upsert` / `setLabel` / `setActive` / `remove`.

## Service layer

| Service | Role |
| --- | --- |
| `APIService` (`actor`) | Bitwarden / Vaultwarden REST client |
| `CryptoService` | `EncType`, `EncString`, `SymmetricCryptoKey` — encrypted-string parsing and symmetric crypto primitives (source of truth for KDF / AES) |
| `KeychainService` | Low-level Keychain store, per-account scoped store, biometric helpers, shared vault key |
| `VaultCache` | Encrypted on-disk cache of the last successful sync |
| `VaultDecryptor` | Produces a `DecryptedVault` off the main thread |
| `VaultBackend` (protocol) + `KeePassBackend` | Abstraction so Bitwarden and KeePass vaults present one interface |
| `VaultMigrator` | Pure transform: decrypted Bitwarden vault → KeePass document (no I/O) |
| `TOTPService` | TOTP / HOTP with `otpauth://` and `steam://` support |
| `NetworkDelegate` | `CertTrustStore` (trust-on-first-use pin policy) + `PinnedCertDelegate` (URLSession delegate) |
| `CredentialIdentityStoreManager` | Mirrors logins into the system credential-identity store for the QuickType bar |
| `PasskeyStore` | Local per-account passkey storage in the shared Keychain group (JSON array of `Fido2.Credential`) |
| `Fido2` | WebAuthn / FIDO2 crypto core (P-256 / ES256, CBOR/COSE byte construction); independent of AutoFill wiring |
| `SecureData` | `SecureBytes` / `SecureString` — zero-on-dealloc wrappers for secret material |
| `LocalizationManager` | `AppLanguage`, the `L10n` key namespace, runtime language switching |
| `Logger` | `Log` logging facade |
| `SendModels` | Codable request/response models for Send |

## Vault backends

The app supports two kinds of vault behind the `VaultBackend` protocol:

- **Bitwarden / Vaultwarden** — `APIService` fetches sync data, `VaultCache`
  seals it on disk, and `VaultDecryptor` turns it into a `DecryptedVault` that
  `AppState` publishes.
- **KeePass** — `KeePassBackend` plus the `Services/KeePass/` subsystem operates
  on a local `.kdbx` file. `AppState+KeePass.swift` drives open / unlock / save.

### KeePass subsystem (`Services/KeePass/`)

| File | Role |
| --- | --- |
| `KDBXReader.swift` | Parse a `.kdbx` database (`KDBXDatabase`) |
| `KDBXVaultMapper.swift` | Map a parsed KDBX into the app's vault model |
| `KDBXWriter.swift` | `KDBXEditor` / `KDBXWriter` — build and encrypt a `.kdbx` |
| `KeePassKDF.swift` | KeePass key-derivation |
| `KeePassStreamCiphers.swift` | Inner stream ciphers (`ChaCha20Cipher`, `Salsa20Cipher`) |

## AutoFill extension

`VaultGuard/AutoFillProvider/` is a separate process:

- `CredentialProviderViewController` (`ASCredentialProviderViewController`) — the
  password AutoFill flow (`prepareCredentialList`, `provideCredentialWithoutUserInteraction`, etc.).
- `CredentialProviderViewController+Passkey.swift` — passkey registration and
  assertion (macOS 14+), kept as an extension so the password flow stays untouched.
- `AutoFillVault.swift` — loads and unlocks the vault for the extension, reading
  the shared vault key (and handling the KeePass path).

The extension is gated by the shared vault key the app publishes while unlocked;
see [security-model.md](security-model.md) for the trust and lifetime rules.

## Models

`Models/Models.swift` holds the domain types: `VaultCipher` and its sub-types
(`CipherLogin`, `CipherCard`, `CipherIdentity`, `CipherSecureNote`,
`CipherAttachment`, `CipherField`, `CipherUri`), `VaultFolder` /
`VaultCollection` / `VaultOrganization`, and the server response shapes
(`PreloginResponse`, `TokenResponse`, `SyncResponse`, and friends).

---

### Notes for maintainers

- Provenance: every component above was taken from the corresponding source
  file's declarations and doc comments — type kinds, method names, and the stated
  responsibilities are as written in the code.
- **Not covered by this document:** `App/VaultGuardApp.swift` (the `@main`
  entry point) and `Shared/SharedConfig.swift` were not part of the reviewed
  source set, so they are intentionally omitted rather than described from
  assumption. `CryptoService` internals (KDF parameters, AES-GCM specifics) are
  named here but not detailed — treat `CryptoService.swift` as authoritative.
