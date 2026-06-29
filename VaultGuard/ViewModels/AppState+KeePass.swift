import Foundation
import CryptoKit

extension AppState {
    /// Вид активного хранилища. Источник истины — `Account.kind`.
    /// Нет активного аккаунта → `.bitwarden` (поведение по умолчанию).
    var activeVaultKind: VaultKind {
        accounts.activeAccount?.kind ?? .bitwarden
    }

    /// Publish a decrypted KeePass vault to the UI and refresh the AutoFill cache.
    func publishKeePass(_ vault: DecryptedVault) {
        applyDecryptedVault(vault)
        publishKeePassAutoFill()
    }

    /// Write the current KeePass logins to the shared AutoFill cache, sealed with a fresh
    /// ephemeral key that is published only while the vault is unlocked (cleared on lock).
    /// On lock the cache file is also removed, so nothing readable remains at rest.
    func publishKeePassAutoFill() {
        guard activeVaultKind == .keepass else { return }
        publishAutoFill()
    }

    /// Publish the current decrypted vault to the AutoFill extension as a minimal credential
    /// list, sealed with a FRESH per-publish random secret. The secret is shared (with a TTL)
    /// via the keychain; the extension derives the AutoFill cache key from it, so it never sees
    /// the real vault/user key, and lock / logout / account removal / TTL expiry all revoke
    /// AutoFill access. Identical for server and KeePass vaults (both expose decrypted
    /// `ciphers` after `applyDecryptedVault`).
    func publishAutoFill() {
        guard let accountId = accounts.activeAccountId else { return }
        guard SharedConfig.isAppGroupAvailable else {
            showToast(.error(L10n.Account.appGroupUnavailable.localized)); return
        }
        let kind = (activeVaultKind == .keepass) ? "keepass" : "server"
        let active = ciphers.filter { $0.deletedDate == nil }
        let records: [AutoFillRecord] = active.compactMap { c in
            guard let login = c.login,
                  let user = login.username, !user.isEmpty,
                  let pass = login.password, !pass.isEmpty else { return nil }
            let uris = login.uris?.compactMap { $0.uri } ?? []
            return AutoFillRecord(id: c.id, name: c.name, user: user, password: pass, uris: uris)
        }
        // Fresh random secret per publish — never the real vault/user key.
        let secret = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        guard AutoFillCache.save(records, secret: secret, accountId: accountId, kind: kind) else {
            Log.fault("autofill cache publish failed"); return
        }
        keychain.saveVaultKind(kind, accountId: accountId)
        keychain.shareAutoFillSecret(secret, accountId: accountId)   // payload {k: secret, e: now + TTL}
        CredentialIdentityStoreManager.update(with: active)
    }

    // MARK: - Открытие локального KeePass-файла (.kdbx)

    /// Прочитать `.kdbx` под security-scoped доступом, расшифровать через `KeePassBackend`,
    /// зарегистрировать `.keepass`-аккаунт и опубликовать vault.
    ///
    /// Bookmark файла всегда кладётся в память (`keePassFileBookmark`) — он нужен для записи
    /// изменений на диск в этой сессии. Если `saveBiometric` и биометрия доступна — bookmark
    /// (+ keyfile) и SHA-256-компонент пароля (не сам пароль) сохраняются в Keychain для
    /// переоткрытия по Touch ID.
    func openKeePass(fileURL: URL, password: String, keyfileURL: URL?,
                     saveBiometric: Bool, rememberFile: Bool, label: String?) async {
        isLoading = true
        errorMessage = nil

        let access = fileURL.startAccessingSecurityScopedResource()
        defer { if access { fileURL.stopAccessingSecurityScopedResource() } }

        do {
            let data = try Data(contentsOf: fileURL)

            var keyfileData: Data?
            var keyfileBookmark: Data?
            if let keyfileURL {
                let kAccess = keyfileURL.startAccessingSecurityScopedResource()
                defer { if kAccess { keyfileURL.stopAccessingSecurityScopedResource() } }
                keyfileData = try? Data(contentsOf: keyfileURL)
                keyfileBookmark = try? keyfileURL.bookmarkData(
                    options: [.withSecurityScope], includingResourceValuesForKeys: nil, relativeTo: nil)
            }

            let backend = KeePassBackend(fileData: data, password: password, keyfile: keyfileData)
            let vault = try await backend.load()

            let accountId = "keepass:" + fileURL.path
            let fileBase = fileURL.deletingPathExtension().lastPathComponent
            let name = vault.profileName.isEmpty ? fileBase : vault.profileName
            accounts.upsert(Account(id: accountId, serverURL: fileURL.path, email: "",
                                    profileName: name, label: label, kind: .keepass))
            accounts.setActive(accountId)
            reloadFolderOrderForActiveAccount()

            // Bookmark for writing back during this session (always).
            let fileBookmark = try? fileURL.bookmarkData(
                options: [.withSecurityScope], includingResourceValuesForKeys: nil, relativeTo: nil)
            keePassFileBookmark = fileBookmark

            // Persistence across launches:
            //  • "Touch ID"      → remember file + store the password under biometric
            //  • "Remember file" → store only the bookmark; password entered each time
            //  • "Ask each time" → store nothing (and clear anything left from a prior choice)
            let store = keychain.account(accountId)
            do {
                if (saveBiometric || rememberFile), let fileBookmark {
                    try store.setKpBookmark(fileBookmark.base64EncodedString())
                    try store.setKpKeyfileBookmark(keyfileBookmark?.base64EncodedString())
                } else {
                    try store.setKpBookmark(nil)
                    try store.setKpKeyfileBookmark(nil)
                }
                if saveBiometric, keychain.isBiometricAvailable {
                    // Store the SHA-256 password component of the KDBX composite key —
                    // sufficient to re-open the database on biometric unlock and
                    // irreversible back to the password. The raw master password is
                    // never persisted (see docs/security-model.md, "KeePass vaults").
                    let passwordKey = Data(SHA256.hash(data: Data(password.utf8)))
                    try store.saveBiometricUnlock(userKey: passwordKey,
                                                  passwordHash: Self.keePassBiometricSecretV1)
                } else {
                    try store.clearBiometricUnlock()   // no stale secret from a prior Touch ID choice
                }
            } catch {
                Log.fault("keepass session persist failed")
            }

            keePassBackend = backend
            publishKeePass(vault)
            isUnlocked = true
            startAutoLockTimer(); setupSleepObservers()
        } catch {
            errorMessage = error.localizedDescription
        }

        isLoading = false
    }

    /// Create a brand-new, empty `.kdbx` at `fileURL`, then open it through the normal path
    /// (account, write-back bookmark, AutoFill publish, unlock). The file is remembered for the
    /// session; the user picks Touch ID / persistence later via the normal open flow if desired.
    func createKeePassDatabase(at fileURL: URL, password: String, label: String?) async {
        isLoading = true
        errorMessage = nil
        do {
            let name = fileURL.deletingPathExtension().lastPathComponent
            let doc = try KDBXWriter.emptyDatabase(name: name)
            let data = try KDBXWriter.build(plaintextXML: doc, password: password, keyfile: nil, profile: .default)

            let access = fileURL.startAccessingSecurityScopedResource()
            defer { if access { fileURL.stopAccessingSecurityScopedResource() } }
            try data.write(to: fileURL, options: .atomic)
        } catch {
            errorMessage = error.localizedDescription
            isLoading = false
            return
        }
        // Hand off to the standard open path (which manages isLoading from here).
        await openKeePass(fileURL: fileURL, password: password, keyfileURL: nil,
                          saveBiometric: false, rememberFile: true, label: label)
    }

    /// Переоткрыть активный KeePass-аккаунт по биометрии: достать SHA-256-компонент пароля
    /// из биометрического секрета, разрешить bookmark файла/keyfile, перечитать и
    /// расшифровать. Легаси-секреты (сырой пароль, до v1) мигрируются на хэш при первом
    /// успешном анлоке.
    func unlockKeePassWithBiometric() async {
        isLoading = true
        errorMessage = nil
        do {
            guard let store = activeStore,
                  let bmB64 = store.kpBookmark, let bmData = Data(base64Encoded: bmB64) else {
                throw AuthError.noSavedSession
            }
            guard let unlock = try await store.getBiometricUnlock() else { throw AuthError.biometricFailed }
            // v1 secrets hold SHA256(password); legacy secrets (empty marker) held the raw
            // password — derive the hash from it now, and after a successful unlock below
            // re-store the hashed form so the raw password leaves the Keychain.
            let isLegacySecret = unlock.passwordHash != Self.keePassBiometricSecretV1
            let passwordKey = isLegacySecret ? Data(SHA256.hash(data: unlock.userKey)) : unlock.userKey

            // A stored security-scoped bookmark can be invalidated by the OS — most often after
            // the app is updated or re-signed (e.g. enabling the AutoFill capability). When that
            // happens, resolving fails or scoped access is denied. Don't surface the raw system
            // error ("file isn't in the correct format"); drop the dead bookmark and ask the user
            // to reopen the file via master password, which recreates a fresh bookmark.
            func failExpiredBookmark() {
                try? store.setKpBookmark(nil)
                try? store.setKpKeyfileBookmark(nil)
                keePassFileBookmark = nil
                errorMessage = L10n.Auth.bookmarkExpired.localized
                isLoading = false
            }
            var stale = false
            let resolved = try? URL(resolvingBookmarkData: bmData, options: [.withSecurityScope],
                                    relativeTo: nil, bookmarkDataIsStale: &stale)
            guard let url = resolved else { failExpiredBookmark(); return }
            let access = url.startAccessingSecurityScopedResource()
            defer { if access { url.stopAccessingSecurityScopedResource() } }
            guard access, let data = try? Data(contentsOf: url) else { failExpiredBookmark(); return }

            var keyfileData: Data?
            if let kfB64 = store.kpKeyfileBookmark, let kfBM = Data(base64Encoded: kfB64) {
                var kfStale = false
                if let kfURL = try? URL(resolvingBookmarkData: kfBM, options: [.withSecurityScope],
                                        relativeTo: nil, bookmarkDataIsStale: &kfStale) {
                    let kAccess = kfURL.startAccessingSecurityScopedResource()
                    defer { if kAccess { kfURL.stopAccessingSecurityScopedResource() } }
                    keyfileData = try? Data(contentsOf: kfURL)
                }
            }

            let backend = KeePassBackend(fileData: data, passwordSHA256: passwordKey, keyfile: keyfileData)
            let vault = try await backend.load()
            if isLegacySecret {
                // Unlock succeeded — replace the legacy raw-password secret with the hashed
                // component (best-effort; a failure just retries the migration next time).
                do { try store.saveBiometricUnlock(userKey: passwordKey,
                                                   passwordHash: Self.keePassBiometricSecretV1) }
                catch { Log.fault("keepass biometric secret migration failed") }
            }
            reloadFolderOrderForActiveAccount()
            keePassBackend = backend
            keePassFileBookmark = bmData          // enable write-back this session
            publishKeePass(vault)
            isUnlocked = true
            startAutoLockTimer(); setupSleepObservers()
        } catch {
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }

    // MARK: - Запись изменений KeePass

    /// Создать/обновить запись в KeePass-бэкенде, записать файл на диск и переопубликовать.
    func saveKeePassCipher(_ cipher: VaultCipher, isNew: Bool) async {
        guard let backend = keePassBackend else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            var newSelection: String?
            if isNew {
                let stored = try backend.addCipher(cipher)
                newSelection = stored.id
            } else {
                try backend.updateCipher(cipher)
            }
            try writeKeePassToDisk(backend)
            publishKeePass(try await backend.load())
            if let newSelection { selectedCipherId = newSelection }
            showToast(.saved())
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Удалить запись из KeePass-бэкенда, записать файл и переопубликовать.
    func deleteKeePassCipher(_ cipher: VaultCipher) async {
        guard let backend = keePassBackend else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            try backend.deleteCipher(id: cipher.id)
            try writeKeePassToDisk(backend)
            publishKeePass(try await backend.load())
            if selectedCipherId == cipher.id { selectedCipherId = nil }
            showToast(.deleted())
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Восстановить запись из корзины (в корень) и переопубликовать.
    func restoreKeePassCipher(_ cipher: VaultCipher) async {
        guard let backend = keePassBackend else { return }
        do {
            try backend.restoreCipher(id: cipher.id)
            try writeKeePassToDisk(backend)
            publishKeePass(try await backend.load())
            showToast(.info(L10n.Detail.restored.localized))
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Удалить запись окончательно (минуя корзину) и переопубликовать.
    func permanentlyDeleteKeePassCipher(_ cipher: VaultCipher) async {
        guard let backend = keePassBackend else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            try backend.permanentlyDeleteCipher(id: cipher.id)
            try writeKeePassToDisk(backend)
            publishKeePass(try await backend.load())
            if selectedCipherId == cipher.id { selectedCipherId = nil }
            showToast(.deleted())
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    // MARK: - Папки KeePass (группы)

    func createKeePassFolder(name: String) async {
        guard let backend = keePassBackend else { return }
        do {
            _ = try backend.addFolder(name: name)
            try writeKeePassToDisk(backend)
            publishKeePass(try await backend.load())
            showToast(.info(L10n.Folder.created.localized))
        } catch { showToast(.error(error.localizedDescription)) }
    }

    func renameKeePassFolder(id: String, newName: String) async {
        guard let backend = keePassBackend else { return }
        do {
            try backend.renameFolder(id: id, newName: newName)
            try writeKeePassToDisk(backend)
            publishKeePass(try await backend.load())
            showToast(.info(L10n.Folder.renamed.localized))
        } catch { showToast(.error(error.localizedDescription)) }
    }

    func deleteKeePassFolder(id: String) async {
        guard let backend = keePassBackend else { return }
        do {
            try backend.deleteFolder(id: id)
            try writeKeePassToDisk(backend)
            publishKeePass(try await backend.load())
            if case .folder(let fid) = filter, fid == id { filter = .all }
            showToast(.info(L10n.Folder.deleted.localized))
        } catch { showToast(.error(error.localizedDescription)) }
    }

    func moveKeePassCipher(cipherId: String, folderId: String?) async {
        guard let backend = keePassBackend else { return }
        do {
            try backend.moveCipher(id: cipherId, toFolderId: folderId)
            try writeKeePassToDisk(backend)
            publishKeePass(try await backend.load())
            showToast(.info(L10n.moved.localized))
        } catch { showToast(.error(error.localizedDescription)) }
    }

    /// Destructive-save guard: if the database contains data the writer can't preserve yet
    /// (binary attachments), return a user-facing message and refuse the save. nil = safe.
    private func keePassSaveBlockMessage(_ backend: KeePassBackend) throws -> String? {
        let lossy = try backend.lossyFeaturesOnSave()
        guard !lossy.isEmpty else { return nil }
        let attachments = lossy.first { $0.hasPrefix("attachments:") }
            .flatMap { Int($0.split(separator: ":").last.map(String.init) ?? "") } ?? 0
        return L10n.keePassSaveBlockedAttachments.localized(attachments)
    }

    /// Сериализовать состояние бэкенда и записать в исходный `.kdbx` под security-scoped
    /// bookmark. Перед записью — снимок текущего файла (для отката) и durable-бэкап в контейнер
    /// приложения. После записи — перечитать файл с диска и проверить `verifyRoundTrip`; при
    /// любой ошибке откатить на прежние байты. Запись неатомарная: sandbox даёт доступ к
    /// конкретному файлу, но не к его директории (создать sibling temp/.bak рядом нельзя).
    func writeKeePassToDisk(_ backend: KeePassBackend) throws {
        guard let bm = keePassFileBookmark else { throw VaultBackendError.fileUnavailable }
        let newData = try backend.serialize()
        var stale = false
        let url = try URL(resolvingBookmarkData: bm, options: [.withSecurityScope],
                          relativeTo: nil, bookmarkDataIsStale: &stale)
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }

        let oldData = try? Data(contentsOf: url)
        if let oldData { backupToContainer(oldData, sourceURL: url) }   // best-effort durability

        do {
            try newData.write(to: url)
            let written = try Data(contentsOf: url)        // verify what actually landed on disk
            try backend.verifyRoundTrip(written)
        } catch {
            if let oldData { try? oldData.write(to: url) } // roll back to last known-good
            throw VaultBackendError.verifyFailed
        }
    }

    /// Sandbox-safe pre-save backup into the app container (we can't write next to the user's
    /// file). Timestamped; keeps the most recent few copies.
    private func backupToContainer(_ data: Data, sourceURL: URL) {
        let fm = FileManager.default
        guard let support = try? fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                        appropriateFor: nil, create: true) else { return }
        let dir = support.appendingPathComponent("KeePassBackups", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let stamp = Self.keePassBackupStamp.string(from: Date())
        let base = sourceURL.deletingPathExtension().lastPathComponent
        try? data.write(to: dir.appendingPathComponent("\(base)_\(stamp).kdbx.bak"))
        if let items = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) {
            let baks = items.filter { $0.lastPathComponent.hasSuffix(".kdbx.bak") }
                            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            if baks.count > 10 { for u in baks.prefix(baks.count - 10) { try? fm.removeItem(at: u) } }
        }
    }

    /// `passwordHash` marker distinguishing biometric secrets that hold the SHA-256
    /// password component (v1) from legacy secrets that held the raw password ("" marker).
    /// Legacy secrets are migrated in `unlockKeePassWithBiometric`.
    static let keePassBiometricSecretV1 = "kdbx-pw-sha256.v1"

    private static let keePassBackupStamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd_HHmmss"
        f.locale = Locale(identifier: "en_US_POSIX")
        return f
    }()
}
