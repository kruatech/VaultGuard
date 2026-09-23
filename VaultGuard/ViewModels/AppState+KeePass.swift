import Foundation
import CryptoKit

extension AppState {
    /// Kind of the active vault. `Account.kind` is the source of truth.
    /// No active account → `.bitwarden` (the default behaviour).
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
        // `reprompt == 1` means "ask for the master password before revealing this item".
        // The extension cannot honour that: it holds no vault key, no KDF parameters and no
        // password hash, so it has nothing to verify a master password against. Publishing
        // such an item would hand out its password with no check at all — strictly weaker than
        // what the item asks for. It is therefore withheld from AutoFill entirely: both from
        // the sealed cache and from the QuickType identity store, so the system never offers a
        // suggestion the extension would have to refuse.
        let fillable = ciphers.filter { $0.deletedDate == nil && ($0.reprompt ?? 0) == 0 }
        let records: [AutoFillRecord] = fillable.compactMap { c in
            guard let login = c.login,
                  let user = login.username, !user.isEmpty,
                  let pass = login.password, !pass.isEmpty else { return nil }
            // Bitwarden UriMatchType: Domain 0, Host 1, StartsWith 2, Exact 3,
            // RegularExpression 4, Never 5. "Never" is the user saying this URI must never be
            // used to auto-fill, so it is dropped before the record leaves the app. An entry
            // whose only URI is "never" still ships (it stays pickable by hand in the
            // extension's list) but now matches no request host.
            let uriMatchNever = 5
            let uris: [String] = login.uris?.compactMap { u -> String? in
                guard u.match != uriMatchNever else { return nil }
                return u.uri
            } ?? []
            return AutoFillRecord(id: c.id, name: c.name, user: user, password: pass,
                                  uris: uris, revisionDate: c.revisionDate)
        }
        // Fresh random secret per publish — never the real vault/user key.
        let secret = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        guard AutoFillCache.save(records, secret: secret, accountId: accountId, kind: kind) else {
            Log.fault("autofill cache publish failed"); return
        }
        keychain.saveVaultKind(kind, accountId: accountId)
        keychain.shareAutoFillSecret(secret, accountId: accountId)   // payload {k: secret, e: now + TTL}
        CredentialIdentityStoreManager.update(with: fillable)
    }

    // MARK: - Opening a local KeePass file (.kdbx)

    /// Read the `.kdbx` under security-scoped access, decrypt it through `KeePassBackend`,
    /// register a `.keepass` account and publish the vault.
    ///
    /// The file's bookmark always goes into memory (`keePassFileBookmark`) — it is what lets
    /// changes be written back during this session. When `saveBiometric` is set and biometrics
    /// are available, the bookmark (plus the key file) and the SHA-256 component of the
    /// password — never the password itself — are stored in the Keychain so the file can be
    /// reopened with Touch ID.
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
            let vault = try await Self.loadFreshBackend(backend)

            let accountId = "keepass:" + fileURL.path
            let fileBase = fileURL.deletingPathExtension().lastPathComponent
            let name = vault.profileName.isEmpty ? fileBase : vault.profileName
            accounts.upsert(Account(id: accountId, serverURL: fileURL.path, email: "",
                                    profileName: name, label: label, kind: .keepass))
            accounts.setActive(accountId)
            reloadFolderOrderForActiveAccount()
            Log.audit("vault unlocked: keepass file")

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

    /// Reopen the active KeePass account with biometrics: take the SHA-256 password component
    /// out of the biometric secret, resolve the file and key-file bookmarks, then re-read and
    /// decrypt. Legacy secrets (a raw password, pre-v1) are migrated to the hash on the first
    /// successful unlock.
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
            let vault = try await Self.loadFreshBackend(backend)
            if isLegacySecret {
                // Unlock succeeded — replace the legacy raw-password secret with the hashed
                // component (best-effort; a failure just retries the migration next time).
                do { try store.saveBiometricUnlock(userKey: passwordKey,
                                                   passwordHash: Self.keePassBiometricSecretV1) }
                catch { Log.fault("keepass biometric secret migration failed") }
            }
            reloadFolderOrderForActiveAccount()
            Log.audit("vault unlocked: keepass file")
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

    // MARK: - Writing KeePass changes

    /// Create or update an entry in the KeePass backend, write the file to disk and republish.
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
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
            if let newSelection { selectedCipherId = newSelection }
            showToast(.saved())
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Delete an entry from the KeePass backend, write the file and republish.
    func deleteKeePassCipher(_ cipher: VaultCipher) async {
        guard let backend = keePassBackend else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            try backend.deleteCipher(id: cipher.id)
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
            if selectedCipherId == cipher.id { selectedCipherId = nil }
            showToast(.deleted())
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Restore an entry from the Recycle Bin (into the root group) and republish.
    func restoreKeePassCipher(_ cipher: VaultCipher) async {
        guard let backend = keePassBackend else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            try backend.restoreCipher(id: cipher.id)
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
            showToast(.info(L10n.Detail.restored.localized))
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Delete an entry permanently, bypassing the Recycle Bin, and republish.
    func permanentlyDeleteKeePassCipher(_ cipher: VaultCipher) async {
        guard let backend = keePassBackend else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            try backend.permanentlyDeleteCipher(id: cipher.id)
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
            if selectedCipherId == cipher.id { selectedCipherId = nil }
            showToast(.deleted())
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    // MARK: - KeePass folders (groups)

    func createKeePassFolder(name: String) async {
        guard let backend = keePassBackend else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            _ = try backend.addFolder(name: name)
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
            showToast(.info(L10n.Folder.created.localized))
        } catch { showToast(.error(error.localizedDescription)) }
    }

    func renameKeePassFolder(id: String, newName: String) async {
        guard let backend = keePassBackend else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            try backend.renameFolder(id: id, newName: newName)
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
            showToast(.info(L10n.Folder.renamed.localized))
        } catch { showToast(.error(error.localizedDescription)) }
    }

    func deleteKeePassFolder(id: String) async {
        guard let backend = keePassBackend else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            try backend.deleteFolder(id: id)
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
            if case .folder(let fid) = filter, fid == id { filter = .all }
            showToast(.info(L10n.Folder.deleted.localized))
        } catch { showToast(.error(error.localizedDescription)) }
    }

    func moveKeePassCipher(cipherId: String, folderId: String?) async {
        guard let backend = keePassBackend else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            try backend.moveCipher(id: cipherId, toFolderId: folderId)
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
            showToast(.info(L10n.moved.localized))
        } catch { showToast(.error(error.localizedDescription)) }
    }

    /// Refusal to overwrite the `.kdbx` with a serialization that would drop data. Carries the
    /// already-localized message so every caller's existing `catch` surfaces it unchanged.
    struct KeePassLossySaveError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    // MARK: - Bulk actions (one file write for the whole run)

    /// Delete several entries with a single write.
    ///
    /// The per-item path writes the `.kdbx` and re-reads it after every change, so deleting
    /// fifty entries one by one meant fifty full serialize-write-verify cycles over the whole
    /// database. The DOM edits are cheap; the file write is not. Batch the edits, write once.
    func bulkDeleteKeePassCiphers(_ ciphersToDelete: [VaultCipher]) async {
        guard let backend = keePassBackend, !ciphersToDelete.isEmpty else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            for cipher in ciphersToDelete { try backend.deleteCipher(id: cipher.id) }
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
            selectedCipherIds.subtract(ciphersToDelete.map { $0.id })
            showToast(.deleted())
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Restore several entries out of the Recycle Bin with a single write.
    func bulkRestoreKeePassCiphers(_ ciphersToRestore: [VaultCipher]) async {
        guard let backend = keePassBackend, !ciphersToRestore.isEmpty else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            for cipher in ciphersToRestore { try backend.restoreCipher(id: cipher.id) }
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
            showToast(.info(L10n.Detail.restored.localized))
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Permanently remove several entries with a single write. Bypasses the Recycle Bin — the
    /// entries are already in it.
    func bulkPurgeKeePassCiphers(_ ciphersToPurge: [VaultCipher]) async {
        guard let backend = keePassBackend, !ciphersToPurge.isEmpty else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            for cipher in ciphersToPurge { try backend.permanentlyDeleteCipher(id: cipher.id) }
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
            selectedCipherIds.subtract(ciphersToPurge.map { $0.id })
            showToast(.deleted())
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Move several entries into one group with a single write. Same reasoning as above.
    func bulkMoveKeePassCiphers(_ ciphersToMove: [VaultCipher], folderId: String?) async {
        guard let backend = keePassBackend, !ciphersToMove.isEmpty else { return }
        do {
            if let blocked = try keePassSaveBlockMessage(backend) { showToast(.error(blocked)); return }
            for cipher in ciphersToMove { try backend.moveCipher(id: cipher.id, toFolderId: folderId) }
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
            showToast(.info(L10n.moved.localized))
        } catch {
            showToast(.error(error.localizedDescription))
        }
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

    /// Serialize the backend's state and write it into the original `.kdbx` under the
    /// security-scoped bookmark. Before writing: snapshot the current file (for rollback) and
    /// take a durable backup into the app container. After writing: re-read the file from disk
    /// and check `verifyRoundTrip`; on any failure, roll back to the previous bytes. The write
    /// is not atomic — the sandbox grants access to the file itself but not to its directory,
    /// so a sibling temp/.bak cannot be created next to it.
    /// First load of a freshly opened file, which runs the file's KDF.
    ///
    /// This used to be a plain `try backend.currentVault()`, and it only left the main thread
    /// because of how Swift 5.9 schedules a nonisolated async function. That is a language
    /// default, not a decision in this code: under a later Swift mode a nonisolated async
    /// function inherits its caller's actor, and opening a vault would start freezing the window
    /// with no warning and no failing test. `Task.detached` states the intent outright.
    ///
    /// Safe to move off the main thread because the backend is brand new — nothing else holds
    /// it until this returns.
    nonisolated static func loadFreshBackend(_ backend: KeePassBackend) async throws -> DecryptedVault {
        try await Task.detached(priority: .userInitiated) { try backend.currentVault() }.value
    }

    /// Save the backend to its `.kdbx`, off the main thread, one save at a time.
    ///
    /// A save runs the file's KDF twice — to encrypt, then to prove the written file opens —
    /// and both ran here on the main actor, so every edit, add, delete and move froze the
    /// window for two full derivations. With a real Argon2 profile that is seconds per action.
    ///
    /// Two things make moving it safe:
    ///
    /// * **A snapshot is taken before the first suspension.** The document is edited on the
    ///   main actor; serializing it in the background while another edit landed would be a
    ///   data race. The snapshot is a private copy.
    /// * **Saves are chained.** Two overlapping saves could finish out of order, and the older
    ///   snapshot landing last would overwrite the file with a state missing the newer edit.
    ///   Snapshots are taken in call order and written in the same order, so the last write is
    ///   always the newest state.
    func writeKeePassToDisk(_ backend: KeePassBackend) async throws {
        // Backstop for the destructive-save guard. Every caller checks it before touching the
        // document (so a refusal leaves the in-memory DOM clean), but this is the one funnel
        // all writes pass through: if a future mutation path forgets the check, the file is
        // still not overwritten with a version that drops data the writer cannot carry.
        if let blocked = try keePassSaveBlockMessage(backend) {
            throw KeePassLossySaveError(message: blocked)
        }
        guard let bm = keePassFileBookmark else { throw VaultBackendError.fileUnavailable }

        // Taken here, synchronously, before anything suspends — see above.
        let snapshot = try backend.makeSaveSnapshot()
        let previous = keePassSaveChain
        let save = Task { @MainActor in
            // A failed earlier save does not stop this one: it holds the newer state.
            _ = try? await previous?.value
            try await self.performKeePassWrite(snapshot, bookmark: bm, backend: backend)
        }
        keePassSaveChain = save
        try await save.value
    }

    private func performKeePassWrite(_ snapshot: KeePassBackend.SaveSnapshot, bookmark bm: Data,
                                     backend: KeePassBackend) async throws {
        let newData = try await Task.detached(priority: .userInitiated) {
            try KeePassBackend.build(snapshot)
        }.value
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
            try await Task.detached(priority: .userInitiated) {
                try KeePassBackend.verify(written, against: snapshot)
            }.value
        } catch {
            if let oldData { try? oldData.write(to: url) } // roll back to last known-good
            throw VaultBackendError.verifyFailed
        }

        // The writer implements only the KDBX 4 container, so saving a KDBX 3 file converts its
        // format. That used to happen silently: the user opened a 3.1 file, changed nothing of
        // consequence, and ended up with a file older KeePass builds refuse to open. Announce it
        // once per session. Refusing the save instead would make every KDBX 3 file read-only,
        // and writing a real v3 container would mean a second serializer.
        if backend.onDiskVersionMajor < 4, !keePassUpgradeNoticeShown {
            keePassUpgradeNoticeShown = true
            showToast(.info(L10n.keePassUpgradedToV4.localized))
        }
    }

    /// Directory holding the pre-save snapshots. Inside the app container, because the sandbox
    /// grants access to the user's file but not to the folder it sits in.
    static func keePassBackupDirectory() -> URL? {
        let fm = FileManager.default
        guard let support = try? fm.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                        appropriateFor: nil, create: true) else { return nil }
        return support.appendingPathComponent("KeePassBackups", isDirectory: true)
    }

    /// Existing snapshots, newest first across all vaults.
    ///
    /// Ordered by the timestamp in the name, not by the name: sorting whole file names groups
    /// by vault first, which is not a time order once there is more than one vault.
    func keePassBackups() -> [URL] {
        guard let dir = Self.keePassBackupDirectory(),
              let items = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
        else { return [] }
        return KeePassBackupPolicy.newestFirst(items).map(\.url)
    }

    /// Copy a snapshot out of the container to somewhere the user picks.
    ///
    /// Deliberately a copy-out rather than a restore-in-place. Writing a snapshot back over the
    /// live file would mean overwriting real data with bytes this app cannot first verify: the
    /// master password is not retained after unlock, so there is no way to confirm the snapshot
    /// even opens before it replaces the original. Handing the user the file instead lets them
    /// open it through the normal flow, password and all, and decide from there.
    /// Delete one pre-save snapshot.
    ///
    /// Needed because a snapshot keeps the credentials the file had when it was taken: after a
    /// master-password change, older snapshots still open with the old password, and until now
    /// nothing in the app could remove them.
    ///
    /// Refuses anything that is not a snapshot in the snapshot directory. The URL comes from the
    /// directory listing, but a function that deletes files should not rely on its caller for
    /// that — a path outside the directory, or a file that is not named like a snapshot, is left
    /// alone.
    func deleteKeePassBackup(_ backup: URL) {
        guard let dir = Self.keePassBackupDirectory(),
              backup.resolvingSymlinksInPath().deletingLastPathComponent().standardizedFileURL
                  == dir.resolvingSymlinksInPath().standardizedFileURL,
              KeePassBackupPolicy.parse(backup) != nil else {
            showToast(.error(L10n.Backup.deleteRefused.localized))
            return
        }
        do {
            try FileManager.default.removeItem(at: backup)
            Log.audit("keepass snapshot deleted")
            showToast(.deleted())
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    func exportKeePassBackup(_ backup: URL, to destination: URL) {
        do {
            let data = try Data(contentsOf: backup)
            try data.write(to: destination)
            showToast(.info(L10n.Backup.saved.localized))
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Write the currently open vault out as an unencrypted Bitwarden `.json` export.
    /// The caller is expected to have warned the user that the file is plaintext.
    func exportVaultAsBitwardenJSON(to destination: URL) {
        do {
            let data = try VaultMigrator.exportBitwardenJSON(ciphers: ciphers, folders: folders)
            try data.write(to: destination)
            Log.audit("vault exported as unencrypted JSON")
            showToast(.info(L10n.Migration.jsonExported.localized))
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Sandbox-safe pre-save backup into the app container (we can't write next to the user's
    /// file). Timestamped; keeps the most recent few copies.
    private func backupToContainer(_ data: Data, sourceURL: URL) {
        let fm = FileManager.default
        guard let dir = Self.keePassBackupDirectory() else { return }
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let stamp = Self.keePassBackupStamp.string(from: Date())
        let base = sourceURL.deletingPathExtension().lastPathComponent
        try? data.write(to: dir.appendingPathComponent("\(base)_\(stamp).kdbx.bak"))
        // Rotate per vault, oldest first. The previous rule sorted every snapshot by file name
        // and kept the last ten — which orders by vault name before time, so saving one vault
        // deleted the newest snapshots of any vault whose name sorted earlier.
        if let items = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) {
            for url in KeePassBackupPolicy.filesToPrune(items) { try? fm.removeItem(at: url) }
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
