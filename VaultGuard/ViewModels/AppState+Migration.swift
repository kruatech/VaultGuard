import Foundation

extension AppState {

    /// Export the currently loaded Bitwarden/Vaultwarden vault to a new, password-protected
    /// `.kdbx` at `fileURL`. Attachments are downloaded and decrypted via the API first, then
    /// embedded. The mapping is lossy where KeePass has no equivalent (see `VaultMigrator`):
    /// card/identity become generic entries with labelled fields; favorite/reprompt are dropped.
    func exportActiveVaultToKDBX(at fileURL: URL, password: String) async {
        isLoading = true
        defer { isLoading = false }
        do {
            // Download + decrypt each attachment's bytes (keyed by attachment id).
            var attachmentBytes: [String: Data] = [:]
            for cipher in ciphers {
                for att in cipher.attachments ?? [] {
                    guard let id = att.id else { continue }
                    if let data = await loadAttachmentData(cipher: cipher, attachment: att) {
                        attachmentBytes[id] = data
                    }
                }
            }

            let base = fileURL.deletingPathExtension().lastPathComponent
            let dbName = !base.isEmpty ? base : (profileName.isEmpty ? "VaultGuard" : profileName)

            let (document, binaries) = VaultMigrator.exportToKDBX(
                databaseName: dbName,
                ciphers: ciphers,
                folders: folders,
                collections: collections,
                organizations: organizations,
                attachmentBytes: attachmentBytes)

            let data = try KDBXWriter.build(plaintextXML: document, password: password,
                                            keyfile: nil, profile: .default, binaries: binaries)

            let access = fileURL.startAccessingSecurityScopedResource()
            defer { if access { fileURL.stopAccessingSecurityScopedResource() } }
            try data.write(to: fileURL, options: .atomic)

            showToast(.info(L10n.Migration.exportComplete.localized))
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Import a `.kdbx` into the active Bitwarden/Vaultwarden vault (merge — entries are added,
    /// nothing is replaced). Each KeePass entry becomes a login; its group becomes a folder
    /// (created on demand); attachments are uploaded. Recycle-bin entries are skipped. This path
    /// talks to the live server and is not covered by offline tests.
    func importKDBXFile(fileURL: URL, password: String, keyfileURL: URL?) async {
        isLoading = true
        defer { isLoading = false }
        do {
            let access = fileURL.startAccessingSecurityScopedResource()
            defer { if access { fileURL.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: fileURL)

            var keyfileData: Data?
            if let keyfileURL {
                let kAccess = keyfileURL.startAccessingSecurityScopedResource()
                defer { if kAccess { keyfileURL.stopAccessingSecurityScopedResource() } }
                keyfileData = try? Data(contentsOf: keyfileURL)
            }

            let backend = KeePassBackend(fileData: data, password: password, keyfile: keyfileData)
            let vault = try await backend.load()
            let rawEntries = VaultMigrator.importFromKDBX(ciphers: vault.ciphers, folders: vault.folders)
            guard !rawEntries.isEmpty else { showToast(.info(L10n.Migration.importEmpty.localized)); return }
            let entries = VaultMigrator.dedupEntries(rawEntries, against: ciphers)
            let skipped = rawEntries.count - entries.count

            let noName = "misc.noName".localized
            let noOrgKey = "misc.noOrgKey".localized
            let undecryptable = "misc.undecryptable".localized
            var created = 0

            for entry in entries {
                // Resolve or create the destination folder by path.
                var folderId: String?
                if let path = entry.folderPath, !path.isEmpty {
                    if let existing = folders.first(where: { $0.name == path }) {
                        folderId = existing.id
                    } else {
                        await createFolder(name: path)
                        folderId = folders.first(where: { $0.name == path })?.id
                    }
                }

                var cipher = entry.cipher
                cipher.folderId = folderId
                let req = encryptCipherRequest(cipher)
                let response = try await api.createCipher(req)
                guard let decrypted = VaultDecryptor.decryptCipher(
                    response, crypto: crypto, noName: noName, noOrgKey: noOrgKey, undecryptable: undecryptable) else { continue }
                ciphers.append(decrypted)
                created += 1

                // Upload attachments: bytes come from the KeePass binary pool (att.id = ref).
                for att in entry.cipher.attachments ?? [] {
                    guard let idStr = att.id, let ref = Int(idStr),
                          let bytes = backend.attachmentData(ref: ref) else { continue }
                    let fileName = att.fileName ?? "attachment"
                    let (encData, encKey) = try crypto.encryptAttachment(bytes, orgId: decrypted.organizationId)
                    let encName = crypto.encrypt(fileName, orgId: decrypted.organizationId) ?? fileName
                    try await api.uploadAttachment(cipherId: decrypted.id, encryptedFileName: encName,
                                                   encryptedData: encData, encryptedKey: encKey)
                }
            }

            do { try await syncVault() } catch {}
            showToast(.info(skipped > 0
                ? String(format: L10n.Migration.importCompleteDedup.localized, created, skipped)
                : String(format: L10n.Migration.importComplete.localized, created)))
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }
    /// Import an unencrypted Bitwarden `.json` export. Merges into the current vault (no delete,
    /// no dedup); type/favorite/reprompt/fields are preserved. Attachments are not part of the
    /// unencrypted export, so none are uploaded.
    func importBitwardenJSONFile(fileURL: URL) async {
        isLoading = true
        defer { isLoading = false }
        do {
            let access = fileURL.startAccessingSecurityScopedResource()
            defer { if access { fileURL.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: fileURL)
            let rawEntries = try VaultMigrator.importBitwardenJSON(data: data)
            guard !rawEntries.isEmpty else { showToast(.info(L10n.Migration.importEmpty.localized)); return }
            let entries = VaultMigrator.dedupEntries(rawEntries, against: ciphers)
            let skipped = rawEntries.count - entries.count

            let noName = "misc.noName".localized
            let noOrgKey = "misc.noOrgKey".localized
            let undecryptable = "misc.undecryptable".localized
            var created = 0

            for entry in entries {
                var folderId: String?
                if let path = entry.folderPath, !path.isEmpty {
                    if let existing = folders.first(where: { $0.name == path }) {
                        folderId = existing.id
                    } else {
                        await createFolder(name: path)
                        folderId = folders.first(where: { $0.name == path })?.id
                    }
                }
                var cipher = entry.cipher
                cipher.folderId = folderId
                let req = encryptCipherRequest(cipher)
                let response = try await api.createCipher(req)
                guard let decrypted = VaultDecryptor.decryptCipher(
                    response, crypto: crypto, noName: noName, noOrgKey: noOrgKey, undecryptable: undecryptable) else { continue }
                ciphers.append(decrypted)
                created += 1
            }

            do { try await syncVault() } catch {}
            showToast(.info(skipped > 0
                ? String(format: L10n.Migration.importCompleteDedup.localized, created, skipped)
                : String(format: L10n.Migration.importComplete.localized, created)))
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Import a CSV export (LastPass / Bitwarden / generic). Merges into the current vault with
    /// dedup; attachments and organizations are not part of CSV exports.
    func importCSVFile(fileURL: URL) async {
        isLoading = true
        defer { isLoading = false }
        do {
            let access = fileURL.startAccessingSecurityScopedResource()
            defer { if access { fileURL.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: fileURL)
            let rawEntries = try VaultMigrator.importCSV(data: data)
            guard !rawEntries.isEmpty else { showToast(.info(L10n.Migration.importEmpty.localized)); return }
            let entries = VaultMigrator.dedupEntries(rawEntries, against: ciphers)
            let skipped = rawEntries.count - entries.count

            let noName = "misc.noName".localized
            let noOrgKey = "misc.noOrgKey".localized
            let undecryptable = "misc.undecryptable".localized
            var created = 0

            for entry in entries {
                var folderId: String?
                if let path = entry.folderPath, !path.isEmpty {
                    if let existing = folders.first(where: { $0.name == path }) {
                        folderId = existing.id
                    } else {
                        await createFolder(name: path)
                        folderId = folders.first(where: { $0.name == path })?.id
                    }
                }
                var cipher = entry.cipher
                cipher.folderId = folderId
                let req = encryptCipherRequest(cipher)
                let response = try await api.createCipher(req)
                guard let decrypted = VaultDecryptor.decryptCipher(
                    response, crypto: crypto, noName: noName, noOrgKey: noOrgKey, undecryptable: undecryptable) else { continue }
                ciphers.append(decrypted)
                created += 1
            }

            do { try await syncVault() } catch {}
            showToast(.info(skipped > 0
                ? String(format: L10n.Migration.importCompleteDedup.localized, created, skipped)
                : String(format: L10n.Migration.importComplete.localized, created)))
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }
}
