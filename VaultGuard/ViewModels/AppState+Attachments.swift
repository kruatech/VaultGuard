import Foundation
import AppKit

extension AppState {
    // MARK: - Drag & Drop Attachments

    /// Upload files from dropped URLs (files and folders, recursive)
    func uploadDroppedFiles(urls: [URL], toCipher cipher: VaultCipher) async {
        if activeVaultKind == .keepass { await uploadKeePassFiles(urls: urls, toCipher: cipher); return }
        let allFiles = collectFiles(from: urls)
        guard !allFiles.isEmpty else { return }

        isUploadingAttachments = true
        attachmentUploadProgress = 0
        let total = Double(allFiles.count)

        for (index, fileURL) in allFiles.enumerated() {
            do {
                let data = try Data(contentsOf: fileURL)
                let fileName = fileURL.lastPathComponent
                let (encryptedData, encryptedKey) = try crypto.encryptAttachment(data, orgId: cipher.organizationId)
                let encFileName = crypto.encrypt(fileName, orgId: cipher.organizationId) ?? fileName

                try await api.uploadAttachment(
                    cipherId: cipher.id,
                    encryptedFileName: encFileName,
                    encryptedData: encryptedData,
                    encryptedKey: encryptedKey
                )
            } catch {
                showToast(.error("\(L10n.DragDrop.uploadFailed.localized): \(fileURL.lastPathComponent)"))
            }

            attachmentUploadProgress = Double(index + 1) / total
        }

        isUploadingAttachments = false
        attachmentUploadProgress = 0

        // Re-sync to get updated attachments
        do { try await syncVault() } catch {}
        showToast(.info(L10n.DragDrop.uploadComplete.localized))
    }

    /// Recursively collect all files from URLs (expanding folders)
    private func collectFiles(from urls: [URL]) -> [URL] {
        var result: [URL] = []
        let fm = FileManager.default
        for url in urls {
            var isDir: ObjCBool = false
            if fm.fileExists(atPath: url.path, isDirectory: &isDir) {
                if isDir.boolValue {
                    // Recursively enumerate folder
                    if let enumerator = fm.enumerator(at: url, includingPropertiesForKeys: [.isRegularFileKey], options: [.skipsHiddenFiles]) {
                        for case let fileURL as URL in enumerator {
                            if let vals = try? fileURL.resourceValues(forKeys: [.isRegularFileKey]), vals.isRegularFile == true {
                                result.append(fileURL)
                            }
                        }
                    }
                } else {
                    result.append(url)
                }
            }
        }
        return result
    }

    // MARK: - Attachments

    func downloadAttachment(cipher: VaultCipher, attachment: CipherAttachment) async {
        if activeVaultKind == .keepass { await downloadKeePassAttachment(cipher: cipher, attachment: attachment); return }
        guard let aid = attachment.id else { return }
        do {
            let (enc, _) = try await api.downloadAttachment(cipherId: cipher.id, attachmentId: aid)
            let dec = try crypto.decryptAttachmentData(enc, attachmentKeyString: attachment.key, orgId: cipher.organizationId)
            let panel = NSSavePanel(); panel.nameFieldStringValue = attachment.fileName ?? "file"; panel.canCreateDirectories = true
            let r = await panel.beginSheetModal(for: NSApp.keyWindow ?? NSApp.mainWindow ?? NSWindow())
            if r == .OK, let url = panel.url { try dec.write(to: url); showToast(.info(L10n.fileSaved.localized)) }
        } catch { showToast(.error(error.localizedDescription)) }
    }

    func deleteAttachment(cipher: VaultCipher, attachment: CipherAttachment) async {
        if activeVaultKind == .keepass { await deleteKeePassAttachment(cipher: cipher, attachment: attachment); return }
        guard let aid = attachment.id else { return }
        do {
            try await api.deleteAttachment(cipherId: cipher.id, attachmentId: aid)
            // Optimistically drop it from the local cipher, then resync to stay authoritative.
            if let i = ciphers.firstIndex(where: { $0.id == cipher.id }) {
                ciphers[i].attachments?.removeAll { $0.id == aid }
            }
            do { try await syncVault() } catch {}
            showToast(.deleted())
        } catch { showToast(.error(error.localizedDescription)) }
    }

    // Attachment previews are shown in-app only (AttachmentPreviewSheet keeps the decrypted
    // bytes in memory and never writes them to disk), so there is no temp file to open via
    // Launch Services and nothing to clean up on lock. This removes the previous
    // decrypted-file-on-disk surface and the preview-vs-auto-lock race entirely.

    func loadAttachmentData(cipher: VaultCipher, attachment: CipherAttachment) async -> Data? {
        if activeVaultKind == .keepass {
            guard let id = attachment.id, let ref = Int(id) else { return nil }
            return keePassBackend?.attachmentData(ref: ref)
        }
        guard let aid = attachment.id else { return nil }
        do {
            let (enc, _) = try await api.downloadAttachment(cipherId: cipher.id, attachmentId: aid)
            return try crypto.decryptAttachmentData(enc, attachmentKeyString: attachment.key, orgId: cipher.organizationId)
        } catch { showToast(.error(error.localizedDescription)); return nil }
    }

    static func isPreviewable(fileName: String?) -> Bool {
        guard let f = fileName?.lowercased() else { return false }
        if f.hasSuffix(".zip") { return true }
        return ["pdf","png","jpg","jpeg","gif","webp","bmp","tiff","tif","heic","heif","svg"].contains { f.hasSuffix(".\($0)") }
    }
    static func isImage(fileName: String?) -> Bool {
        guard let f = fileName?.lowercased() else { return false }
        return ["png","jpg","jpeg","gif","webp","bmp","tiff","tif","heic","heif"].contains { f.hasSuffix(".\($0)") }
    }
    static func isPDF(fileName: String?) -> Bool { fileName?.lowercased().hasSuffix(".pdf") ?? false }
    static func isZip(fileName: String?) -> Bool { fileName?.lowercased().hasSuffix(".zip") ?? false }
    // MARK: - KeePass attachments (local .kdbx binary pool)

    private func uploadKeePassFiles(urls: [URL], toCipher cipher: VaultCipher) async {
        guard let backend = keePassBackend else { return }
        let files = collectFiles(from: urls)
        guard !files.isEmpty else { return }
        isUploadingAttachments = true
        attachmentUploadProgress = 0
        let total = Double(files.count)
        do {
            for (index, fileURL) in files.enumerated() {
                let data = try Data(contentsOf: fileURL)
                _ = try backend.addAttachment(cipherId: cipher.id, fileName: fileURL.lastPathComponent, data: data)
                attachmentUploadProgress = Double(index + 1) / total
            }
            try writeKeePassToDisk(backend)
            publishKeePass(try await backend.load())
            showToast(.info(L10n.DragDrop.uploadComplete.localized))
        } catch {
            showToast(.error(error.localizedDescription))
        }
        isUploadingAttachments = false
        attachmentUploadProgress = 0
    }

    private func deleteKeePassAttachment(cipher: VaultCipher, attachment: CipherAttachment) async {
        guard let backend = keePassBackend, let id = attachment.id, let ref = Int(id) else { return }
        do {
            try backend.removeAttachment(cipherId: cipher.id, ref: ref)
            try writeKeePassToDisk(backend)
            publishKeePass(try await backend.load())
            showToast(.deleted())
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    private func downloadKeePassAttachment(cipher: VaultCipher, attachment: CipherAttachment) async {
        guard let backend = keePassBackend, let id = attachment.id, let ref = Int(id),
              let data = backend.attachmentData(ref: ref) else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = attachment.fileName ?? "file"
        panel.canCreateDirectories = true
        let r = await panel.beginSheetModal(for: NSApp.keyWindow ?? NSApp.mainWindow ?? NSWindow())
        if r == .OK, let url = panel.url {
            do { try data.write(to: url); showToast(.info(L10n.fileSaved.localized)) }
            catch { showToast(.error(error.localizedDescription)) }
        }
    }
}
