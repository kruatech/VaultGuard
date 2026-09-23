import Foundation
import AppKit

extension AppState {
    /// Largest file accepted as an attachment.
    ///
    /// Checked before the file is read, because everything after that holds it whole in
    /// memory: the plaintext, then the ciphertext beside it — two to three times the file at
    /// peak. On the KeePass side the cost recurs, since attachments live inside the `.kdbx`
    /// and every later save rewrites the entire database. A limit the server enforces is no
    /// help here; by the time it answers, the memory has already been spent.
    static let maxAttachmentBytes = 100 * 1024 * 1024

    /// The file's size without reading it, or nil if it cannot be determined.
    nonisolated static func attachmentSize(_ url: URL) -> Int? {
        (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize
    }

    /// Split files into the ones that fit and the names of those that do not.
    private func partitionBySize(_ files: [URL]) -> (fitting: [URL], tooLarge: [String]) {
        var fitting: [URL] = [], tooLarge: [String] = []
        for file in files {
            if let size = Self.attachmentSize(file), size > Self.maxAttachmentBytes {
                tooLarge.append(file.lastPathComponent)
            } else {
                fitting.append(file)
            }
        }
        return (fitting, tooLarge)
    }

    private func reportTooLarge(_ names: [String]) {
        guard !names.isEmpty else { return }
        let limitMB = Self.maxAttachmentBytes / (1024 * 1024)
        showToast(.error(L10n.DragDrop.tooLarge.localized(names.joined(separator: ", "), limitMB)))
    }

    // MARK: - Drag & Drop Attachments

    /// Upload files from dropped URLs (files and folders, recursive)
    func uploadDroppedFiles(urls: [URL], toCipher cipher: VaultCipher) async {
        if activeVaultKind == .keepass { await uploadKeePassFiles(urls: urls, toCipher: cipher); return }
        let (allFiles, tooLarge) = partitionBySize(collectFiles(from: urls))
        reportTooLarge(tooLarge)
        guard !allFiles.isEmpty else { return }

        isUploadingAttachments = true
        attachmentUploadProgress = 0
        let total = Double(allFiles.count)

        // Captured once: `lock()` replaces `crypto` rather than mutating it, so an upload
        // already running keeps the keys it started with instead of reading a wiped instance.
        let session = crypto
        let orgId = cipher.organizationId

        for (index, fileURL) in allFiles.enumerated() {
            do {
                let fileName = fileURL.lastPathComponent
                // Reading the file and encrypting all of it ran on the main actor, freezing the
                // window for as long as a large file took. The session is only read here, never
                // written, so running this off the main thread races with nothing.
                let (encryptedData, encryptedKey, encFileName) = try await Task.detached(priority: .userInitiated) {
                    let data = try Data(contentsOf: fileURL)
                    let (encData, encKey) = try session.encryptAttachment(data, orgId: orgId)
                    return (encData, encKey, session.encrypt(fileName, orgId: orgId) ?? fileName)
                }.value

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
        let (files, tooLarge) = partitionBySize(collectFiles(from: urls))
        reportTooLarge(tooLarge)
        guard !files.isEmpty else { return }
        isUploadingAttachments = true
        attachmentUploadProgress = 0
        let total = Double(files.count)
        do {
            for (index, fileURL) in files.enumerated() {
                // The read is the slow part and touches nothing shared; the DOM edit below stays
                // on the main actor with the rest of the backend's use.
                let data = try await Task.detached(priority: .userInitiated) {
                    try Data(contentsOf: fileURL)
                }.value
                _ = try backend.addAttachment(cipherId: cipher.id, fileName: fileURL.lastPathComponent, data: data)
                attachmentUploadProgress = Double(index + 1) / total
            }
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
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
            try await writeKeePassToDisk(backend)
            publishKeePass(try backend.currentVault())
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
