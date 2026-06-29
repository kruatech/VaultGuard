import Foundation

extension AppState {

    /// Create a text Send and return its shareable URL (`{base}/#/send/{accessId}/{key}`).
    /// `deletionDays` sets when the server auto-deletes it. Talks to the live server.
    @discardableResult
    func createTextSend(name: String, text: String, hidden: Bool, deletionSeconds: TimeInterval,
                        notes: String? = nil, maxAccessCount: Int? = nil, hideEmail: Bool = false,
                        sendPassword: String? = nil) async -> String? {
        isLoading = true
        defer { isLoading = false }
        do {
            let material = try crypto.makeSendKeyMaterial()
            let encName = try crypto.encryptSendString(name.isEmpty ? "Send" : name, key: material.cryptoKey)
            let encText = try crypto.encryptSendString(text, key: material.cryptoKey)
            var encNotes: String? = nil
            if let n = notes, !n.isEmpty { encNotes = try crypto.encryptSendString(n, key: material.cryptoKey) }
            let deletion = ISO8601DateFormatter().string(
                from: Date().addingTimeInterval(max(deletionSeconds, 3600)))

            let req = SendRequest(
                type: 0, name: encName, notes: encNotes, key: material.encryptedKey,
                maxAccessCount: maxAccessCount, expirationDate: nil, deletionDate: deletion,
                password: (sendPassword?.isEmpty == false) ? sendPassword : nil,
                disabled: false, hideEmail: hideEmail,
                text: SendTextRequest(text: encText, hidden: hidden))

            let response = try await api.createSend(req)
            guard let accessId = response.accessId else { showToast(.error(L10n.error.localized)); return nil }
            let base = await api.sendShareBaseURL()
            let url = "\(base)/#/send/\(accessId)/\(material.fragment)"
            await loadSends()
            showToast(.info(L10n.Send.created.localized))
            return url
        } catch {
            showToast(.error(error.localizedDescription))
            return nil
        }
    }

    /// Fetch and decrypt the active Sends for display (name + reconstructed share link).
    func loadSends() async {
        do {
            let raw = try await api.getSends()
            let base = await api.sendShareBaseURL()
            var out: [SendSummary] = []
            for s in raw {
                guard let id = s.id, let accessId = s.accessId else { continue }
                var name = ""
                var shareURL = ""
                var text: String?
                var notes: String?
                if let keyEnc = s.key, let sendKey = crypto.decryptToData(keyEnc) {
                    let cryptoKey = crypto.sendCryptoKey(fromSendKey: sendKey)
                    name = crypto.decrypt(s.name, with: cryptoKey) ?? ""
                    if let encText = s.text?.text { text = crypto.decrypt(encText, with: cryptoKey) }
                    if let encNotes = s.notes { notes = crypto.decrypt(encNotes, with: cryptoKey) }
                    let fragment = sendKey.base64EncodedString()
                        .replacingOccurrences(of: "+", with: "-")
                        .replacingOccurrences(of: "/", with: "_")
                        .replacingOccurrences(of: "=", with: "")
                    shareURL = "\(base)/#/send/\(accessId)/\(fragment)"
                }
                out.append(SendSummary(
                    id: id, accessId: accessId,
                    name: name.isEmpty ? accessId : name,
                    shareURL: shareURL, deletionDate: s.deletionDate,
                    accessCount: s.accessCount ?? 0, maxAccessCount: s.maxAccessCount,
                    disabled: s.disabled ?? false,
                    type: s.type ?? 0, encryptedKey: s.key ?? "",
                    hideEmail: s.hideEmail ?? false, text: text, hidden: s.text?.hidden ?? false,
                    notes: notes, sizeName: s.file?.sizeName, expirationDate: s.expirationDate))
            }
            sends = out
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    func deleteSend(_ summary: SendSummary) async {
        do {
            try await api.deleteSend(id: summary.id)
            sends.removeAll { $0.id == summary.id }
            showToast(.deleted())
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }

    /// Create a file Send (two-step: create metadata, then upload the encrypted bytes). The file
    /// is encrypted with the Send crypto key (EncArrayBuffer). Returns the share URL.
    @discardableResult
    func createFileSend(name: String, fileURL: URL, deletionSeconds: TimeInterval,
                        notes: String? = nil, maxAccessCount: Int? = nil, hideEmail: Bool = false,
                        sendPassword: String? = nil) async -> String? {
        isLoading = true
        defer { isLoading = false }
        let access = fileURL.startAccessingSecurityScopedResource()
        defer { if access { fileURL.stopAccessingSecurityScopedResource() } }
        do {
            let fileData = try Data(contentsOf: fileURL)
            let fileName = fileURL.lastPathComponent
            let material = try crypto.makeSendKeyMaterial()
            let encName = try crypto.encryptSendString(name.isEmpty ? fileName : name, key: material.cryptoKey)
            let encFileName = try crypto.encryptSendString(fileName, key: material.cryptoKey)
            let encFile = try crypto.encryptBuffer(fileData, key: material.cryptoKey)
            var encNotes: String? = nil
            if let n = notes, !n.isEmpty { encNotes = try crypto.encryptSendString(n, key: material.cryptoKey) }
            let deletion = ISO8601DateFormatter().string(
                from: Date().addingTimeInterval(max(deletionSeconds, 3600)))

            let req = SendFileCreateRequest(
                type: 1, name: encName, notes: encNotes, key: material.encryptedKey,
                fileLength: encFile.count, file: SendFileMeta(fileName: encFileName),
                maxAccessCount: maxAccessCount, expirationDate: nil, deletionDate: deletion,
                password: (sendPassword?.isEmpty == false) ? sendPassword : nil,
                disabled: false, hideEmail: hideEmail)

            let created = try await api.createFileSend(req)
            guard let sendId = created.sendResponse.id,
                  let fileId = created.sendResponse.file?.id,
                  let accessId = created.sendResponse.accessId else {
                showToast(.error(L10n.error.localized)); return nil
            }
            try await api.uploadSendFile(sendId: sendId, fileId: fileId,
                                         encryptedFileName: encFileName, encryptedData: encFile)

            let base = await api.sendShareBaseURL()
            let url = "\(base)/#/send/\(accessId)/\(material.fragment)"
            await loadSends()
            showToast(.info(L10n.Send.created.localized))
            return url
        } catch {
            showToast(.error(error.localizedDescription))
            return nil
        }
    }

    // MARK: - Edit / disable

    /// Re-derive a Send's crypto key from its stored encrypted key, to re-encrypt fields on update.
    private func deriveSendKey(for summary: SendSummary) -> SymmetricCryptoKey? {
        guard let sendKey = crypto.decryptToData(summary.encryptedKey) else { return nil }
        return crypto.sendCryptoKey(fromSendKey: sendKey)
    }

    /// Enable/disable a Send without changing its content.
    func setSendDisabled(_ summary: SendSummary, disabled: Bool) async {
        await putSend(summary, name: summary.name, text: summary.text ?? "", hidden: summary.hidden,
                      notes: summary.notes, deletionDate: summary.deletionDate,
                      maxAccessCount: summary.maxAccessCount,
                      hideEmail: summary.hideEmail, disabled: disabled)
    }

    /// Edit a Send's fields. `deletionDays` resets the expiry window when non-nil; otherwise the
    /// existing deletion date is kept.
    func updateSend(_ summary: SendSummary, name: String, text: String, hidden: Bool, notes: String?,
                    deletionSeconds: TimeInterval?, maxAccessCount: Int?, hideEmail: Bool) async {
        let deletion = deletionSeconds.map {
            ISO8601DateFormatter().string(from: Date().addingTimeInterval(max($0, 3600)))
        }
        await putSend(summary, name: name, text: text, hidden: hidden, notes: notes,
                      deletionDate: deletion ?? summary.deletionDate, maxAccessCount: maxAccessCount,
                      hideEmail: hideEmail, disabled: summary.disabled)
    }

    private func putSend(_ summary: SendSummary, name: String, text: String, hidden: Bool, notes: String?,
                         deletionDate: String?, maxAccessCount: Int?, hideEmail: Bool, disabled: Bool) async {
        isLoading = true
        defer { isLoading = false }
        guard let cryptoKey = deriveSendKey(for: summary) else { showToast(.error(L10n.error.localized)); return }
        do {
            let encName = try crypto.encryptSendString(name.isEmpty ? "Send" : name, key: cryptoKey)
            var encNotes: String? = nil
            if let n = notes, !n.isEmpty { encNotes = try crypto.encryptSendString(n, key: cryptoKey) }
            // The server requires a deletion date within 31 days; reuse the existing one, or +7d.
            let deletion = deletionDate ?? ISO8601DateFormatter().string(from: Date().addingTimeInterval(7 * 86_400))
            let textReq: SendTextRequest? = summary.type == 0
                ? SendTextRequest(text: try crypto.encryptSendString(text, key: cryptoKey), hidden: hidden)
                : nil
            let req = SendRequest(
                type: summary.type, name: encName, notes: encNotes, key: summary.encryptedKey,
                maxAccessCount: maxAccessCount, expirationDate: nil, deletionDate: deletion,
                password: nil, disabled: disabled, hideEmail: hideEmail, text: textReq)
            _ = try await api.updateSend(id: summary.id, req)
            await loadSends()
            showToast(.info(L10n.Send.updated.localized))
        } catch {
            showToast(.error(error.localizedDescription))
        }
    }
}
