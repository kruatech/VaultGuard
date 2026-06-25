import Foundation

extension AppState {
    // MARK: - Folder CRUD

    func createFolder(name: String) async {
        guard let encrypted = crypto.encrypt(name) else { showToast(.error(L10n.encryptionError.localized)); return }
        do {
            let result = try await api.createFolder(name: encrypted)
            if let id = result.id {
                folders.append(VaultFolder(id: id, name: name, revisionDate: Date()))
                folderOrder.append(id)
                showToast(.info(L10n.Folder.created.localized))
            }
        } catch { showToast(.error("\(L10n.error.localized): \(error.localizedDescription)")) }
    }

    func renameFolder(id: String, newName: String) async {
        guard let encrypted = crypto.encrypt(newName) else { showToast(.error(L10n.encryptionError.localized)); return }
        do {
            _ = try await api.updateFolder(id: id, name: encrypted)
            if let idx = folders.firstIndex(where: { $0.id == id }) { folders[idx].name = newName }
            showToast(.info(L10n.Folder.renamed.localized))
        } catch { showToast(.error("\(L10n.error.localized): \(error.localizedDescription)")) }
    }

    func deleteFolder(id: String) async {
        do {
            try await api.deleteFolder(id: id)
            folders.removeAll { $0.id == id }
            folderOrder.removeAll { $0 == id }
            for i in ciphers.indices where ciphers[i].folderId == id { ciphers[i].folderId = nil }
            if case .folder(let fid) = filter, fid == id { filter = .all }
            showToast(.info(L10n.Folder.deleted.localized))
        } catch { showToast(.error("\(L10n.error.localized): \(error.localizedDescription)")) }
    }

    // MARK: - Cipher CRUD

    func saveCipher(_ cipher: VaultCipher, isNew: Bool) async {
        do {
            let req = encryptCipherRequest(cipher)
            let noName = "misc.noName".localized, noOrgKey = "misc.noOrgKey".localized, undecryptable = "misc.undecryptable".localized
            if isNew {
                let r = try await api.createCipher(req)
                if let d = VaultDecryptor.decryptCipher(r, crypto: crypto, noName: noName, noOrgKey: noOrgKey, undecryptable: undecryptable) { ciphers.append(d); selectedCipherId = d.id }
            } else {
                let r = try await api.updateCipher(id: cipher.id, req)
                if let d = VaultDecryptor.decryptCipher(r, crypto: crypto, noName: noName, noOrgKey: noOrgKey, undecryptable: undecryptable), let i = ciphers.firstIndex(where: { $0.id == cipher.id }) { ciphers[i] = d }
            }
            showToast(.saved())
        } catch { showToast(.error(error.localizedDescription)) }
    }

    func deleteCipher(_ cipher: VaultCipher) async {
        do {
            try await api.deleteCipher(id: cipher.id)
            ciphers.removeAll { $0.id == cipher.id }
            if selectedCipherId == cipher.id { selectedCipherId = nil }
            showToast(.deleted())
        } catch { showToast(.error(error.localizedDescription)) }
    }

    /// Create a copy of a cipher as a new item (server assigns the real id).
    /// Attachments are not copied (they are separate server blobs).
    func duplicateCipher(_ cipher: VaultCipher) async {
        var copy = cipher
        copy.id = UUID().uuidString
        copy.name = cipher.name + " " + L10n.Items.copySuffix.localized
        copy.attachments = nil
        await saveCipher(copy, isNew: true)
    }

    func toggleFavorite(_ cipher: VaultCipher) async {
        guard let i = ciphers.firstIndex(where: { $0.id == cipher.id }) else { return }
        ciphers[i].favorite.toggle()
        do { _ = try await api.updateCipher(id: cipher.id, encryptCipherRequest(ciphers[i])) }
        catch { ciphers[i].favorite.toggle(); showToast(.error(L10n.error.localized)) }
    }

    func moveCipherToFolder(_ cipherId: String, folderId: String?) async {
        guard let i = ciphers.firstIndex(where: { $0.id == cipherId }) else { return }
        let old = ciphers[i].folderId; ciphers[i].folderId = folderId
        do {
            _ = try await api.updateCipher(id: cipherId, encryptCipherRequest(ciphers[i]))
            showToast(.info(L10n.moved.localized))
        } catch { ciphers[i].folderId = old; showToast(.error(L10n.error.localized)) }
    }


    // MARK: - Encrypt

    private func encryptCipherRequest(_ c: VaultCipher) -> CipherRequest {
        let org = c.organizationId
        var lr: LoginRequest?
        if let l = c.login {
            lr = LoginRequest(username: crypto.encrypt(l.username, orgId: org), password: crypto.encrypt(l.password, orgId: org),
                            totp: crypto.encrypt(l.totp, orgId: org),
                            uris: l.uris?.map { UriRequest(uri: crypto.encrypt($0.uri, orgId: org), match: $0.match) })
        }
        var cr: CardRequest?
        if let cd = c.card {
            cr = CardRequest(cardholderName: crypto.encrypt(cd.cardholderName, orgId: org), brand: crypto.encrypt(cd.brand, orgId: org),
                           number: crypto.encrypt(cd.number, orgId: org), expMonth: crypto.encrypt(cd.expMonth, orgId: org),
                           expYear: crypto.encrypt(cd.expYear, orgId: org), code: crypto.encrypt(cd.code, orgId: org))
        }
        var ir: IdentityRequest?
        if let id = c.identity {
            ir = IdentityRequest(
                title: crypto.encrypt(id.title, orgId: org), firstName: crypto.encrypt(id.firstName, orgId: org),
                middleName: crypto.encrypt(id.middleName, orgId: org), lastName: crypto.encrypt(id.lastName, orgId: org),
                company: crypto.encrypt(id.company, orgId: org), email: crypto.encrypt(id.email, orgId: org),
                phone: crypto.encrypt(id.phone, orgId: org), ssn: crypto.encrypt(id.ssn, orgId: org),
                username: crypto.encrypt(id.username, orgId: org), passportNumber: crypto.encrypt(id.passportNumber, orgId: org),
                licenseNumber: crypto.encrypt(id.licenseNumber, orgId: org),
                address1: crypto.encrypt(id.address1, orgId: org), address2: crypto.encrypt(id.address2, orgId: org),
                address3: crypto.encrypt(id.address3, orgId: org), city: crypto.encrypt(id.city, orgId: org),
                state: crypto.encrypt(id.state, orgId: org), postalCode: crypto.encrypt(id.postalCode, orgId: org),
                country: crypto.encrypt(id.country, orgId: org))
        }
        let fr = c.fields?.map { FieldRequest(name: crypto.encrypt($0.name, orgId: org), value: crypto.encrypt($0.value, orgId: org), type: $0.type.rawValue) }
        return CipherRequest(
            type: c.type.rawValue, name: crypto.encrypt(c.name, orgId: org) ?? "",
            notes: crypto.encrypt(c.notes, orgId: org), folderId: c.folderId,
            favorite: c.favorite, login: lr, card: cr,
            secureNote: c.secureNote.map { SecureNoteRequest(type: $0.type ?? 0) },
            identity: ir, fields: fr, reprompt: c.reprompt)
    }
}
