import Foundation

/// Decrypted vault produced off the main thread by `VaultDecryptor`.
struct DecryptedVault {
    let profileName: String
    let profileEmail: String
    let organizations: [VaultOrganization]
    let folders: [VaultFolder]
    let collections: [VaultCollection]
    let ciphers: [VaultCipher]
}

/// Decodes and decrypts a sync payload entirely off the main actor so the UI
/// doesn't stall while a large vault is processed. All methods are `nonisolated`
/// and operate only on the passed-in `CryptoService` (no main-actor state), with
/// localized fallback strings supplied by the caller (resolved on the main thread).
enum VaultDecryptor {

    nonisolated static func decrypt(data: Data, crypto: CryptoService, noName: String, noOrgKey: String, undecryptable: String) -> DecryptedVault? {
        guard let r = try? JSONDecoder().decode(SyncResponse.self, from: data) else { return nil }

        let profileName = r.profile?.name ?? ""
        let profileEmail = r.profile?.email ?? ""

        // Key setup must precede decryption; it happens here, inside the single
        // background task, so the crypto instance is never mutated concurrently.
        if let pk = r.profile?.privateKey { crypto.setPrivateKey(from: pk) }
        var organizations: [VaultOrganization] = []
        if let orgs = r.profile?.organizations, !orgs.isEmpty {
            crypto.setOrganizationKeys(orgs)
            organizations = orgs.compactMap { o in
                guard let id = o.id, let name = o.name else { return nil }
                return VaultOrganization(id: id, name: name)
            }
        }

        let folders: [VaultFolder] = (r.folders ?? []).compactMap { sf in
            guard let id = sf.id else { return nil }
            return VaultFolder(id: id, name: crypto.decrypt(sf.name) ?? noName, revisionDate: Date.fromISO(sf.revisionDate))
        }

        let collections: [VaultCollection] = (r.collections ?? []).compactMap { sc in
            guard let id = sc.id else { return nil }
            let orgId = sc.organizationId
            let name = crypto.decrypt(sc.name, orgId: orgId) ?? noName
            return VaultCollection(id: id, name: name, organizationId: orgId)
        }

        let ciphers: [VaultCipher] = (r.ciphers ?? []).compactMap {
            decryptCipher($0, crypto: crypto, noName: noName, noOrgKey: noOrgKey, undecryptable: undecryptable)
        }

        return DecryptedVault(profileName: profileName, profileEmail: profileEmail,
                              organizations: organizations, folders: folders,
                              collections: collections, ciphers: ciphers)
    }

    nonisolated static func decryptCipher(_ sc: SyncCipher, crypto: CryptoService, noName: String, noOrgKey: String, undecryptable: String) -> VaultCipher? {
        guard let id = sc.id, let typeInt = sc.type, let type = CipherType(rawValue: typeInt) else { return nil }
        let orgId = sc.organizationId

        // Cipher Key Encryption: newer items carry their own key, wrapped by the user/org
        // key. When present, every field of the item is encrypted with this per-cipher key
        // rather than the user/org key directly. `dec` routes each field accordingly.
        let itemKey: SymmetricCryptoKey? = sc.key.flatMap { crypto.cipherKey(from: $0, orgId: orgId) }
        func dec(_ s: String?) -> String? {
            if let itemKey { return crypto.decrypt(s, with: itemKey) }
            return crypto.decrypt(s, orgId: orgId)
        }

        let decryptedName: String = {
            if let n = dec(sc.name), !n.isEmpty { return n }
            if let n = dec(sc.data?.name), !n.isEmpty { return n }
            if orgId != nil && !crypto.hasOrgKey(for: orgId) { return noOrgKey }
            // An encrypted name is present but could not be decrypted (legacy unauthenticated
            // EncType 0, an unsupported type, or a failed MAC check). Surface it explicitly so
            // the item doesn't masquerade as a normal unnamed entry. Crypto is NOT relaxed:
            // the field is still rejected at decrypt time; this only changes the placeholder.
            let hasEncryptedName = (sc.name?.isEmpty == false) || (sc.data?.name?.isEmpty == false)
            if hasEncryptedName { return undecryptable }
            return noName
        }()

        let notes = dec(sc.notes) ?? dec(sc.data?.notes)

        var login: CipherLogin?
        if let sl = sc.login {
            login = CipherLogin(username: dec(sl.username), password: dec(sl.password),
                               totp: dec(sl.totp),
                               uris: sl.uris?.map { CipherUri(uri: dec($0.uri), match: $0.match) })
        } else if type == .login, let d = sc.data {
            login = CipherLogin(username: dec(d.username), password: dec(d.password),
                               totp: dec(d.totp),
                               uris: d.uris?.map { CipherUri(uri: dec($0.uri), match: $0.match) })
        }

        var card: CipherCard?
        if let sc2 = sc.card {
            card = CipherCard(cardholderName: dec(sc2.cardholderName), brand: dec(sc2.brand),
                            number: dec(sc2.number), expMonth: dec(sc2.expMonth),
                            expYear: dec(sc2.expYear), code: dec(sc2.code))
        } else if type == .card, let d = sc.data {
            card = CipherCard(cardholderName: dec(d.cardholderName), brand: dec(d.brand),
                            number: dec(d.number), expMonth: dec(d.expMonth),
                            expYear: dec(d.expYear), code: dec(d.code))
        }

        var identity: CipherIdentity?
        if let si = sc.identity {
            identity = CipherIdentity(
                title: dec(si.title), firstName: dec(si.firstName),
                middleName: dec(si.middleName), lastName: dec(si.lastName),
                company: dec(si.company), email: dec(si.email),
                phone: dec(si.phone), ssn: dec(si.ssn),
                username: dec(si.username), passportNumber: dec(si.passportNumber),
                licenseNumber: dec(si.licenseNumber),
                address1: dec(si.address1), address2: dec(si.address2),
                address3: dec(si.address3), city: dec(si.city),
                state: dec(si.state), postalCode: dec(si.postalCode),
                country: dec(si.country))
        } else if type == .identity, let d = sc.data {
            identity = CipherIdentity(
                title: dec(d.title), firstName: dec(d.firstName),
                middleName: dec(d.middleName), lastName: dec(d.lastName),
                company: dec(d.company), email: dec(d.email),
                phone: dec(d.phone), ssn: dec(d.ssn),
                username: dec(d.username), passportNumber: dec(d.passportNumber),
                licenseNumber: dec(d.licenseNumber),
                address1: dec(d.address1), address2: dec(d.address2),
                address3: dec(d.address3), city: dec(d.city),
                state: dec(d.state), postalCode: dec(d.postalCode),
                country: dec(d.country))
        }

        let fields: [CipherField]? = (sc.fields ?? sc.data?.fields)?.map {
            CipherField(name: dec($0.name) ?? "", value: dec($0.value) ?? "",
                       type: FieldType(rawValue: $0.type ?? 0) ?? .text)
        }

        let atts = sc.attachments?.map { sa in
            CipherAttachment(id: sa.id, fileName: dec(sa.fileName),
                           size: sa.size, sizeName: sa.sizeName, url: sa.url, key: sa.key)
        }

        return VaultCipher(id: id, organizationId: sc.organizationId, folderId: sc.folderId,
                          collectionIds: sc.collectionIds, type: type, name: decryptedName, notes: notes,
                          login: login, card: card,
                          secureNote: sc.secureNote.map { CipherSecureNote(type: $0.type) },
                          identity: identity,
                          fields: fields, attachments: atts, favorite: sc.favorite ?? false, reprompt: sc.reprompt,
                          creationDate: Date.fromISO(sc.creationDate), revisionDate: Date.fromISO(sc.revisionDate),
                          deletedDate: Date.fromISO(sc.deletedDate))
    }
}
