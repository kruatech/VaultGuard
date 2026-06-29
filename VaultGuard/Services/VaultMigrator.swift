import Foundation
import Security

/// Convert a decrypted Bitwarden/Vaultwarden vault into a KeePass document that
/// `KDBXWriter.build` can encrypt. Pure transform: no I/O, no network. Attachment bytes are
/// supplied by the caller (they must be downloaded/decrypted via the API first), keyed by the
/// `CipherAttachment.id`; attachments without bytes are skipped.
///
/// Field mapping (lossy points called out):
///  • login → Title / UserName / Password(Protected) / URL / Notes; extra URIs → KP2A_URL_N;
///    TOTP → `otp` (otpauth URI); custom fields → strings (hidden → Protected).
///  • card / identity → a generic entry with labelled custom strings (sensitive ones Protected);
///    the Bitwarden *type* is not represented by KeePass and is therefore lost, but no data is.
///  • secureNote → Title + Notes.
///  • folder → group path (Bitwarden "/" nesting honoured); organization → `Organizations/<org>`
///    path prefix; multiple collections → a `Collections` custom string (a KeePass entry can live
///    in only one group). Deleted items → Recycle Bin group.
///  • favorite and reprompt are dropped (no KeePass equivalent).
enum VaultMigrator {

    /// - Returns: the plaintext KeePass `XMLDocument` (Protected values hold plaintext; the
    ///   writer encrypts them) and the binary pool to pass to `KDBXWriter.build`.
    static func exportToKDBX(
        databaseName: String,
        ciphers: [VaultCipher],
        folders: [VaultFolder],
        collections: [VaultCollection],
        organizations: [VaultOrganization],
        attachmentBytes: [String: Data] = [:]
    ) -> (document: XMLDocument, binaries: [Data]) {

        let folderById = Dictionary(folders.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        let orgById = Dictionary(organizations.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        let collById = Dictionary(collections.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })

        var binaries: [Data] = []

        // Root group named after the database.
        let root = XMLElement(name: "Group")
        root.addChild(XMLElement(name: "UUID", stringValue: secureRandom(16).base64EncodedString()))
        root.addChild(XMLElement(name: "Name", stringValue: databaseName))

        // Recycle Bin group (referenced from Meta) for soft-deleted items.
        let rbUUID = secureRandom(16).base64EncodedString()
        let recycleBin = XMLElement(name: "Group")
        recycleBin.addChild(XMLElement(name: "UUID", stringValue: rbUUID))
        recycleBin.addChild(XMLElement(name: "Name", stringValue: "Recycle Bin"))
        root.addChild(recycleBin)

        // Lazy group creation by path, reusing intermediate groups.
        var groupCache: [String: XMLElement] = [:]
        func ensureGroup(_ segments: [String]) -> XMLElement {
            var parent = root
            var key = ""
            for seg in segments where !seg.isEmpty {
                key += "/" + seg
                if let existing = groupCache[key] { parent = existing; continue }
                let g = XMLElement(name: "Group")
                g.addChild(XMLElement(name: "UUID", stringValue: secureRandom(16).base64EncodedString()))
                g.addChild(XMLElement(name: "Name", stringValue: seg))
                parent.addChild(g)
                groupCache[key] = g
                parent = g
            }
            return parent
        }

        for cipher in ciphers {
            let entry = makeEntry(cipher, collById: collById, attachmentBytes: attachmentBytes, binaries: &binaries)
            if cipher.deletedDate != nil {
                recycleBin.addChild(entry)
                continue
            }
            var segments: [String] = []
            if let orgId = cipher.organizationId, let org = orgById[orgId] {
                segments.append("Organizations"); segments.append(org.name)
            }
            if let fid = cipher.folderId, let folder = folderById[fid] {
                segments.append(contentsOf: folder.name.split(separator: "/").map(String.init))
            }
            ensureGroup(segments).addChild(entry)
        }

        // Meta + Root → KeePassFile.
        let meta = XMLElement(name: "Meta")
        meta.addChild(XMLElement(name: "Generator", stringValue: "VaultGuard"))
        meta.addChild(XMLElement(name: "DatabaseName", stringValue: databaseName))
        meta.addChild(XMLElement(name: "RecycleBinEnabled", stringValue: "True"))
        meta.addChild(XMLElement(name: "RecycleBinUUID", stringValue: rbUUID))
        meta.addChild(XMLElement(name: "HistoryMaxItems", stringValue: "10"))

        let rootContainer = XMLElement(name: "Root")
        rootContainer.addChild(root)

        let keePassFile = XMLElement(name: "KeePassFile")
        keePassFile.addChild(meta)
        keePassFile.addChild(rootContainer)

        let doc = XMLDocument(rootElement: keePassFile)
        doc.version = "1.0"
        doc.characterEncoding = "utf-8"
        return (doc, binaries)
    }

    // MARK: - Entry construction

    private static func makeEntry(
        _ cipher: VaultCipher,
        collById: [String: VaultCollection],
        attachmentBytes: [String: Data],
        binaries: inout [Data]
    ) -> XMLElement {
        let entry = XMLElement(name: "Entry")
        entry.addChild(XMLElement(name: "UUID", stringValue: secureRandom(16).base64EncodedString()))
        entry.addChild(times(creation: cipher.creationDate, modification: cipher.revisionDate))

        switch cipher.type {
        case .login:
            let login = cipher.login
            addStandard(entry, "Title", cipher.name)
            addStandard(entry, "UserName", login?.username ?? "")
            addStandard(entry, "Password", login?.password ?? "", protected: true)
            let uris = login?.uris ?? []
            addStandard(entry, "URL", uris.first?.uri ?? "")
            for (i, u) in uris.enumerated() where i >= 1 {
                addCustom(entry, "KP2A_URL_\(i)", u.uri)
            }
            if let totp = login?.totp, !totp.isEmpty {
                addCustom(entry, "otp", totpString(totp, title: cipher.name), protected: true)
            }
            addStandard(entry, "Notes", cipher.notes ?? "")

        case .card:
            addStandard(entry, "Title", cipher.name)
            addStandard(entry, "Notes", cipher.notes ?? "")
            let c = cipher.card
            addCustom(entry, "Cardholder Name", c?.cardholderName)
            addCustom(entry, "Brand", c?.brand)
            addCustom(entry, "Number", c?.number, protected: true)
            let exp = [c?.expMonth, c?.expYear].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: "/")
            addCustom(entry, "Expiration", exp.isEmpty ? nil : exp)
            addCustom(entry, "CVV", c?.code, protected: true)

        case .identity:
            addStandard(entry, "Title", cipher.name)
            addStandard(entry, "Notes", cipher.notes ?? "")
            let id = cipher.identity
            addCustom(entry, "First Name", id?.firstName)
            addCustom(entry, "Middle Name", id?.middleName)
            addCustom(entry, "Last Name", id?.lastName)
            addCustom(entry, "Company", id?.company)
            addCustom(entry, "Email", id?.email)
            addCustom(entry, "Phone", id?.phone)
            addCustom(entry, "SSN", id?.ssn, protected: true)
            addCustom(entry, "Passport Number", id?.passportNumber, protected: true)
            addCustom(entry, "License Number", id?.licenseNumber, protected: true)
            addCustom(entry, "Username", id?.username)
            let addr = [id?.address1, id?.address2, id?.address3, id?.city, id?.state, id?.postalCode, id?.country]
                .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: ", ")
            addCustom(entry, "Address", addr.isEmpty ? nil : addr)

        case .secureNote:
            addStandard(entry, "Title", cipher.name)
            addStandard(entry, "Notes", cipher.notes ?? "")
        }

        // Custom fields (all types). hidden → Protected.
        for field in cipher.fields ?? [] {
            addCustom(entry, field.name, field.value, protected: field.type == .hidden)
        }

        // Multiple collections can't be groups; preserve their names as a string.
        let collNames = (cipher.collectionIds ?? []).compactMap { collById[$0]?.name }
        if !collNames.isEmpty {
            addCustom(entry, "Collections", collNames.joined(separator: ", "))
        }

        // Attachments → binary pool + <Binary> references.
        for att in cipher.attachments ?? [] {
            guard let aid = att.id, let bytes = attachmentBytes[aid] else { continue }
            let ref = binaries.count
            binaries.append(Data([0x01]) + bytes)
            let bin = XMLElement(name: "Binary")
            bin.addChild(XMLElement(name: "Key", stringValue: att.fileName ?? "attachment"))
            let v = XMLElement(name: "Value")
            if let attr = XMLNode.attribute(withName: "Ref", stringValue: String(ref)) as? XMLNode {
                v.addAttribute(attr)
            }
            bin.addChild(v)
            entry.addChild(bin)
        }

        return entry
    }

    // MARK: - String helpers

    /// Standard KeePass field: always emitted (value may be empty) so readers see the key.
    private static func addStandard(_ entry: XMLElement, _ key: String, _ value: String, protected: Bool = false) {
        let s = XMLElement(name: "String")
        s.addChild(XMLElement(name: "Key", stringValue: key))
        let v = XMLElement(name: "Value", stringValue: value)
        if protected, let attr = XMLNode.attribute(withName: "Protected", stringValue: "True") as? XMLNode {
            v.addAttribute(attr)
        }
        s.addChild(v)
        entry.addChild(s)
    }

    /// Custom field: skipped when empty/nil.
    private static func addCustom(_ entry: XMLElement, _ key: String, _ value: String?, protected: Bool = false) {
        guard let value, !value.isEmpty else { return }
        addStandard(entry, key, value, protected: protected)
    }

    private static func times(creation: Date?, modification: Date?) -> XMLElement {
        let created = KeePassBackend.kdbxTimeString(creation ?? Date())
        let modified = KeePassBackend.kdbxTimeString(modification ?? creation ?? Date())
        let t = XMLElement(name: "Times")
        t.addChild(XMLElement(name: "CreationTime", stringValue: created))
        t.addChild(XMLElement(name: "LastModificationTime", stringValue: modified))
        t.addChild(XMLElement(name: "LastAccessTime", stringValue: modified))
        t.addChild(XMLElement(name: "Expires", stringValue: "False"))
        t.addChild(XMLElement(name: "UsageCount", stringValue: "0"))
        return t
    }

    /// Normalise a Bitwarden TOTP value to a KeePassXC `otp` otpauth URI. A value that is already
    /// an otpauth URI is kept as-is; a bare secret is wrapped.
    private static func totpString(_ totp: String, title: String) -> String {
        let trimmed = totp.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("otpauth://") { return trimmed }
        let secret = trimmed.replacingOccurrences(of: " ", with: "")
        let label = title.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? "TOTP"
        return "otpauth://totp/\(label)?secret=\(secret)"
    }

    private static func secureRandom(_ n: Int) -> Data {
        var d = Data(count: n)
        let ok = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) }
        // Group/entry UUIDs are identity material, not cryptographic key material; a CSPRNG
        // failure here is extraordinarily unlikely, but fall back rather than crashing the export.
        if ok != errSecSuccess { return Data(UUID().uuidString.utf8).prefix(n) }
        return d
    }

    // MARK: - Import (KeePass → Bitwarden shape)

    /// One entry ready to be created on the server: a reshaped `VaultCipher` plus the folder
    /// path it should live in (the caller resolves/creates the folder and sets `folderId`).
    /// Attachments are carried on `cipher.attachments` with `id` = KeePass binary ref, so the
    /// caller can fetch the bytes via `KeePassBackend.attachmentData(ref:)`.
    struct ImportedEntry {
        var cipher: VaultCipher
        var folderPath: String?
    }

    /// Reshape KeePass entries (as produced by `KDBXVaultMapper`) into Bitwarden-bound ciphers:
    /// fold the `otp` field back into `login.totp`, `KP2A_URL_N` fields back into extra URIs, map
    /// the group path to a folder path, and strip KeePass/Bitwarden-only identity (server assigns
    /// ids). Soft-deleted entries (Recycle Bin) are skipped. Everything imports as a login, since
    /// KeePass has no card/identity types — labelled fields from a prior export survive as custom
    /// fields.
    static func importFromKDBX(ciphers: [VaultCipher], folders: [VaultFolder]) -> [ImportedEntry] {
        let folderById = Dictionary(folders.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        var result: [ImportedEntry] = []

        for source in ciphers where source.deletedDate == nil {
            var login = source.login ?? CipherLogin(username: nil, password: nil, totp: nil, uris: nil)
            var remaining: [CipherField] = []
            var extraURIs: [(index: Int, uri: String)] = []

            for field in source.fields ?? [] {
                if field.name == "otp" {
                    login.totp = field.value
                } else if field.name.hasPrefix("KP2A_URL_"), let n = Int(field.name.dropFirst("KP2A_URL_".count)) {
                    extraURIs.append((n, field.value))
                } else {
                    remaining.append(field)
                }
            }

            if !extraURIs.isEmpty {
                var uris = login.uris ?? []
                for item in extraURIs.sorted(by: { $0.index < $1.index }) {
                    uris.append(CipherUri(uri: item.uri, match: nil))
                }
                login.uris = uris
            }

            let folderPath = source.folderId.flatMap { folderById[$0]?.name }

            let cipher = VaultCipher(
                id: "", organizationId: nil, folderId: nil, collectionIds: nil,
                type: .login, name: source.name, notes: source.notes,
                login: login, card: nil, secureNote: nil, identity: nil,
                fields: remaining.isEmpty ? nil : remaining,
                attachments: source.attachments,
                favorite: false, reprompt: nil,
                creationDate: source.creationDate, revisionDate: source.revisionDate, deletedDate: nil)

            result.append(ImportedEntry(cipher: cipher, folderPath: folderPath))
        }
        return result
    }

    // MARK: - Bitwarden JSON import (unencrypted export)

    enum ImportError: LocalizedError {
        case encryptedExport
        var errorDescription: String? {
            switch self {
            case .encryptedExport: return "encrypted_export"
            }
        }
    }

    private struct BWExport: Decodable {
        var encrypted: Bool?
        var folders: [BWFolder]?
        var items: [BWItem]?
    }
    private struct BWFolder: Decodable { var id: String?; var name: String? }
    private struct BWItem: Decodable {
        var folderId: String?
        var type: Int?
        var name: String?
        var notes: String?
        var favorite: Bool?
        var reprompt: Int?
        var login: CipherLogin?
        var card: CipherCard?
        var identity: CipherIdentity?
        var secureNote: CipherSecureNote?
        var fields: [CipherField]?
    }

    /// Parse an *unencrypted* Bitwarden `.json` export into importable entries. Type, favorite,
    /// reprompt, and custom fields are preserved (Bitwarden→Bitwarden, no loss). Encrypted exports
    /// are rejected. Throws on malformed JSON.
    static func importBitwardenJSON(data: Data) throws -> [ImportedEntry] {
        let export = try JSONDecoder().decode(BWExport.self, from: data)
        if export.encrypted == true { throw ImportError.encryptedExport }

        let folderName = Dictionary(
            (export.folders ?? []).compactMap { f -> (String, String)? in
                guard let id = f.id, let name = f.name else { return nil }
                return (id, name)
            }, uniquingKeysWith: { a, _ in a })

        var result: [ImportedEntry] = []
        for item in export.items ?? [] {
            let type = CipherType(rawValue: item.type ?? 1) ?? .login
            let fields = (item.fields?.isEmpty ?? true) ? nil : item.fields

            let cipher = VaultCipher(
                id: "", organizationId: nil, folderId: nil, collectionIds: nil,
                type: type, name: item.name ?? "", notes: item.notes,
                login: type == .login ? item.login : nil,
                card: type == .card ? item.card : nil,
                secureNote: type == .secureNote ? (item.secureNote ?? CipherSecureNote(type: 0)) : nil,
                identity: type == .identity ? item.identity : nil,
                fields: fields,
                attachments: nil,
                favorite: item.favorite ?? false, reprompt: item.reprompt,
                creationDate: nil, revisionDate: nil, deletedDate: nil)

            let folderPath = item.folderId.flatMap { folderName[$0] }
            result.append(ImportedEntry(cipher: cipher, folderPath: folderPath))
        }
        return result
    }

    // MARK: - Dedup

    /// Normalized identity used to detect duplicates: name + type + login username (lowercased).
    private static func dedupKey(_ c: VaultCipher) -> String {
        "\(c.name.lowercased())|\(c.type.rawValue)|\((c.login?.username ?? "").lowercased())"
    }

    /// Drop entries that already exist in `existing`, and collapse duplicates within the batch.
    static func dedupEntries(_ entries: [ImportedEntry], against existing: [VaultCipher]) -> [ImportedEntry] {
        var seen = Set(existing.map { dedupKey($0) })
        var out: [ImportedEntry] = []
        for entry in entries {
            let key = dedupKey(entry.cipher)
            if seen.contains(key) { continue }
            seen.insert(key)
            out.append(entry)
        }
        return out
    }

    // MARK: - CSV import (LastPass / Bitwarden / generic)

    enum CSVFormat { case lastpass, bitwarden, generic }

    /// RFC-4180-style CSV parse: handles quoted fields, escaped quotes (""), and commas/newlines
    /// inside quotes. Returns rows of string fields.
    static func parseCSV(_ text: String) -> [[String]] {
        var rows: [[String]] = []
        var row: [String] = []
        var field = ""
        var inQuotes = false
        let chars = Array(text)
        var i = 0
        while i < chars.count {
            let c = chars[i]
            if inQuotes {
                if c == "\"" {
                    if i + 1 < chars.count, chars[i + 1] == "\"" { field.append("\""); i += 2; continue }
                    inQuotes = false; i += 1
                } else { field.append(c); i += 1 }
            } else {
                switch c {
                case "\"": inQuotes = true; i += 1
                case ",":  row.append(field); field = ""; i += 1
                case "\r": i += 1
                case "\n": row.append(field); rows.append(row); row = []; field = ""; i += 1
                default:   field.append(c); i += 1
                }
            }
        }
        if !field.isEmpty || !row.isEmpty { row.append(field); rows.append(row) }
        return rows
    }

    /// Detect the CSV flavor from its header row.
    private static func detectCSV(_ header: [String]) -> CSVFormat {
        let h = Set(header.map { $0.lowercased() })
        if h.contains("login_username") || h.contains("login_uri") || h.contains("login_password") { return .bitwarden }
        if h.contains("grouping"), h.contains("extra"), h.contains("url") { return .lastpass }
        return .generic
    }

    /// Parse a CSV export (LastPass, Bitwarden, or a generic url/username/password/name layout)
    /// into importable entries. Type is preserved where the format encodes it; everything maps to
    /// a login otherwise.
    static func importCSV(data: Data) throws -> [ImportedEntry] {
        guard let text = String(data: data, encoding: .utf8) else { return [] }
        var rows = parseCSV(text)
        guard !rows.isEmpty else { return [] }
        let header = rows.removeFirst().map { $0.trimmingCharacters(in: .whitespaces) }
        let format = detectCSV(header)
        var index: [String: Int] = [:]
        for (i, name) in header.enumerated() { index[name.lowercased()] = i }
        func col(_ row: [String], _ name: String) -> String? {
            guard let i = index[name], i < row.count else { return nil }
            let v = row[i].trimmingCharacters(in: .whitespaces)
            return v.isEmpty ? nil : v
        }

        var result: [ImportedEntry] = []
        for row in rows {
            if row.allSatisfy({ $0.trimmingCharacters(in: .whitespaces).isEmpty }) { continue }
            let entry: ImportedEntry?
            switch format {
            case .lastpass:  entry = mapLastPass(row, col)
            case .bitwarden: entry = mapBitwardenCSV(row, col)
            case .generic:   entry = mapGeneric(row, col)
            }
            if let entry { result.append(entry) }
        }
        return result
    }

    private static func makeLogin(username: String?, password: String?, totp: String?, uri: String?) -> CipherLogin {
        CipherLogin(username: username, password: password, totp: totp,
                    uris: uri.map { [CipherUri(uri: $0, match: nil)] })
    }

    private static func cipher(type: CipherType, name: String, notes: String?,
                               login: CipherLogin?, fields: [CipherField]?,
                               favorite: Bool) -> VaultCipher {
        VaultCipher(id: "", organizationId: nil, folderId: nil, collectionIds: nil,
                    type: type, name: name.isEmpty ? "Imported" : name, notes: notes,
                    login: login, card: nil, secureNote: type == .secureNote ? CipherSecureNote(type: 0) : nil,
                    identity: nil, fields: fields, attachments: nil,
                    favorite: favorite, reprompt: nil,
                    creationDate: nil, revisionDate: nil, deletedDate: nil)
    }

    private static func mapLastPass(_ row: [String], _ col: ([String], String) -> String?) -> ImportedEntry? {
        let url = col(row, "url")
        let name = col(row, "name") ?? "Imported"
        let grouping = col(row, "grouping")?.replacingOccurrences(of: "\\", with: "/")
        let isNote = (url == "http://sn") || (url == nil && col(row, "username") == nil && col(row, "password") == nil)
        if isNote {
            return ImportedEntry(cipher: cipher(type: .secureNote, name: name, notes: col(row, "extra"),
                                                login: nil, fields: nil, favorite: col(row, "fav") == "1"),
                                 folderPath: grouping)
        }
        let login = makeLogin(username: col(row, "username"), password: col(row, "password"),
                              totp: col(row, "totp"), uri: url)
        return ImportedEntry(cipher: cipher(type: .login, name: name, notes: col(row, "extra"),
                                            login: login, fields: nil, favorite: col(row, "fav") == "1"),
                             folderPath: grouping)
    }

    private static func mapBitwardenCSV(_ row: [String], _ col: ([String], String) -> String?) -> ImportedEntry? {
        let typeStr = (col(row, "type") ?? "login").lowercased()
        let type: CipherType = typeStr == "note" ? .secureNote : .login   // card/identity CSV → login (no columns)
        let name = col(row, "name") ?? "Imported"
        let fav = (col(row, "favorite") ?? "0") == "1" || (col(row, "favorite") ?? "").lowercased() == "true"
        var fields: [CipherField]?
        if let raw = col(row, "fields") {
            let parsed = raw.split(separator: "\n").compactMap { line -> CipherField? in
                let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                guard parts.count == 2 else { return nil }
                return CipherField(name: parts[0], value: parts[1], type: .text)
            }
            fields = parsed.isEmpty ? nil : parsed
        }
        let login = type == .login
            ? makeLogin(username: col(row, "login_username"), password: col(row, "login_password"),
                        totp: col(row, "login_totp"), uri: col(row, "login_uri"))
            : nil
        return ImportedEntry(cipher: cipher(type: type, name: name, notes: col(row, "notes"),
                                            login: login, fields: fields, favorite: fav),
                             folderPath: col(row, "folder"))
    }

    private static func mapGeneric(_ row: [String], _ col: ([String], String) -> String?) -> ImportedEntry? {
        let name = col(row, "name") ?? col(row, "title") ?? "Imported"
        let login = makeLogin(username: col(row, "username") ?? col(row, "user") ?? col(row, "login"),
                              password: col(row, "password") ?? col(row, "pass"),
                              totp: col(row, "totp") ?? col(row, "otp"),
                              uri: col(row, "url") ?? col(row, "uri") ?? col(row, "website"))
        return ImportedEntry(cipher: cipher(type: .login, name: name, notes: col(row, "notes") ?? col(row, "note") ?? col(row, "extra"),
                                            login: login, fields: nil, favorite: false),
                             folderPath: col(row, "folder") ?? col(row, "grouping") ?? col(row, "group"))
    }
}
