import Foundation

/// Import from 1Password's unencrypted export (`.1pux`).
///
/// A `.1pux` is a ZIP holding `export.attributes`, `export.data` and a `files/` folder. Only
/// `export.data` is read: it is JSON shaped `accounts[].vaults[].items[]`, and the `files/`
/// folder holds documents and attachments, which the server import path cannot carry anyway.
///
/// Shape taken from 1Password's published description of the format rather than from a sample
/// file, so the optional pieces are treated as optional throughout — an export from a vault
/// with no sections, no tags or no URLs is normal, not malformed.
enum OnePasswordImporter {

    /// 1Password item categories. Only the ones with a clear counterpart are mapped; anything
    /// else becomes a secure note, which keeps the title, the notes and every field rather
    /// than guessing at a shape and dropping what does not fit.
    private enum Category: String {
        case login = "001"
        case creditCard = "002"
        case secureNote = "003"
        case identity = "004"
        case password = "005"
    }

    static func parse(_ archive: Data) throws -> [VaultMigrator.ImportedEntry] {
        // Some exporters nest the contents under a folder, so the exact path is not assumed.
        guard let json = try ZipArchive.extractFirst(from: archive, where: {
            $0 == "export.data" || $0.hasSuffix("/export.data")
        }) else {
            throw ZipArchive.ZipError.entryNotFound("export.data")
        }
        return try parseExportData(json)
    }

    /// Split out so the JSON can be tested without building an archive around it.
    static func parseExportData(_ json: Data) throws -> [VaultMigrator.ImportedEntry] {
        let root = try JSONSerialization.jsonObject(with: json)
        guard let object = root as? [String: Any],
              let accounts = object["accounts"] as? [[String: Any]] else { return [] }

        var entries: [VaultMigrator.ImportedEntry] = []
        for account in accounts {
            for vault in account["vaults"] as? [[String: Any]] ?? [] {
                let vaultName = (vault["attrs"] as? [String: Any])?["name"] as? String
                for item in vault["items"] as? [[String: Any]] ?? [] {
                    if let entry = mapItem(item, vaultName: vaultName) { entries.append(entry) }
                }
            }
        }
        return entries
    }

    // MARK: - One item

    private static func mapItem(_ item: [String: Any], vaultName: String?) -> VaultMigrator.ImportedEntry? {
        // "archived" is 1Password's trash. Importing it would restore things the user threw
        // away, in a vault where they may no longer be able to tell which is which.
        guard (item["state"] as? String ?? "active") == "active" else { return nil }

        let overview = item["overview"] as? [String: Any] ?? [:]
        let details = item["details"] as? [String: Any] ?? [:]
        let title = (overview["title"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            ?? (overview["url"] as? String) ?? ""
        guard !title.isEmpty else { return nil }

        let category = Category(rawValue: item["categoryUuid"] as? String ?? "") ?? .secureNote
        let login = loginFields(details)
        let sections = sectionFields(details)
        var notes = details["notesPlain"] as? String

        // Tags have no counterpart in the Bitwarden shape, and dropping them silently would
        // lose something the user deliberately wrote. They go into the notes instead.
        if let tags = overview["tags"] as? [String], !tags.isEmpty {
            let line = "Tags: " + tags.joined(separator: ", ")
            notes = [notes, line].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: "\n\n")
        }

        var cipher = VaultCipher(
            id: UUID().uuidString, organizationId: nil, folderId: nil, collectionIds: nil,
            type: .secureNote, name: title, notes: (notes?.isEmpty ?? true) ? nil : notes,
            login: nil, card: nil, secureNote: CipherSecureNote(type: 0), identity: nil,
            fields: sections.custom.isEmpty ? nil : sections.custom, attachments: nil,
            favorite: (item["favIndex"] as? Int ?? 0) > 0, reprompt: nil,
            creationDate: unixDate(item["createdAt"]), revisionDate: unixDate(item["updatedAt"]),
            deletedDate: nil)

        switch category {
        case .login, .password:
            cipher.type = .login
            cipher.secureNote = nil
            cipher.login = CipherLogin(username: login.username, password: login.password,
                                       totp: sections.totp, uris: uris(overview))
        case .creditCard:
            cipher.type = .card
            cipher.secureNote = nil
            cipher.card = sections.card
        case .identity:
            cipher.type = .identity
            cipher.secureNote = nil
            cipher.identity = sections.identity
        case .secureNote:
            break
        }
        return VaultMigrator.ImportedEntry(cipher: cipher, folderPath: vaultName)
    }

    // MARK: - Login fields

    /// `loginFields` is what the browser extension captured, so the field names vary by site.
    /// `designation` is the only reliable marker — the format allows at most one `username`
    /// and one `password` — with the field type as a fallback for exports that omit it.
    private static func loginFields(_ details: [String: Any]) -> (username: String?, password: String?) {
        let fields = details["loginFields"] as? [[String: Any]] ?? []
        var username: String?
        var password: String?
        for field in fields {
            let value = field["value"] as? String
            guard let value, !value.isEmpty else { continue }
            let designation = (field["designation"] as? String)?.lowercased()
            // The documented key is `type`; exports in the wild also use `fieldType`.
            let type = (field["fieldType"] as? String ?? field["type"] as? String)?.uppercased()
            if designation == "username" || (designation == nil && type == "E" && username == nil) {
                username = username ?? value
            } else if designation == "password" || (designation == nil && type == "P" && password == nil) {
                password = password ?? value
            }
        }
        return (username, password)
    }

    private static func uris(_ overview: [String: Any]) -> [CipherUri]? {
        var seen = Set<String>()
        var result: [CipherUri] = []
        for raw in [overview["url"] as? String].compactMap({ $0 })
            + (overview["urls"] as? [[String: Any]] ?? []).compactMap({ $0["url"] as? String }) {
            guard !raw.isEmpty, seen.insert(raw).inserted else { continue }
            result.append(CipherUri(uri: raw, match: nil))
        }
        return result.isEmpty ? nil : result
    }

    // MARK: - Sections

    private struct Sections {
        var custom: [CipherField] = []
        var totp: String?
        var card: CipherCard?
        var identity: CipherIdentity?
    }

    /// Walk `details.sections`, pulling out the pieces that have a home in a typed cipher and
    /// keeping everything else as a custom field.
    ///
    /// A section field's `value` is a single-key object naming its type — `{"concealed": "…"}`,
    /// `{"string": "…"}`, `{"totp": "…"}` and so on. That key is the only indication of what
    /// the value is, so it drives both the typed mapping and whether a custom field is marked
    /// hidden.
    private static func sectionFields(_ details: [String: Any]) -> Sections {
        var out = Sections()
        var card = CipherCard(cardholderName: nil, brand: nil, number: nil,
                              expMonth: nil, expYear: nil, code: nil)
        var identity = CipherIdentity(title: nil, firstName: nil, middleName: nil, lastName: nil,
                                      company: nil, email: nil, phone: nil, ssn: nil, username: nil,
                                      passportNumber: nil, licenseNumber: nil,
                                      address1: nil, address2: nil, address3: nil,
                                      city: nil, state: nil, postalCode: nil, country: nil)

        for section in details["sections"] as? [[String: Any]] ?? [] {
            let sectionTitle = section["title"] as? String ?? ""
            for field in section["fields"] as? [[String: Any]] ?? [] {
                guard let wrapper = field["value"] as? [String: Any],
                      let (kind, value) = flatten(wrapper), !value.isEmpty else { continue }

                let id = (field["id"] as? String ?? "").lowercased()
                let label = (field["title"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? id
                let name = sectionTitle.isEmpty ? label : "\(sectionTitle) / \(label)"

                if kind == "totp", out.totp == nil { out.totp = value; continue }

                switch id {
                case "cardholder":   card.cardholderName = value; continue
                case "ccnum":        card.number = value; continue
                case "cvv":          card.code = value; continue
                case "type":         card.brand = value; continue
                case "expiry":
                    // 1Password stores a month-year as YYYYMM.
                    if value.count == 6, let year = Int(value.prefix(4)), let month = Int(value.suffix(2)) {
                        card.expYear = String(year); card.expMonth = String(month)
                        continue
                    }
                case "firstname":    identity.firstName = value; continue
                case "initial":      identity.middleName = value; continue
                case "lastname":     identity.lastName = value; continue
                case "company":      identity.company = value; continue
                case "email":        identity.email = value; continue
                case "defphone", "cellphone": identity.phone = identity.phone ?? value; continue
                case "number":       identity.passportNumber = value; continue
                case "city":         identity.city = value; continue
                case "state":        identity.state = value; continue
                case "zip":          identity.postalCode = value; continue
                case "country":      identity.country = value; continue
                case "street":       identity.address1 = value; continue
                default: break
                }

                out.custom.append(CipherField(name: name, value: value,
                                              type: kind == "concealed" ? .hidden : .text))
            }
        }

        if card.number != nil || card.cardholderName != nil || card.code != nil { out.card = card }
        if identity.firstName != nil || identity.lastName != nil || identity.email != nil {
            out.identity = identity
        }
        return out
    }

    /// The single key/value pair inside a section field's `value` wrapper, as (type, text).
    /// Numbers and booleans are rendered rather than skipped — a field the user filled in is
    /// worth keeping whatever its JSON type.
    private static func flatten(_ wrapper: [String: Any]) -> (String, String)? {
        guard let key = wrapper.keys.first else { return nil }
        switch wrapper[key] {
        case let text as String:   return (key, text)
        case let number as NSNumber:
            // A month-year comes through as a number; Bool would otherwise print as 1/0.
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return (key, number.boolValue ? "true" : "false") }
            return (key, number.stringValue)
        case let nested as [String: Any]:
            // An address is an object of its own; flattened into one readable line.
            let order = ["street", "city", "state", "zip", "country"]
            let parts = order.compactMap { nested[$0] as? String }.filter { !$0.isEmpty }
            return parts.isEmpty ? nil : (key, parts.joined(separator: ", "))
        default:
            return nil
        }
    }

    private static func unixDate(_ raw: Any?) -> Date? {
        guard let seconds = raw as? Double ?? (raw as? Int).map(Double.init), seconds > 0 else { return nil }
        return Date(timeIntervalSince1970: seconds)
    }
}
