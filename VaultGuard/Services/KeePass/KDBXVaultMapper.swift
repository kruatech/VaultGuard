import Foundation

// MARK: - KDBX XML → DecryptedVault
//
// Maps the decrypted KeePass XML into the app's neutral `DecryptedVault` (the same type the
// Bitwarden path produces), so everything above the backend is source-agnostic.
//
// Protected values are resolved through `KDBXProtectedStream` in DOCUMENT ORDER. Crucially,
// protected values inside <History> (and anywhere else) are still consumed from the stream
// even though history entries are not surfaced — otherwise the keystream would desync for
// every entry after a history block.
//
// Mapping notes (v1, read-only):
// - Each non-root <Group> becomes a `VaultFolder`; an entry's `folderId` is its immediate
//   parent group (nil when directly under the root group).
// - Entries map to `.login` ciphers. Title→name, UserName, Password, URL→uri, Notes,
//   `otp`/`TOTP Seed`→totp. Other string fields become custom `CipherField`s (hidden if the
//   value was protected).
// - Entries under the Recycle Bin group are marked deleted (shown in Trash).
// - Entry CreationTime/LastModificationTime are mapped to creationDate/revisionDate
//   (KDBX4 packed-binary or KDBX3.1 ISO-8601).

enum KDBXVaultMapper {

    static func map(xml: Data, stream: KDBXProtectedStream?, fallbackName: String = "", binaries: [Data] = []) -> DecryptedVault {
        let delegate = Delegate(stream: stream, binaries: binaries)
        let parser = XMLParser(data: xml)
        parser.delegate = delegate
        parser.parse()
        return DecryptedVault(
            profileName: delegate.databaseName.isEmpty ? fallbackName : delegate.databaseName,
            profileEmail: "",
            organizations: [],
            folders: delegate.folders,
            collections: [],
            ciphers: delegate.ciphers)
    }

    // MARK: SAX delegate

    private final class Delegate: NSObject, XMLParserDelegate {
        let stream: KDBXProtectedStream?
        let binaries: [Data]
        init(stream: KDBXProtectedStream?, binaries: [Data] = []) { self.stream = stream; self.binaries = binaries }

        // Results
        var folders: [VaultFolder] = []
        var ciphers: [VaultCipher] = []
        var databaseName = ""
        private var recycleBinId: String?

        // Parse state
        private var elementStack: [String] = []
        private var chars = ""

        private struct GroupFrame { let id: String; let name: String; let isRoot: Bool; let inRecycleBin: Bool; let isRecycleBinRoot: Bool; let path: String }
        private var groupStack: [GroupFrame] = []
        private var pendingGroupId: String?
        private var pendingGroupName: String?
        private var pendingGroupParentIsRoot = false

        // Entry/history
        private var historyDepth = 0
        private var realEntryActive = false
        private var entryId = ""
        private var entryKV: [(key: String, value: String, prot: Bool)] = []
        private var entryCreation: Date?
        private var entryModified: Date?
        private var binAttachments: [(key: String, ref: Int)] = []
        private var curBinKey: String?
        private var curBinRef: Int?

        // Icons
        private var customIcons: [String: Data] = [:]
        private var curCustomIconUUID: String?
        private var curCustomIconData: Data?
        private var entryIconId: Int?
        private var entryCustomIconUUID: String?

        // Current <String>
        private var curKey: String?
        private var curValueProtected = false

        private func parentElement() -> String {
            elementStack.count >= 2 ? elementStack[elementStack.count - 2] : ""
        }

        private func grandparentElement() -> String {
            elementStack.count >= 3 ? elementStack[elementStack.count - 3] : ""
        }

        func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?,
                    qualifiedName qName: String?, attributes attrs: [String: String]) {
            elementStack.append(name)
            chars = ""
            switch name {
            case "Group":
                pendingGroupParentIsRoot = (parentElement() == "Root")
                pendingGroupId = nil
                pendingGroupName = nil
            case "Entry":
                if historyDepth == 0 {
                    realEntryActive = true; entryKV = []; entryId = ""
                    entryCreation = nil; entryModified = nil
                    binAttachments = []
                    entryIconId = nil; entryCustomIconUUID = nil
                }
            case "History":
                historyDepth += 1
            case "String":
                curKey = nil; curValueProtected = false
            case "Binary":
                curBinKey = nil; curBinRef = nil
            case "Icon":
                if parentElement() == "CustomIcons" { curCustomIconUUID = nil; curCustomIconData = nil }
            case "Value":
                if parentElement() == "Binary" {
                    curBinRef = attrs["Ref"].flatMap { Int($0) }
                } else {
                    curValueProtected = (attrs["Protected"] == "True")
                }
            default:
                break
            }
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) { chars += string }
        func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
            if let s = String(data: CDATABlock, encoding: .utf8) { chars += s }
        }

        func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?,
                    qualifiedName qName: String?) {
            let parent = parentElement()
            switch name {
            case "UUID":
                if parent == "Group" {
                    pendingGroupId = Self.hexFromBase64(chars)
                } else if parent == "Entry", historyDepth == 0 {
                    entryId = Self.hexFromBase64(chars)
                } else if parent == "Icon" {
                    curCustomIconUUID = Self.hexFromBase64(chars)
                }
            case "Name":
                if parent == "Group" {
                    pendingGroupName = chars
                    let id = pendingGroupId ?? ""
                    let isRecycleBinRoot = (recycleBinId != nil && id == recycleBinId)
                    let inRB = (groupStack.last?.inRecycleBin ?? false) || isRecycleBinRoot
                    let parentPath = (groupStack.last.map { $0.isRoot ? "" : $0.path }) ?? ""
                    let path = parentPath.isEmpty ? chars : parentPath + "/" + chars
                    groupStack.append(GroupFrame(id: id, name: chars, isRoot: pendingGroupParentIsRoot,
                                                 inRecycleBin: inRB, isRecycleBinRoot: isRecycleBinRoot, path: path))
                }
            case "DatabaseName":
                if parent == "Meta" { databaseName = chars }
            case "RecycleBinUUID":
                if parent == "Meta" {
                    let hexId = Self.hexFromBase64(chars)
                    if hexId != String(repeating: "0", count: 32) { recycleBinId = hexId }
                }
            case "IconID":
                if historyDepth == 0, parent == "Entry" { entryIconId = Int(chars.trimmingCharacters(in: .whitespacesAndNewlines)) }
            case "CustomIconUUID":
                if historyDepth == 0, parent == "Entry" { entryCustomIconUUID = Self.hexFromBase64(chars) }
            case "Data":
                if parent == "Icon" { curCustomIconData = Data(base64Encoded: chars, options: .ignoreUnknownCharacters) }
            case "Icon":
                if parent == "CustomIcons", let u = curCustomIconUUID, let d = curCustomIconData { customIcons[u] = d }
            case "Key":
                if parentElement() == "Binary" { curBinKey = chars } else { curKey = chars }
            case "Value":
                // Resolve protected values in order — ALWAYS, even inside history, to keep the
                // keystream aligned. Only store into the real (non-history) entry.
                // Protected values: with a stream, decrypt in document order (consuming the
                // keystream, even inside history); without a stream, the document already holds
                // plaintext (editable form).
                let resolved: String
                if curValueProtected {
                    resolved = (stream != nil) ? (stream!.decrypt(chars) ?? "") : chars
                } else {
                    resolved = chars
                }
                if historyDepth == 0, realEntryActive, let k = curKey {
                    entryKV.append((k, resolved, curValueProtected))
                }
            case "CreationTime":
                if historyDepth == 0, parentElement() == "Times", grandparentElement() == "Entry" {
                    entryCreation = Self.parseKdbxTime(chars)
                }
            case "LastModificationTime":
                if historyDepth == 0, parentElement() == "Times", grandparentElement() == "Entry" {
                    entryModified = Self.parseKdbxTime(chars)
                }
            case "String":
                curKey = nil; curValueProtected = false
            case "Binary":
                if historyDepth == 0, realEntryActive, let k = curBinKey, let ref = curBinRef {
                    binAttachments.append((k, ref))
                }
            case "Entry":
                if historyDepth == 0, realEntryActive { emitCipher(); realEntryActive = false }
            case "History":
                historyDepth -= 1
            case "Group":
                let frame = groupStack.removeLast()
                if !frame.isRoot, (!frame.inRecycleBin || frame.isRecycleBinRoot) {
                    let parentId: String? = (groupStack.last?.isRoot ?? true) ? nil : groupStack.last?.id
                    folders.append(VaultFolder(id: frame.id, name: frame.path, revisionDate: nil, parentId: parentId))
                }
            default:
                break
            }
            elementStack.removeLast()
        }

        // MARK: build cipher

        private func emitCipher() {
            var kv: [String: String] = [:]
            for item in entryKV { kv[item.key] = item.value }
            let standard: Set<String> = ["Title", "UserName", "Password", "URL", "Notes",
                                         "otp", "TOTP Seed", "TOTP Settings"]
            let title = kv["Title"] ?? ""
            let username = kv["UserName"]
            let password = kv["Password"]
            let url = kv["URL"]
            let notes = kv["Notes"]
            let totp = kv["otp"] ?? kv["TOTP Seed"]

            let uris: [CipherUri]? = (url?.isEmpty == false) ? [CipherUri(uri: url, match: nil)] : nil
            let login = CipherLogin(username: username, password: password, totp: totp, uris: uris)

            let custom: [CipherField] = entryKV
                .filter { !standard.contains($0.key) }
                .map { CipherField(name: $0.key, value: $0.value, type: $0.prot ? .hidden : .text) }

            let folder = groupStack.last
            let folderId: String? = (folder == nil || folder!.isRoot) ? nil : folder!.id
            let inRB = folder?.inRecycleBin ?? false

            // KeePass binary attachments: id = inner-header binary index (ref); bytes are the
            // referenced binary minus its 1-byte flag prefix.
            let attachments: [CipherAttachment] = binAttachments.map { item in
                let bytes = (item.ref >= 0 && item.ref < binaries.count) ? max(binaries[item.ref].count - 1, 0) : 0
                return CipherAttachment(id: String(item.ref), fileName: item.key,
                                        size: String(bytes), sizeName: Self.humanSize(bytes),
                                        url: nil, key: nil)
            }

            let kpIcon: KeePassIconRef?
            if let u = entryCustomIconUUID, let png = customIcons[u] {
                kpIcon = .custom(png)
            } else if let iid = entryIconId, iid != 0 {
                kpIcon = .standard(iid)
            } else {
                kpIcon = nil
            }

            let cipher = VaultCipher(
                id: entryId.isEmpty ? UUID().uuidString : entryId,
                organizationId: nil, folderId: folderId, collectionIds: nil,
                type: .login, name: title, notes: notes,
                login: login, card: nil, secureNote: nil, identity: nil,
                fields: custom.isEmpty ? nil : custom, attachments: attachments.isEmpty ? nil : attachments,
                favorite: false, reprompt: nil,
                creationDate: entryCreation, revisionDate: entryModified,
                deletedDate: inRB ? Date() : nil,
                keepassIcon: kpIcon)
            ciphers.append(cipher)
        }

        // MARK: helpers

        private static func humanSize(_ bytes: Int) -> String {
            if bytes < 1024 { return "\(bytes) B" }
            let units = ["KB", "MB", "GB"]
            var value = Double(bytes) / 1024
            var i = 0
            while value >= 1024, i < units.count - 1 { value /= 1024; i += 1 }
            return String(format: "%.1f %@", value, units[i])
        }

        private static func hexFromBase64(_ s: String) -> String {
            let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let d = Data(base64Encoded: trimmed) else { return trimmed }
            return d.map { String(format: "%02x", $0) }.joined()
        }

        private static let iso8601 = ISO8601DateFormatter()

        /// Decode a KDBX timestamp. KDBX 4 stores base64 of a little-endian Int64 = seconds since
        /// 0001-01-01 UTC; KDBX 3.1 stores an ISO-8601 string. Returns nil if neither parses.
        private static func parseKdbxTime(_ s: String) -> Date? {
            let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
            if t.isEmpty { return nil }
            if let data = Data(base64Encoded: t), data.count == 8 {
                let bytes = [UInt8](data)
                var secs: Int64 = 0
                for i in 0..<8 { secs |= Int64(bytes[i]) << (8 * i) }
                return Date(timeIntervalSince1970: TimeInterval(secs - 62_135_596_800))
            }
            return iso8601.date(from: t)
        }
    }
}
