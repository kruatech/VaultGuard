import Foundation
import Security

// MARK: - Vault Backend Abstraction
//
// И серверный Bitwarden/Vaultwarden, и локальный KeePass (.kdbx) отдают один и тот же
// `DecryptedVault`. Всё выше backend (публикация vault, фильтры, sidebar, детальные экраны)
// не зависит от источника данных.
//
// `VaultKind` объявлен в `Account.swift` (хранится в `Account.kind`).

/// Ошибки слоя backend, общие для всех источников.
enum VaultBackendError: LocalizedError {
    case notImplemented
    case readOnly
    case fileUnavailable
    case invalidCredentials
    case entryNotFound
    case verifyFailed

    var errorDescription: String? {
        switch self {
        case .notImplemented: return "Backend is not implemented yet"
        case .readOnly: return "This vault is read-only"
        case .fileUnavailable: return "Vault file is unavailable"
        case .invalidCredentials: return "Invalid password or key file"
        case .entryNotFound: return "Entry not found in the database"
        case .verifyFailed: return "Saved file failed verification"
        }
    }
}

/// Абстракция источника данных хранилища (операции чтения).
protocol VaultBackend: AnyObject {
    var kind: VaultKind { get }
    var isReadOnly: Bool { get }
    func load() async throws -> DecryptedVault
    func reload() async throws -> DecryptedVault
}

extension VaultBackend {
    func reload() async throws -> DecryptedVault { try await load() }
}

/// KeePass-бэкенд: держит байты `.kdbx` + учётные данные. На открытии один раз
/// расшифровывает контейнер и строит редактируемый `XMLDocument` (protected-значения в
/// открытом виде). `load()` маппит этот документ в `DecryptedVault`; методы записи правят
/// DOM; `serialize()` пересобирает валидный KDBX 4 (`KDBXWriter`). Запись файла на диск —
/// ответственность `AppState` (он владеет security-scoped bookmark).
final class KeePassBackend: VaultBackend {
    let kind: VaultKind = .keepass
    let isReadOnly: Bool = false

    private let fileData: Data
    /// SHA-256 of the UTF-8 master password — the password's contribution to the KDBX
    /// composite key. The raw password is hashed in `init` and NOT retained: this component
    /// is sufficient for unlock/save/verify and cannot be reversed back to the password.
    private let passwordSHA256: Data?
    private let keyfile: Data?
    private var doc: XMLDocument?   // editable; Protected values hold plaintext
    private var binaries: [Data] = []   // inner-header attachments, passed through verbatim on save
    private var profile: KDBXProfile = .default   // original on-disk format, reproduced on save

    init(fileData: Data, password: String?, keyfile: Data? = nil) {
        self.fileData = fileData
        self.passwordSHA256 = KDBXReader.hashedPasswordComponent(password)
        self.keyfile = keyfile
    }

    /// Init from the pre-hashed password component — used by biometric unlock, which stores
    /// this value instead of the raw master password.
    init(fileData: Data, passwordSHA256: Data?, keyfile: Data? = nil) {
        self.fileData = fileData
        self.passwordSHA256 = passwordSHA256
        self.keyfile = keyfile
    }

    // MARK: Read

    func load() async throws -> DecryptedVault {
        let document = try editableDocument()
        return KDBXVaultMapper.map(xml: document.xmlData, stream: nil, binaries: binaries)
    }

    /// Build a fresh KDBX 4 file from the current document (re-encrypts Protected values).
    /// Build a fresh KDBX file from the current document, reproducing the original format
    /// profile (version / cipher / KDF) and attachments. `profileOverride` lets tests force a
    /// light KDF; production passes nil to preserve the file's own profile.
    func serialize(profileOverride: KDBXProfile? = nil) throws -> Data {
        let document = try editableDocument()
        return try KDBXWriter.build(plaintextXML: document, passwordSHA256: passwordSHA256, keyfile: keyfile,
                                    profile: profileOverride ?? profile, binaries: binaries)
    }

    /// Verify a freshly serialized (or just-written) file actually opens with our credentials
    /// and contains exactly the entries we currently hold. Throws `verifyFailed` on any mismatch.
    /// Used by the save path to guarantee we never replace a good file with a broken one.
    func verifyRoundTrip(_ data: Data) throws {
        let db = try KDBXReader.unlock(data: data, passwordSHA256: passwordSHA256, keyfile: keyfile)
        guard let stream = KDBXProtectedStream(streamID: db.innerStreamID, key: db.innerStreamKey) else {
            throw KDBXError.badInnerStream
        }
        guard db.binaries.count == binaries.count else { throw VaultBackendError.verifyFailed }
        let vault = KDBXVaultMapper.map(xml: db.xml, stream: stream)
        let produced = Set(vault.ciphers.map { $0.id })
        let expected = try currentEntryIds()
        guard produced == expected else { throw VaultBackendError.verifyFailed }
    }

    /// Features in the current document that the writer would NOT preserve on save (today:
    /// binary attachments). Empty means saving is lossless. The save path refuses to write
    /// when this is non-empty, so an edit never silently destroys data.
    func lossyFeaturesOnSave() throws -> [String] {
        KDBXEditor.lossyFeatures(in: try editableDocument())
    }

    private func currentEntryIds() throws -> Set<String> {
        let document = try editableDocument()
        var ids = Set<String>()
        for node in try document.nodes(forXPath: "//Entry[not(ancestor::History)]") {
            if let e = node as? XMLElement, let id = elementUUIDHex(e) { ids.insert(id) }
        }
        return ids
    }

    // MARK: Write (DOM edits)

    func updateCipher(_ cipher: VaultCipher) throws {
        let document = try editableDocument()
        guard let entry = try findEntry(byId: cipher.id, in: document) else {
            throw VaultBackendError.entryNotFound
        }
        pushHistory(entry)                 // snapshot the pre-edit state into <History>
        setStrings(entry, from: cipher)
        try applyIcon(entry, from: cipher, in: document)
        touchModified(entry)               // bump LastModification/LastAccess times
    }

    /// Add a new entry; returns the cipher with its assigned id (the new entry UUID, hex).
    @discardableResult
    func addCipher(_ cipher: VaultCipher) throws -> VaultCipher {
        let document = try editableDocument()
        guard let group = try findGroup(byId: cipher.folderId, in: document) ?? rootGroup(document) else {
            throw VaultBackendError.fileUnavailable
        }
        let uuid = try randomBytes(16)
        let entry = XMLElement(name: "Entry")
        entry.addChild(XMLElement(name: "UUID", stringValue: uuid.base64EncodedString()))
        entry.addChild(makeTimesNow())
        group.addChild(entry)

        var stored = cipher
        stored.id = uuid.map { String(format: "%02x", $0) }.joined()
        setStrings(entry, from: stored)
        try applyIcon(entry, from: stored, in: document)
        return stored
    }

    /// Delete an entry: move it to the Recycle Bin (if enabled and not already there),
    /// otherwise remove it permanently. Mirrors KeePass behaviour.
    func deleteCipher(id: String) throws {
        let document = try editableDocument()
        guard let entry = try findEntry(byId: id, in: document) else { return }
        try recycleOrPurge(entry, in: document)
    }

    /// Restore an entry out of the Recycle Bin back to the root group.
    func restoreCipher(id: String) throws {
        let document = try editableDocument()
        guard let entry = try findEntry(byId: id, in: document),
              let root = rootGroup(document) else { throw VaultBackendError.entryNotFound }
        entry.detach()
        root.addChild(entry)
        touchLocationChanged(entry)
    }

    /// Permanently remove an entry regardless of Recycle Bin state.
    func permanentlyDeleteCipher(id: String) throws {
        let document = try editableDocument()
        guard let entry = try findEntry(byId: id, in: document),
              let parent = entry.parent as? XMLElement else { return }
        parent.removeChild(at: entry.index)
    }

    // MARK: Write (groups)

    /// Create a group from a "/"-separated path, creating or reusing intermediate groups.
    /// Returns the leaf folder (id = leaf group UUID, name = the full path). A name without
    /// "/" creates a single top-level group, as before.
    @discardableResult
    func addFolder(name: String) throws -> VaultFolder {
        let document = try editableDocument()
        guard let root = rootGroup(document) else { throw VaultBackendError.fileUnavailable }
        let segments = name.split(separator: "/")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard !segments.isEmpty else { throw VaultBackendError.fileUnavailable }

        var parent = root
        var leafUUIDHex = ""
        for segment in segments {
            if let existing = childGroup(named: segment, in: parent) {
                parent = existing
                leafUUIDHex = elementUUIDHex(existing) ?? ""
            } else {
                let uuid = try randomBytes(16)
                let group = XMLElement(name: "Group")
                group.addChild(XMLElement(name: "UUID", stringValue: uuid.base64EncodedString()))
                group.addChild(XMLElement(name: "Name", stringValue: segment))
                parent.addChild(group)
                parent = group
                leafUUIDHex = uuid.map { String(format: "%02x", $0) }.joined()
            }
        }
        return VaultFolder(id: leafUUIDHex, name: segments.joined(separator: "/"), revisionDate: nil)
    }

    /// Direct child `<Group>` of `parent` whose `<Name>` matches, if any.
    private func childGroup(named name: String, in parent: XMLElement) -> XMLElement? {
        for child in parent.elements(forName: "Group")
        where child.elements(forName: "Name").first?.stringValue == name {
            return child
        }
        return nil
    }

    func renameFolder(id: String, newName: String) throws {
        let document = try editableDocument()
        guard let group = try findGroup(byId: id, in: document) else { throw VaultBackendError.entryNotFound }
        if let nameEl = group.elements(forName: "Name").first {
            nameEl.stringValue = newName
        } else {
            group.insertChild(XMLElement(name: "Name", stringValue: newName), at: min(1, group.childCount))
        }
    }

    /// Delete a group: move it (with its entries/subgroups) to the Recycle Bin if enabled and
    /// not already there, otherwise remove it permanently. Mirrors KeePass's "delete group".
    func deleteFolder(id: String) throws {
        let document = try editableDocument()
        guard let group = try findGroup(byId: id, in: document) else { throw VaultBackendError.entryNotFound }
        try recycleOrPurge(group, in: document)
    }

    /// Move an entry to another group (folderId == nil → root group).
    func moveCipher(id: String, toFolderId folderId: String?) throws {
        let document = try editableDocument()
        guard let entry = try findEntry(byId: id, in: document) else { throw VaultBackendError.entryNotFound }
        let target = (folderId == nil) ? rootGroup(document) : try findGroup(byId: folderId, in: document)
        guard let dest = target else { throw VaultBackendError.fileUnavailable }
        entry.detach()
        dest.addChild(entry)
    }

    // MARK: Write (attachments)

    /// Attach a file: append it to the inner-header binary pool and add a `<Binary>` reference
    /// to the entry. Returns the new attachment (id = binary index).
    @discardableResult
    func addAttachment(cipherId: String, fileName: String, data: Data) throws -> CipherAttachment {
        let document = try editableDocument()
        guard let entry = try findEntry(byId: cipherId, in: document) else { throw VaultBackendError.entryNotFound }
        let ref = binaries.count
        binaries.append(Data([0x01]) + data)            // inner-header item: [flags:1][data:N]
        let bin = XMLElement(name: "Binary")
        bin.addChild(XMLElement(name: "Key", stringValue: fileName))
        let value = XMLElement(name: "Value")
        if let attr = XMLNode.attribute(withName: "Ref", stringValue: String(ref)) as? XMLNode {
            value.addAttribute(attr)
        }
        bin.addChild(value)
        if let history = entry.elements(forName: "History").first {
            entry.insertChild(bin, at: history.index)   // keep <History> last
        } else {
            entry.addChild(bin)
        }
        return CipherAttachment(id: String(ref), fileName: fileName, size: String(data.count),
                                sizeName: nil, url: nil, key: nil)
    }

    /// Remove an entry's reference to a binary (by ref index). The binary stays in the pool so
    /// other references keep their indices (an orphaned binary is harmless).
    func removeAttachment(cipherId: String, ref: Int) throws {
        let document = try editableDocument()
        guard let entry = try findEntry(byId: cipherId, in: document) else { throw VaultBackendError.entryNotFound }
        for bin in entry.elements(forName: "Binary") {
            if let v = bin.elements(forName: "Value").first,
               let r = v.attribute(forName: "Ref")?.stringValue, Int(r) == ref {
                entry.removeChild(at: bin.index)
                return
            }
        }
    }

    /// Raw file bytes for a binary reference (strips the 1-byte memory-protection flag).
    func attachmentData(ref: Int) -> Data? {
        guard ref >= 0, ref < binaries.count else { return nil }
        return Data(binaries[ref].dropFirst())
    }

    // MARK: DOM helpers

    private func editableDocument() throws -> XMLDocument {
        if let doc { return doc }
        let db = try KDBXReader.unlock(data: fileData, passwordSHA256: passwordSHA256, keyfile: keyfile)
        guard let stream = KDBXProtectedStream(streamID: db.innerStreamID, key: db.innerStreamKey) else {
            throw KDBXError.badInnerStream
        }
        let d = try KDBXEditor.makeEditable(xml: db.xml, stream: stream)
        binaries = db.binaries
        profile = db.profile
        doc = d
        return d
    }

    /// Rebuild an entry's `<String>` children from the cipher. KeePass-specific children
    /// (UUID, Times, History, …) are left untouched. New strings are inserted before any
    /// `<History>` (else appended).
    private func setStrings(_ entry: XMLElement, from c: VaultCipher) {
        for s in entry.elements(forName: "String").reversed() {
            entry.removeChild(at: s.index)
        }
        var newStrings: [XMLElement] = []
        func mk(_ key: String, _ value: String?, _ protected: Bool) {
            guard let value else { return }
            let s = XMLElement(name: "String")
            s.addChild(XMLElement(name: "Key", stringValue: key))
            let v = XMLElement(name: "Value", stringValue: value)
            if protected, let attr = XMLNode.attribute(withName: "Protected", stringValue: "True") as? XMLNode {
                v.addAttribute(attr)
            }
            s.addChild(v)
            newStrings.append(s)
        }
        mk("Title", c.name, false)
        mk("UserName", c.login?.username, false)
        mk("Password", c.login?.password, true)
        mk("URL", c.login?.uris?.first?.uri, false)
        mk("Notes", c.notes, false)
        if let totp = c.login?.totp, !totp.isEmpty { mk("otp", totp, true) }
        for f in c.fields ?? [] { mk(f.name, f.value, f.type == .hidden) }

        if let historyIndex = entry.elements(forName: "History").first?.index {
            var at = historyIndex
            for s in newStrings { entry.insertChild(s, at: at); at += 1 }
        } else {
            for s in newStrings { entry.addChild(s) }
        }
    }

    // MARK: Icon helpers

    /// Write the cipher's KeePass icon into the entry. `.standard` sets `<IconID>` (and clears any
    /// `<CustomIconUUID>`); `.custom` registers the PNG in `<Meta><CustomIcons>` (reusing an identical
    /// image if already present) and points the entry at it; `nil` leaves the existing icon untouched.
    private func applyIcon(_ entry: XMLElement, from cipher: VaultCipher, in doc: XMLDocument) throws {
        guard let icon = cipher.keepassIcon else { return }
        switch icon {
        case .standard(let idx):
            setEntryChild(entry, "IconID", String(idx))
            removeEntryChild(entry, "CustomIconUUID")
        case .custom(let data):
            let uuidB64 = try customIconUUID(forData: data, in: doc)
            setEntryChild(entry, "CustomIconUUID", uuidB64)
        }
    }

    /// Set a direct child of `<Entry>` (not History descendants), inserting right after `<UUID>`.
    private func setEntryChild(_ entry: XMLElement, _ name: String, _ value: String) {
        if let c = entry.elements(forName: name).first { c.stringValue = value; return }
        let at = (entry.elements(forName: "UUID").first?.index).map { $0 + 1 } ?? 0
        entry.insertChild(XMLElement(name: name, stringValue: value), at: at)
    }

    private func removeEntryChild(_ entry: XMLElement, _ name: String) {
        for c in entry.elements(forName: name).reversed() { entry.removeChild(at: c.index) }
    }

    /// Base64 UUID of a custom icon in `<Meta><CustomIcons>`, reusing an identical image if present,
    /// otherwise creating a new `<Icon><UUID/><Data/></Icon>`. UUID/Data are base64, matching the reader.
    private func customIconUUID(forData data: Data, in doc: XMLDocument) throws -> String {
        let meta = (try? doc.nodes(forXPath: "//Meta").first) as? XMLElement
        let b64 = data.base64EncodedString()
        if let icons = meta?.elements(forName: "CustomIcons").first {
            for icon in icons.elements(forName: "Icon")
            where icon.elements(forName: "Data").first?.stringValue == b64 {
                if let u = icon.elements(forName: "UUID").first?.stringValue { return u }
            }
        }
        let uuidB64 = try randomBytes(16).base64EncodedString()
        let iconEl = XMLElement(name: "Icon")
        iconEl.addChild(XMLElement(name: "UUID", stringValue: uuidB64))
        iconEl.addChild(XMLElement(name: "Data", stringValue: b64))
        if let meta {
            let icons = meta.elements(forName: "CustomIcons").first ?? {
                let c = XMLElement(name: "CustomIcons"); meta.addChild(c); return c
            }()
            icons.addChild(iconEl)
        }
        return uuidB64
    }

    // MARK: Times & history helpers

    /// KDBX 4 timestamp: base64 of a little-endian Int64 = seconds since 0001-01-01 00:00:00 UTC.
    private static let secondsFrom0001To1970: Int64 = 62_135_596_800
    static func kdbxTimeString(_ date: Date = Date()) -> String {
        var le = (Int64(date.timeIntervalSince1970) + secondsFrom0001To1970).littleEndian
        return withUnsafeBytes(of: &le) { Data($0) }.base64EncodedString()
    }

    /// A fresh `<Times>` block (all timestamps = now) for a newly created entry.
    private func makeTimesNow() -> XMLElement {
        let now = Self.kdbxTimeString()
        let t = XMLElement(name: "Times")
        for n in ["CreationTime", "LastModificationTime", "LastAccessTime", "ExpiryTime", "LocationChanged"] {
            t.addChild(XMLElement(name: n, stringValue: now))
        }
        t.addChild(XMLElement(name: "Expires", stringValue: "False"))
        t.addChild(XMLElement(name: "UsageCount", stringValue: "0"))
        return t
    }

    /// Bump LastModificationTime / LastAccessTime on an edited entry (creating `<Times>` if absent).
    private func touchModified(_ entry: XMLElement) {
        let now = Self.kdbxTimeString()
        let times = entry.elements(forName: "Times").first ?? {
            let t = XMLElement(name: "Times"); entry.addChild(t); return t
        }()
        for name in ["LastModificationTime", "LastAccessTime"] {
            if let c = times.elements(forName: name).first { c.stringValue = now }
            else { times.addChild(XMLElement(name: name, stringValue: now)) }
        }
    }

    /// Snapshot the entry's current state into its `<History>` before an edit (KeePass behaviour),
    /// then prune to the most recent 10 (matching KeePass's default MaxHistoryItems).
    private func pushHistory(_ entry: XMLElement) {
        guard let snapshot = entry.copy() as? XMLElement else { return }
        for h in snapshot.elements(forName: "History").reversed() { snapshot.removeChild(at: h.index) }
        let history = entry.elements(forName: "History").first ?? {
            let h = XMLElement(name: "History"); entry.addChild(h); return h
        }()
        history.addChild(snapshot)
        let items = history.elements(forName: "Entry")
        if items.count > 10 {
            for e in items.prefix(items.count - 10).sorted(by: { $0.index > $1.index }) {
                history.removeChild(at: e.index)
            }
        }
    }

    // MARK: Recycle Bin helpers

    /// Move a node (entry or group) to the Recycle Bin, or remove it permanently when the bin
    /// is disabled or the node is already inside it.
    private func recycleOrPurge(_ node: XMLElement, in doc: XMLDocument) throws {
        guard let parent = node.parent as? XMLElement else { return }
        let existingRB = recycleBinUUIDHex(doc)
        let alreadyInRB = existingRB.map { isInside(node, rbHex: $0) || elementUUIDHex(node) == $0 } ?? false
        if recycleBinEnabled(doc), !alreadyInRB, let rb = try getOrCreateRecycleBin(doc) {
            node.detach()
            rb.addChild(node)
            touchLocationChanged(node)
        } else {
            parent.removeChild(at: node.index)   // permanent: bin disabled, or already in the bin
        }
    }

    private func isInside(_ node: XMLElement, rbHex: String) -> Bool {
        var cur = node.parent
        while let el = cur as? XMLElement {
            if el.name == "Group", elementUUIDHex(el) == rbHex { return true }
            cur = el.parent
        }
        return false
    }

    private func recycleBinEnabled(_ doc: XMLDocument) -> Bool {
        guard let v = (try? doc.nodes(forXPath: "//Meta/RecycleBinEnabled").first as? XMLElement)?.stringValue
        else { return true }   // KeePass default when absent
        return v.lowercased() != "false"
    }

    /// Hex UUID of the existing Recycle Bin group, or nil if none (absent or all-zero UUID).
    private func recycleBinUUIDHex(_ doc: XMLDocument) -> String? {
        guard let b64 = (try? doc.nodes(forXPath: "//Meta/RecycleBinUUID").first as? XMLElement)?.stringValue,
              let data = Data(base64Encoded: b64), data.contains(where: { $0 != 0 }) else { return nil }
        return data.map { String(format: "%02x", $0) }.joined()
    }

    private func getOrCreateRecycleBin(_ doc: XMLDocument) throws -> XMLElement? {
        if let hex = recycleBinUUIDHex(doc), let g = try findGroup(byId: hex, in: doc) { return g }
        guard let root = rootGroup(doc) else { return nil }
        let uuid = try randomBytes(16)
        let rb = XMLElement(name: "Group")
        rb.addChild(XMLElement(name: "UUID", stringValue: uuid.base64EncodedString()))
        rb.addChild(XMLElement(name: "Name", stringValue: "Recycle Bin"))
        rb.addChild(makeTimesNow())
        root.addChild(rb)
        setMetaRecycleBin(doc, uuidB64: uuid.base64EncodedString())
        return rb
    }

    private func setMetaRecycleBin(_ doc: XMLDocument, uuidB64: String) {
        guard let meta = (try? doc.nodes(forXPath: "//Meta").first) as? XMLElement else { return }
        setOrAddChild(meta, "RecycleBinEnabled", "True")
        setOrAddChild(meta, "RecycleBinUUID", uuidB64)
        setOrAddChild(meta, "RecycleBinChanged", Self.kdbxTimeString())
    }

    private func touchLocationChanged(_ node: XMLElement) {
        let times = node.elements(forName: "Times").first ?? {
            let t = XMLElement(name: "Times"); node.addChild(t); return t
        }()
        setOrAddChild(times, "LocationChanged", Self.kdbxTimeString())
    }

    private func setOrAddChild(_ parent: XMLElement, _ name: String, _ value: String) {
        if let c = parent.elements(forName: name).first { c.stringValue = value }
        else { parent.addChild(XMLElement(name: name, stringValue: value)) }
    }

    private func findEntry(byId id: String, in doc: XMLDocument) throws -> XMLElement? {
        for node in try doc.nodes(forXPath: "//Entry[not(ancestor::History)]") {
            guard let e = node as? XMLElement else { continue }
            if elementUUIDHex(e) == id { return e }
        }
        return nil
    }

    private func findGroup(byId id: String?, in doc: XMLDocument) throws -> XMLElement? {
        guard let id else { return nil }
        for node in try doc.nodes(forXPath: "//Group") {
            guard let g = node as? XMLElement else { continue }
            if elementUUIDHex(g) == id { return g }
        }
        return nil
    }

    private func rootGroup(_ doc: XMLDocument) -> XMLElement? {
        (try? doc.nodes(forXPath: "//Root/Group").first) as? XMLElement
    }

    private func elementUUIDHex(_ e: XMLElement) -> String? {
        guard let b64 = e.elements(forName: "UUID").first?.stringValue,
              let data = Data(base64Encoded: b64.trimmingCharacters(in: .whitespacesAndNewlines)) else { return nil }
        return data.map { String(format: "%02x", $0) }.joined()
    }

    /// Cryptographically secure random bytes. Fails hard (no weak fallback) — used for new
    /// entry UUIDs, which must be unique and unpredictable.
    private func randomBytes(_ n: Int) throws -> Data {
        var d = Data(count: n)
        let ok = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) }
        guard ok == errSecSuccess else { throw KDBXError.randomGenerationFailed }
        return d
    }
}
