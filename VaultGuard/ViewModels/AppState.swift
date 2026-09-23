import Foundation
import SwiftUI
import Combine

// `VaultFilter` and `VaultSort` live in `Services/VaultListPipeline.swift`, next to the
// pipeline that consumes them, so the unit-test target can build them without this file.

enum AppTheme: String, CaseIterable {
    case system, light, dark
    var displayName: String {
        switch self {
        case .system: return L10n.Settings.themeSystem.localized
        case .light: return L10n.Settings.themeLight.localized
        case .dark: return L10n.Settings.themeDark.localized
        }
    }
    var appearance: NSAppearance? {
        switch self { case .system: return nil; case .light: return NSAppearance(named: .aqua); case .dark: return NSAppearance(named: .darkAqua) }
    }
}

struct ToastMessage: Identifiable {
    let id = UUID(); let text: String; let icon: String
    static func copied() -> ToastMessage { .init(text: L10n.copied.localized, icon: "checkmark") }
    static func saved() -> ToastMessage { .init(text: L10n.saved.localized, icon: "checkmark") }
    static func deleted() -> ToastMessage { .init(text: L10n.deleted.localized, icon: "trash") }
    static func error(_ msg: String) -> ToastMessage { .init(text: msg, icon: "xmark.circle") }
    static func info(_ msg: String) -> ToastMessage { .init(text: msg, icon: "info.circle") }
}

/// A pending master-password reprompt for a reprompt-protected item.
struct RepromptRequest: Identifiable {
    let id = UUID()
    let cipherId: String
    let cipherName: String
    let onVerified: () -> Void
}

// MARK: - App State

@MainActor
final class AppState: ObservableObject {
    @Published var isUnlocked = false
    @Published var isLoading = false
    @Published var errorMessage: String?

    // Data
    @Published var ciphers: [VaultCipher] = [] { didSet { rebuildSearchIndex(); recomputeDerived() } }
    @Published var folders: [VaultFolder] = []
    @Published var collections: [VaultCollection] = []
    @Published var organizations: [VaultOrganization] = []
    @Published var profileName = ""
    @Published var profileEmail = ""

    // Vault switching
    @Published var activeVaultId: String? = nil { didSet { recomputeDerived() } }

    // Filters
    @Published var filter: VaultFilter = .all { didSet { recomputeDerived() } }
    @Published var sort: VaultSort = .name { didSet { recomputeDerived() } }
    @Published var searchText = "" { didSet { recomputeDerived() } }
    /// The list's selection. A set because the list allows picking several rows; the bulk
    /// actions operate on exactly this.
    @Published var selectedCipherIds: Set<String> = []

    /// The single selected item, when there is exactly one.
    ///
    /// Kept as the name the rest of the app already uses — the detail view, keyboard
    /// navigation, and every "deselect what I just deleted" line read and write this. Reading
    /// it with a multi-selection gives nil, which is what those call sites want: there is no
    /// one item to show or to copy from.
    var selectedCipherId: String? {
        get { selectedCipherIds.count == 1 ? selectedCipherIds.first : nil }
        set { selectedCipherIds = newValue.map { [$0] } ?? [] }
    }

    /// Selected items in the order they appear in the list, skipping ids that no longer exist.
    var selectedCiphers: [VaultCipher] {
        filteredCiphers.filter { selectedCipherIds.contains($0.id) }
    }

    /// True once more than one row is picked — the point at which the UI switches from
    /// showing an item to offering actions over a group.
    var hasMultipleSelection: Bool { selectedCipherIds.count > 1 }
    @Published var pendingReprompt: RepromptRequest?
    var repromptVerifiedCipherIds: Set<String> = []

    /// The last secret placed on the pasteboard by `copyToClipboard`, so `lock()` can take it
    /// back off. Not a `@Published` — no view shows it.
    var lastCopiedValue: String?

    // Sheets
    @Published var showEditSheet = false
    @Published var editingCipher: VaultCipher?
    // Prefill hints applied to a freshly created item (derived from the current filter).
    var newItemPrefillType: CipherType? = nil
    var newItemPrefillFolderId: String? = nil
    var newItemPrefillFavorite: Bool = false

    /// Opens the editor for a new item, prefilling type/folder/favorite from the current section.
    func startNewItem() {
        newItemPrefillType = nil
        newItemPrefillFolderId = nil
        newItemPrefillFavorite = false
        switch filter {
        case .type(let t): newItemPrefillType = t
        case .folder(let id): newItemPrefillFolderId = id
        case .favorites: newItemPrefillFavorite = true
        case .all, .recent, .trash, .collection: break
        }
        editingCipher = nil
        showEditSheet = true
    }
    @Published var showDeleteConfirm = false
    @Published var deletingCipher: VaultCipher?
    @Published var showBulkDeleteConfirm = false
    @Published var showGenerator = false
    @Published var showPasswordHealth = false
    @Published var showSends = false
    @Published var showAddAccount = false
    @Published var toasts: [ToastMessage] = []
    @Published var sends: [SendSummary] = []

    // 2FA
    @Published var show2FA = false
    @Published var twoFactorCode = ""
    @Published var twoFactorRememberDevice = false
    @Published var pending2FALogin: PendingLogin?

    // Self-signed certificate trust prompt (fingerprint pinning)
    @Published var showCertTrust = false
    @Published var pendingCertTrust: PendingCertTrust?
    let certTrust = CertTrustStore.shared

    // Folder management
    @Published var showCreateFolder = false
    @Published var showRenameFolder = false
    @Published var renamingFolder: VaultFolder?
    @Published var folderInputName = ""
    @Published var showDeleteFolderConfirm = false
    @Published var deletingFolder: VaultFolder?

    // Folder sort order (stored locally per-account, server doesn't support ordering)
    @Published var folderOrder: [String] = [] {
        didSet { UserDefaults.standard.set(folderOrder, forKey: folderOrderKey) }
    }
    @Published var folderSortMode: FolderSortMode = .alphabetical {
        didSet { UserDefaults.standard.set(folderSortMode.rawValue, forKey: "folderSortMode") }
    }

    // MARK: - Password templates
    @Published var passwordTemplates: [PasswordTemplate] = [] {
        didSet {
            if let data = try? JSONEncoder().encode(passwordTemplates) {
                UserDefaults.standard.set(data, forKey: "passwordTemplates")
            }
        }
    }
    /// Last-selected generator preset; nil = built-in default generator.
    @Published var lastTemplateId: String? = nil {
        didSet {
            if let id = lastTemplateId { UserDefaults.standard.set(id, forKey: "lastTemplateId") }
            else { UserDefaults.standard.removeObject(forKey: "lastTemplateId") }
        }
    }

    /// Look up a template by id.
    func template(id: String?) -> PasswordTemplate? {
        guard let id = id else { return nil }
        return passwordTemplates.first { $0.id == id }
    }

    /// Generate a password using the last-selected template, or the default generator.
    func generateFromLastTemplate() -> String {
        if let t = template(id: lastTemplateId) {
            return CryptoService.generate(from: t)
        }
        return CryptoService.generatePassword()
    }

    func addTemplate(_ t: PasswordTemplate) {
        let s = t.sanitized()
        passwordTemplates.append(s)
        lastTemplateId = s.id
    }
    func updateTemplate(_ t: PasswordTemplate) {
        guard let idx = passwordTemplates.firstIndex(where: { $0.id == t.id }) else { return }
        passwordTemplates[idx] = t.sanitized()
    }
    func deleteTemplate(_ id: String) {
        passwordTemplates.removeAll { $0.id == id }
        if lastTemplateId == id { lastTemplateId = nil }
    }

    /// Create a custom copy of any template (used to "duplicate as custom"). Returns the new id.
    @discardableResult
    func duplicateAsCustom(_ t: PasswordTemplate, name: String) -> String {
        var copy = t
        copy.id = UUID().uuidString
        copy.name = name
        copy.builtinKey = nil
        copy.icon = nil
        addTemplate(copy)   // also selects it
        return copy.id
    }

    // MARK: - Recently used

    /// The "recently used" list. Logic lives in `RecentCiphersStore`; this holds the value
    /// and keeps it on disk.
    @Published private(set) var recent = RecentCiphersStore()

    /// Note that an item was used. Called where the user copies something out of a specific
    /// entry — opening one to look at it is not the same as using it.
    func recordCipherUsed(_ cipherId: String) {
        recent.record(cipherId)
        recent.save(for: accounts.activeAccountId)
        recomputeDerived()
    }

    /// Reload the list for the active account. Same reason as the folder order: the key is
    /// derived from the account id, so it has to be re-read after a switch.
    func reloadRecentForActiveAccount() {
        recent = RecentCiphersStore(loadingFor: accounts.activeAccountId)
        recomputeDerived()
    }

    /// Remove the per-account preferences kept in `UserDefaults` — the manual folder order and
    /// the recently-used list — for an account that is being signed out of or removed.
    ///
    /// Both used to outlive the account. "Log out and delete all local data" promises to remove
    /// local metadata, and these are local metadata: item and folder ids that say which entries
    /// exist and which were used. They are keyed by account id, so they would also have been
    /// inherited by a later account that happened to reuse it.
    func forgetAccountPreferences(_ accountId: String) {
        UserDefaults.standard.removeObject(forKey: "folderOrder.\(accountId)")
        clearRecent(accountId: accountId)
    }

    /// Drop the list for an account being removed, so a later account reusing the id does not
    /// inherit it.
    func clearRecent(accountId: String) {
        RecentCiphersStore.clear(for: accountId)
        if accounts.activeAccountId == accountId { recent = RecentCiphersStore() }
    }

    /// Per-account UserDefaults key for the manual folder order. Uses a neutral key when
    /// there's no active account yet.
    private var folderOrderKey: String {
        accounts.activeAccountId.map { "folderOrder.\($0)" } ?? "folderOrder"
    }

    // Attachment upload progress
    @Published var isUploadingAttachments = false
    @Published var attachmentUploadProgress: Double = 0

    // Progress for any long run of per-item work — an import, or a bulk action over a
    // selection. `isLoading` alone just froze the window: a thousand-item import creates each
    // entry over the network one at a time, and the user had a motionless spinner with no way
    // to tell progress from a hang.
    @Published var isBatchRunning = false
    @Published var batchDone = 0
    @Published var batchTotal = 0

    /// 0...1 for a determinate ProgressView; 0 while the total is unknown.
    var batchProgress: Double {
        batchTotal > 0 ? Double(batchDone) / Double(batchTotal) : 0
    }

    func beginBatch(total: Int) {
        batchTotal = total; batchDone = 0; isBatchRunning = total > 0
    }
    func advanceBatch() { batchDone += 1 }
    func endBatch() { isBatchRunning = false; batchDone = 0; batchTotal = 0 }

    private(set) var api = APIService()
    private(set) var crypto = CryptoService()
    let keychain = KeychainService.shared
    let accounts = AccountManager()
    var lastActivityDate = Date()
    var autoLockTimer: Timer?
    var sleepObservers: [NSObjectProtocol] = []

    /// In-memory backend for the active KeePass session (holds file bytes + credentials so the
    /// vault can be re-read while unlocked). Created in `openKeePass`, cleared in `lock()`.
    /// nil for server (Bitwarden) accounts.
    var keePassBackend: KeePassBackend?

    /// True once the "this file was upgraded from KDBX 3" notice has been shown for the current
    /// KeePass session. Reset in `lock()` along with the backend, so reopening the file warns
    /// again rather than staying silent forever.
    var keePassUpgradeNoticeShown = false

    /// The KeePass save currently in progress, if any. Each save waits for the one before it;
    /// see `writeKeePassToDisk` for why they must not overlap.
    var keePassSaveChain: Task<Void, Error>?

    /// Security-scoped bookmark to the active KeePass .kdbx, kept in memory so the file can be
    /// written back during this session (even when biometric persistence wasn't requested).
    var keePassFileBookmark: Data?

    struct PendingLogin {
        let serverURL: String; let email: String; let passwordHash: String
        let saveBiometric: Bool; let password: String
        let kdf: Int; let kdfIterations: Int; let kdfMemory: Int?; let kdfParallelism: Int?
        let encryptedKey: String?
        var label: String?
        var providers: [Int] = [0]
    }

    /// A self-signed certificate awaiting the user's trust decision, plus the login context
    /// to retry once trusted.
    struct PendingCertTrust {
        let host: String
        let fingerprint: String
        /// true when a previously-trusted certificate for this host changed (stronger warning).
        let changed: Bool
        let serverURL: String
        let email: String
        let password: String
        let saveBiometric: Bool
        let allowSelfSigned: Bool
        let label: String?
    }

    enum FolderSortMode: String { case alphabetical, manual }

    init() {
        // Load this account's manual folder order.
        if let saved = UserDefaults.standard.stringArray(forKey: folderOrderKey) {
            folderOrder = saved
        } else {
            folderOrder = []
        }
        folderSortMode = FolderSortMode(rawValue: UserDefaults.standard.string(forKey: "folderSortMode") ?? "alphabetical") ?? .alphabetical

        // Load all templates as-is; every template is editable/deletable (no read-only built-ins).
        if let data = UserDefaults.standard.data(forKey: "passwordTemplates") {
            if let arr = try? JSONDecoder().decode([PasswordTemplate].self, from: data) {
                passwordTemplates = arr
            } else {
                // Same shape as the account-index hazard, with far less at stake: the next
                // save replaces templates that only failed to decode. They are generator
                // presets the user can recreate, so this is logged rather than guarded —
                // but silently is the one way it must not happen.
                passwordTemplates = []
                Log.fault("password templates could not be decoded — they will be replaced on the next save")
            }
        } else {
            passwordTemplates = []
        }
        // One-time: fold the starter presets into the editable list so they appear by default
        // but can be renamed / updated / deleted like any other. Dedupe by stable id.
        if !UserDefaults.standard.bool(forKey: "templatesSeededV2") {
            let existing = Set(passwordTemplates.map { $0.id })
            let seeds = PasswordTemplate.builtins.filter { !existing.contains($0.id) }
            passwordTemplates = seeds + passwordTemplates
            UserDefaults.standard.set(true, forKey: "templatesSeededV2")
        }
        lastTemplateId = UserDefaults.standard.string(forKey: "lastTemplateId")
        recomputeDerived()
    }


    /// Reload the manual folder order for the currently active account. Call after the
    /// active account changes (login / unlock / switch) and before applying a sync.
    func reloadFolderOrderForActiveAccount() {
        folderOrder = UserDefaults.standard.stringArray(forKey: folderOrderKey) ?? []
    }

    // MARK: - Active Account Session

    /// Keychain scope for the currently active account, if any.
    var activeStore: KeychainAccountStore? {
        accounts.activeAccountId.map { keychain.account($0) }
    }

    /// Encrypted offline cache for the currently active account, if any.
    var activeCache: VaultCache? {
        accounts.activeAccountId.map { VaultCache.forAccount($0) }
    }

    /// Replace the crypto session with a fresh instance. We replace rather than wipe in
    /// place: if a background decrypt still holds the previous CryptoService, it stays valid
    /// until that task completes, after which the old instance is deallocated and
    /// SecureBytes.deinit zeroes the key material. This removes the clearKeys()-vs-decrypt
    /// data race without locking the crypto hot path.
    func wipeCryptoSession() {
        crypto = CryptoService()
    }

    /// Install a session whose keys were derived elsewhere — off the main actor, into an
    /// instance nothing else held. The counterpart of `wipeCryptoSession`: both replace the
    /// instance rather than mutate it, which is what keeps a decrypt already running on a
    /// detached task working with the keys it started with.
    func installCryptoSession(_ session: CryptoService) {
        crypto = session
    }

    /// Tear down the in-memory crypto/network session and start fresh ones. Used before a
    /// new login and when switching accounts, so no key material or token survives the swap.
    func rebuildActiveSession() {
        wipeCryptoSession()
        api = APIService()
    }

    /// Select an account to unlock without unlocking it yet (used by the lock screen's
    /// account switcher). Resets the session so a previous account's keys never linger.
    func selectAccount(_ id: String) {
        guard accounts.contains(id), id != accounts.activeAccountId else { return }
        rebuildActiveSession()
        accounts.setActive(id)
        // Same reason as in switchAccount: the persisted folder order is keyed by account id.
        reloadFolderOrderForActiveAccount()
        reloadRecentForActiveAccount()
    }

    // MARK: - Computed: Active Vault

    var activeVaultName: String {
        if let orgId = activeVaultId {
            return organizations.first { $0.id == orgId }?.name ?? L10n.Sidebar.organization.localized
        }
        return L10n.Sidebar.myVault.localized
    }

    var isPersonalVault: Bool { activeVaultId == nil }

    var vaultCiphers: [VaultCipher] {
        if let orgId = activeVaultId {
            return ciphers.filter { $0.organizationId == orgId }
        }
        return ciphers.filter { $0.organizationId == nil || $0.organizationId?.isEmpty == true }
    }

    var activeFolders: [VaultFolder] {
        guard isPersonalVault else { return [] }
        switch folderSortMode {
        case .alphabetical:
            return folders.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        case .manual:
            return folders.sorted { a, b in
                let ia = folderOrder.firstIndex(of: a.id) ?? Int.max
                let ib = folderOrder.firstIndex(of: b.id) ?? Int.max
                return ia < ib
            }
        }
    }

    var activeCollections: [VaultCollection] {
        guard let orgId = activeVaultId else { return [] }
        return collections.filter { $0.organizationId == orgId }
    }

    var selectedCipher: VaultCipher? {
        guard let id = selectedCipherId else { return nil }
        return ciphers.first { $0.id == id }
    }

    // Cached derived data. Recomputed only when a source input changes
    // (ciphers / activeVaultId / filter / sort / searchText). Not @Published: the source
    // properties are @Published, so observers already re-render when these can change, and
    // they read the freshly-recomputed value. Publishing it again from inside a source's
    // didSet would trigger "Publishing changes from within view updates".
    private(set) var filteredCiphers: [VaultCipher] = []

    /// cipherId -> lowercased searchable text. `VaultCipher.searchableText` is a computed
    /// property that allocates an array, parses the item's URL and builds two strings on every
    /// read, so evaluating it inside the search filter cost one full rebuild per item per
    /// keystroke. It is materialised here instead and refreshed only when `ciphers` changes.
    private var searchIndex: [String: String] = [:]

    /// Sidebar counts, refreshed with the list in `recomputeDerived`.
    private var counts = VaultCounts()

    /// Rebuild the cached searchable text. Called from `ciphers.didSet` only — the index is
    /// keyed by cipher id and does not depend on the active vault, filter, sort or query.
    func rebuildSearchIndex() {
        var idx: [String: String] = [:]
        idx.reserveCapacity(ciphers.count)
        for c in ciphers { idx[c.id] = c.searchableText }
        searchIndex = idx
    }

    /// Recompute the filtered list and all sidebar counts in a single pass over the vault.
    func recomputeDerived() {
        // The work itself is `VaultListPipeline`, a pure function the unit tests can reach.
        let output = VaultListPipeline.run(.init(
            vault: vaultCiphers, filter: filter, sort: sort, searchText: searchText,
            searchIndex: searchIndex, recent: recent))
        filteredCiphers = output.list
        counts = output.counts
    }

    var filterTitle: String {
        switch filter {
        case .all: return L10n.Sidebar.allItems.localized
        case .favorites: return L10n.Sidebar.favorites.localized
        case .recent: return L10n.Sidebar.recent.localized
        case .type(let t): return t.localizedName
        case .folder(let id): return folders.first { $0.id == id }?.name ?? L10n.Sidebar.folders.localized
        case .collection(let id): return collections.first { $0.id == id }?.name ?? L10n.Sidebar.collections.localized
        case .trash: return L10n.Sidebar.trash.localized
        }
    }

    /// O(1) lookup into the cached counts (populated by recomputeDerived()).
    func countFor(filter: VaultFilter) -> Int {
        switch filter {
        case .all: return counts.all
        case .favorites: return counts.favorites
        case .recent: return counts.recent
        case .type(let t): return counts.byType[t] ?? 0
        case .folder(let id): return counts.byFolder[id] ?? 0
        case .collection(let id): return counts.byCollection[id] ?? 0
        case .trash: return counts.trash
        }
    }
}

enum AuthError: LocalizedError {
    case keyDerivationFailed, noEncryptionKey, noSavedSession, biometricFailed
    var errorDescription: String? {
        switch self {
        case .keyDerivationFailed: return "Key derivation failed"
        case .noEncryptionKey: return "Server did not return encryption key"
        case .noSavedSession: return "No saved session data"
        case .biometricFailed: return "Biometric authentication failed"
        }
    }
}
