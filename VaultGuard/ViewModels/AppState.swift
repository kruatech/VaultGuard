import Foundation
import SwiftUI
import Combine

// MARK: - Filter & Sort

enum VaultFilter: Hashable {
    case all, favorites, trash
    case type(CipherType)
    case folder(String)
    case collection(String)
}

enum VaultSort: String, CaseIterable {
    case name, modified
    var displayName: String {
        switch self {
        case .name: return L10n.Items.sortName.localized
        case .modified: return L10n.Items.sortDate.localized
        }
    }
}

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
    @Published var ciphers: [VaultCipher] = [] { didSet { recomputeDerived() } }
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
    @Published var selectedCipherId: String?
    @Published var pendingReprompt: RepromptRequest?
    var repromptVerifiedCipherIds: Set<String> = []

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
        case .all, .trash, .collection: break
        }
        editingCipher = nil
        showEditSheet = true
    }
    @Published var showDeleteConfirm = false
    @Published var deletingCipher: VaultCipher?
    @Published var showGenerator = false
    @Published var showSettings = false
    @Published var showAddAccount = false
    @Published var toasts: [ToastMessage] = []

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

    /// Per-account UserDefaults key for the manual folder order. Uses a neutral key when
    /// there's no active account yet.
    private var folderOrderKey: String {
        accounts.activeAccountId.map { "folderOrder.\($0)" } ?? "folderOrder"
    }

    // Attachment upload progress
    @Published var isUploadingAttachments = false
    @Published var attachmentUploadProgress: Double = 0

    private(set) var api = APIService()
    private(set) var crypto = CryptoService()
    let keychain = KeychainService.shared
    let accounts = AccountManager()
    var lastActivityDate = Date()
    var autoLockTimer: Timer?
    var sleepObservers: [NSObjectProtocol] = []

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
        if let data = UserDefaults.standard.data(forKey: "passwordTemplates"),
           let arr = try? JSONDecoder().decode([PasswordTemplate].self, from: data) {
            passwordTemplates = arr
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

    var selectedCipher: VaultCipher? { ciphers.first { $0.id == selectedCipherId } }

    // Cached derived data. Recomputed only when a source input changes
    // (ciphers / activeVaultId / filter / sort / searchText). Not @Published: the source
    // properties are @Published, so observers already re-render when these can change, and
    // they read the freshly-recomputed value. Publishing it again from inside a source's
    // didSet would trigger "Publishing changes from within view updates".
    private(set) var filteredCiphers: [VaultCipher] = []
    private var countAll = 0
    private var countFavorites = 0
    private var countTrash = 0
    private var countByType: [CipherType: Int] = [:]
    private var countByFolder: [String: Int] = [:]
    private var countByCollection: [String: Int] = [:]

    /// Recompute the filtered list and all sidebar counts in a single pass over the vault.
    func recomputeDerived() {
        let vault = vaultCiphers
        let active = vault.filter { $0.deletedDate == nil }

        // Filtered list for the current filter/search/sort.
        var result: [VaultCipher]
        switch filter {
        case .all: result = active
        case .favorites: result = active.filter { $0.favorite }
        case .type(let t): result = active.filter { $0.type == t }
        case .folder(let id): result = active.filter { $0.folderId == id }
        case .collection(let id): result = active.filter { $0.collectionIds?.contains(id) == true }
        case .trash: result = vault.filter { $0.deletedDate != nil }
        }
        if !searchText.isEmpty {
            let q = searchText.lowercased()
            result = result.filter { $0.searchableText.contains(q) }
        }
        switch sort {
        case .name: result.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        case .modified: result.sort { ($0.revisionDate ?? .distantPast) > ($1.revisionDate ?? .distantPast) }
        }
        filteredCiphers = result

        // Sidebar counts — computed once here, read O(1) by countFor(filter:).
        countAll = active.count
        countTrash = vault.count - active.count
        var fav = 0
        var byType: [CipherType: Int] = [:]
        var byFolder: [String: Int] = [:]
        var byCollection: [String: Int] = [:]
        for c in active {
            if c.favorite { fav += 1 }
            byType[c.type, default: 0] += 1
            if let f = c.folderId { byFolder[f, default: 0] += 1 }
            for cid in c.collectionIds ?? [] { byCollection[cid, default: 0] += 1 }
        }
        countFavorites = fav
        countByType = byType
        countByFolder = byFolder
        countByCollection = byCollection
    }

    var filterTitle: String {
        switch filter {
        case .all: return L10n.Sidebar.allItems.localized
        case .favorites: return L10n.Sidebar.favorites.localized
        case .type(let t): return t.localizedName
        case .folder(let id): return folders.first { $0.id == id }?.name ?? L10n.Sidebar.folders.localized
        case .collection(let id): return collections.first { $0.id == id }?.name ?? L10n.Sidebar.collections.localized
        case .trash: return L10n.Sidebar.trash.localized
        }
    }

    /// O(1) lookup into the cached counts (populated by recomputeDerived()).
    func countFor(filter: VaultFilter) -> Int {
        switch filter {
        case .all: return countAll
        case .favorites: return countFavorites
        case .type(let t): return countByType[t] ?? 0
        case .folder(let id): return countByFolder[id] ?? 0
        case .collection(let id): return countByCollection[id] ?? 0
        case .trash: return countTrash
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
