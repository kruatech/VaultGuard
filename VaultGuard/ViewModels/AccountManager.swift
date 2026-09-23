import Foundation

/// Owns the set of signed-in accounts, the active-account pointer, and their persistence.
///
/// The list (metadata only) is JSON-encoded into the Keychain via
/// `KeychainService.accountIndexJSON`; the active id via `activeAccountId`. Per-account
/// secrets are managed separately through `KeychainService.account(_:)`.
///
/// This type deliberately knows nothing about login/unlock — that orchestration lives in
/// `AppState`. It only manages identity, ordering and storage.
@MainActor
final class AccountManager: ObservableObject {
    @Published private(set) var accounts: [Account] = []
    @Published private(set) var activeAccountId: String?

    private let keychain: KeychainService

    /// Set when `load()` found a stored index it could not decode.
    ///
    /// While it is set, nothing may persist the list: an index that merely failed to decode
    /// would be replaced by the empty array that failure produced, and the user's accounts
    /// would vanish from the app. `JSONDecoder` rejects the whole array if any element does
    /// not match, so a future change to `Account` is enough to trigger it — no corruption and
    /// no attacker needed. `upsert` clears it, because adding an account is the user
    /// deliberately rebuilding the list.
    private var indexUnreadable = false

    init(keychain: KeychainService = .shared) {
        self.keychain = keychain
        // Wipe any pre-split legacy items from the shared keychain group before reading state.
        keychain.migrateAccessGroupsIfNeeded()
        load()
    }

    // MARK: - Queries

    var activeAccount: Account? { accounts.first { $0.id == activeAccountId } }
    var hasAccounts: Bool { !accounts.isEmpty }
    func contains(_ id: String) -> Bool { accounts.contains { $0.id == id } }

    /// Accounts ordered for display: oldest first (stable switcher ordering).
    var ordered: [Account] { accounts.sorted { $0.addedAt < $1.addedAt } }

    // MARK: - Mutations

    /// Insert or update an account. An existing entry keeps its original `addedAt` (stable
    /// switcher order) and its user-defined `label` (a re-login passes `label == nil` and
    /// must not wipe a name the user set).
    func upsert(_ account: Account) {
        // Signing in rebuilds the list on purpose, so an unreadable index stops blocking writes.
        indexUnreadable = false
        if let idx = accounts.firstIndex(where: { $0.id == account.id }) {
            var merged = account
            merged.addedAt = accounts[idx].addedAt
            if merged.label == nil { merged.label = accounts[idx].label }
            accounts[idx] = merged
        } else {
            accounts.append(account)
        }
        persist()
    }

    /// Set or clear the user-defined connection name for an account. Blank input clears it
    /// (so `displayName` falls back to `email · host`).
    func setLabel(_ label: String?, for id: String) {
        guard let idx = accounts.firstIndex(where: { $0.id == id }) else { return }
        let trimmed = label?.trimmingCharacters(in: .whitespacesAndNewlines)
        accounts[idx].label = (trimmed?.isEmpty == false) ? trimmed : nil
        persist()
    }

    func setActive(_ id: String?) {
        activeAccountId = id
        keychain.activeAccountId = id
    }

    /// Remove a single account: wipe its Keychain secrets, drop it from the index, and
    /// reassign the active pointer if it was the active one. The index update always happens
    /// (UI stays consistent); a failed secret wipe is rethrown so the caller can warn.
    func remove(_ id: String) throws {
        var wipeError: Error?
        do { try keychain.clearAccount(id) } catch { wipeError = error }
        accounts.removeAll { $0.id == id }
        if activeAccountId == id { setActive(ordered.first?.id) }
        persist()
        if let wipeError { throw wipeError }
    }

    /// Remove every account and clear global pointers. The index is always cleared; a failed
    /// secret wipe is rethrown so the caller can warn.
    func removeAll(_ ids: [String]) throws {
        var wipeError: Error?
        do { try keychain.clearAllAccounts(ids) } catch { wipeError = error }
        accounts.removeAll()
        activeAccountId = nil
        if let wipeError { throw wipeError }
    }

    // MARK: - Persistence

    private func load() {
        activeAccountId = keychain.activeAccountId
        guard let json = keychain.accountIndexJSON, let data = json.data(using: .utf8) else { return }
        if let decoded = try? JSONDecoder().decode([Account].self, from: data) {
            accounts = decoded
        } else {
            indexUnreadable = true
            Log.fault("account index could not be decoded — not overwriting it")
        }
    }

    private func persist() {
        guard !indexUnreadable else {
            Log.fault("skipped account index write: the stored index was never read")
            return
        }
        guard let data = try? JSONEncoder().encode(accounts),
              let json = String(data: data, encoding: .utf8) else { return }
        keychain.accountIndexJSON = json
    }

}
