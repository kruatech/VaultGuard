import Foundation

/// The "recently used" list: ordered, de-duplicated, capped, persisted.
///
/// Standalone rather than a handful of methods on `AppState`, for the same reason as
/// `BitwardenEndpoints` and `AutoFillHostMatcher`: `AppState` drags in the network stack and
/// the keychain, so nothing that lives on it can be unit-tested. This has no dependency past
/// `VaultCipher`, and the ordering is exactly the part worth asserting — a list that repeats
/// an entry, or that keeps the first use rather than the latest, stops answering the question
/// it exists for.
///
/// Persisted per account in `UserDefaults`. That does put a list of identifiers on disk in
/// the clear: they carry no names, passwords or URLs, and anyone able to read them can
/// already read `folderOrder` sitting beside them, so it hands an attacker nothing new.
/// Keeping it in memory instead would reset the list on every auto-lock, which for a list
/// whose whole purpose is "what did I use lately" makes the feature pointless.
struct RecentCiphersStore {

    /// Longer than a sidebar section can usefully show; the cap stops the list growing
    /// without bound rather than deciding what fits on screen.
    static let limit = 20

    private(set) var ids: [String]

    /// UserDefaults key. The neutral one is used when no account is active yet, matching how
    /// the manual folder order is keyed.
    static func key(accountId: String?) -> String {
        accountId.map { "recentCiphers.\($0)" } ?? "recentCiphers"
    }

    init(ids: [String] = []) { self.ids = ids }

    init(loadingFor accountId: String?, from defaults: UserDefaults = .standard) {
        ids = defaults.stringArray(forKey: Self.key(accountId: accountId)) ?? []
    }

    /// Note a use. An id already present moves to the front instead of being added again.
    mutating func record(_ cipherId: String) {
        guard !cipherId.isEmpty else { return }
        ids.removeAll { $0 == cipherId }
        ids.insert(cipherId, at: 0)
        if ids.count > Self.limit { ids.removeLast(ids.count - Self.limit) }
    }

    func save(for accountId: String?, to defaults: UserDefaults = .standard) {
        defaults.set(ids, forKey: Self.key(accountId: accountId))
    }

    static func clear(for accountId: String, in defaults: UserDefaults = .standard) {
        defaults.removeObject(forKey: key(accountId: accountId))
    }

    /// The given items that have been used, most recent first.
    ///
    /// Ordered by use rather than by whatever sort the vault is showing — a "recent" list in
    /// alphabetical order is just the vault again. Ids whose item no longer exists fall out
    /// silently; the list is a convenience, not a record.
    func order(_ ciphers: [VaultCipher]) -> [VaultCipher] {
        let rank = Dictionary(uniqueKeysWithValues: ids.enumerated().map { ($1, $0) })
        return ciphers.filter { rank[$0.id] != nil }
                      .sorted { (rank[$0.id] ?? .max) < (rank[$1.id] ?? .max) }
    }

    /// How many of `ciphers` are on the list. Counting the ids directly would include items
    /// that have since been deleted, and the sidebar would offer a section that opens empty.
    func count(in ciphers: [VaultCipher]) -> Int {
        let live = Set(ciphers.map { $0.id })
        return ids.filter { live.contains($0) }.count
    }
}
