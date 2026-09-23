import Foundation

// MARK: - Filter & Sort

enum VaultFilter: Hashable {
    case all, favorites, recent, trash
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

/// Sidebar counts, computed in the same pass as the list.
struct VaultCounts: Equatable {
    var all = 0
    var recent = 0
    var favorites = 0
    var trash = 0
    var byType: [CipherType: Int] = [:]
    var byFolder: [String: Int] = [:]
    var byCollection: [String: Int] = [:]
}

/// What the item list shows and what the sidebar counts, from the vault and the current view
/// settings.
///
/// This lived inside `AppState.recomputeDerived()`, which put it out of reach of the unit tests:
/// `AppState` depends on the network client and the keychain, and the test target cannot build
/// either. Filtering, search, sorting and the counts had no coverage at all, even though every
/// one of them is visible to the user on every keystroke. As a pure function over values it can
/// be asserted exactly.
///
/// `AppState` still owns the inputs and calls this whenever one of them changes.
enum VaultListPipeline {

    struct Input {
        var vault: [VaultCipher]
        var filter: VaultFilter
        var sort: VaultSort
        var searchText: String
        /// cipherId -> lowercased searchable text, prepared ahead so a keystroke does not
        /// rebuild it for every item. Items missing from it fall back to `searchableText`.
        var searchIndex: [String: String]
        var recent: RecentCiphersStore
    }

    struct Output: Equatable {
        var list: [VaultCipher]
        var counts: VaultCounts

        static func == (a: Output, b: Output) -> Bool {
            a.list.map(\.id) == b.list.map(\.id) && a.counts == b.counts
        }
    }

    static func run(_ input: Input) -> Output {
        let active = input.vault.filter { $0.deletedDate == nil }

        var list: [VaultCipher]
        switch input.filter {
        case .all:                list = active
        case .favorites:          list = active.filter { $0.favorite }
        case .recent:             list = input.recent.order(active)
        case .type(let t):        list = active.filter { $0.type == t }
        case .folder(let id):     list = active.filter { $0.folderId == id }
        case .collection(let id): list = active.filter { $0.collectionIds?.contains(id) == true }
        case .trash:              list = input.vault.filter { $0.deletedDate != nil }
        }

        list = search(list, for: input.searchText, index: input.searchIndex)

        // The recent list is ordered by use; sorting it by name would turn it into a copy of
        // the vault.
        if input.filter != .recent {
            list = sorted(list, by: input.sort)
        }

        return Output(list: list, counts: counts(active: active, all: input.vault, recent: input.recent))
    }

    /// Items matching the query in any of its spellings. The query is expanded once, not per
    /// item: a Cyrillic query also tries its Latin transliteration and the same keys on the
    /// other keyboard layout, and vice versa. See `SearchQueryExpander`.
    static func search(_ items: [VaultCipher], for text: String, index: [String: String]) -> [VaultCipher] {
        guard !text.isEmpty else { return items }
        let queries = SearchQueryExpander.variants(for: text)
        guard !queries.isEmpty else { return items }
        return items.filter { c in
            let hay = index[c.id] ?? c.searchableText
            return queries.contains { hay.contains($0) }
        }
    }

    /// Name order is case-insensitive and locale-aware; date order is newest first, with items
    /// that have no date last.
    static func sorted(_ items: [VaultCipher], by sort: VaultSort) -> [VaultCipher] {
        switch sort {
        case .name:
            return items.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        case .modified:
            return items.sorted { ($0.revisionDate ?? .distantPast) > ($1.revisionDate ?? .distantPast) }
        }
    }

    /// Counts for the sidebar. Taken over the whole vault regardless of the current filter or
    /// search — the sidebar shows what each section contains, not what the list is showing.
    static func counts(active: [VaultCipher], all: [VaultCipher], recent: RecentCiphersStore) -> VaultCounts {
        var c = VaultCounts()
        c.all = active.count
        c.trash = all.count - active.count
        c.recent = recent.count(in: active)
        for item in active {
            if item.favorite { c.favorites += 1 }
            c.byType[item.type, default: 0] += 1
            if let f = item.folderId { c.byFolder[f, default: 0] += 1 }
            for cid in item.collectionIds ?? [] { c.byCollection[cid, default: 0] += 1 }
        }
        return c
    }
}
