import XCTest
import Foundation

/// `VaultListPipeline` decides what the item list shows and what the sidebar counts. It ran
/// inside `AppState`, where no test could reach it; these are its first tests.
final class VaultListPipelineTests: XCTestCase {

    // MARK: Fixtures

    private func item(_ name: String, id: String? = nil, type: CipherType = .login,
                      favorite: Bool = false, folder: String? = nil, collections: [String]? = nil,
                      user: String = "", modified: Date? = nil, deleted: Bool = false) -> VaultCipher {
        VaultCipher(id: id ?? name, organizationId: nil, folderId: folder, collectionIds: collections,
                    type: type, name: name, notes: nil,
                    login: type == .login ? CipherLogin(username: user, password: "p", totp: nil, uris: nil) : nil,
                    card: nil, secureNote: type == .secureNote ? CipherSecureNote(type: 0) : nil, identity: nil,
                    fields: nil, attachments: nil, favorite: favorite, reprompt: nil,
                    creationDate: nil, revisionDate: modified, deletedDate: deleted ? Date() : nil)
    }

    private func run(_ vault: [VaultCipher], filter: VaultFilter = .all, sort: VaultSort = .name,
                     search: String = "", recent: RecentCiphersStore = RecentCiphersStore()) -> VaultListPipeline.Output {
        VaultListPipeline.run(.init(vault: vault, filter: filter, sort: sort, searchText: search,
                                    searchIndex: [:], recent: recent))
    }

    private func names(_ out: VaultListPipeline.Output) -> [String] { out.list.map(\.name) }

    // MARK: Filters

    func testAllShowsEveryLiveItemAndNothingTrashed() {
        let out = run([item("A"), item("B"), item("Gone", deleted: true)])
        XCTAssertEqual(names(out), ["A", "B"])
    }

    func testTrashShowsOnlyDeletedItems() {
        let out = run([item("A"), item("Gone", deleted: true)], filter: .trash)
        XCTAssertEqual(names(out), ["Gone"])
    }

    func testFavoritesExcludesTrashedFavorites() {
        let out = run([item("Fav", favorite: true), item("Plain"),
                       item("DeadFav", favorite: true, deleted: true)], filter: .favorites)
        XCTAssertEqual(names(out), ["Fav"])
    }

    func testTypeFilter() {
        let out = run([item("Login"), item("Note", type: .secureNote)], filter: .type(.secureNote))
        XCTAssertEqual(names(out), ["Note"])
    }

    func testFolderFilter() {
        let out = run([item("In", folder: "f1"), item("Out", folder: "f2"), item("None")],
                      filter: .folder("f1"))
        XCTAssertEqual(names(out), ["In"])
    }

    func testCollectionFilter() {
        let out = run([item("Shared", collections: ["c1", "c2"]), item("Other", collections: ["c3"]),
                       item("Personal")], filter: .collection("c2"))
        XCTAssertEqual(names(out), ["Shared"])
    }

    // MARK: Sort

    /// Case-insensitive: "apple" belongs between "Apple" and "Banana", not after every capital.
    func testNameSortIsCaseInsensitive() {
        let out = run([item("banana"), item("Apple"), item("cherry")], sort: .name)
        XCTAssertEqual(names(out), ["Apple", "banana", "cherry"])
    }

    func testDateSortIsNewestFirstWithUndatedLast() {
        let now = Date()
        let out = run([item("Old", modified: now.addingTimeInterval(-100)),
                       item("Undated"),
                       item("New", modified: now)], sort: .modified)
        XCTAssertEqual(names(out), ["New", "Old", "Undated"])
    }

    /// The recent list is in order of use; the vault sort must not reorder it.
    func testRecentIgnoresTheSort() {
        var recent = RecentCiphersStore()
        recent.record("Zebra"); recent.record("Apple")   // Apple used last
        let out = run([item("Apple"), item("Zebra"), item("Middle")], filter: .recent,
                      sort: .name, recent: recent)
        XCTAssertEqual(names(out), ["Apple", "Zebra"])
    }

    // MARK: Search

    func testSearchMatchesNameAndUsername() {
        let vault = [item("GitHub", user: "octocat"), item("Dropbox", user: "wendy")]
        XCTAssertEqual(names(run(vault, search: "git")), ["GitHub"])
        XCTAssertEqual(names(run(vault, search: "wendy")), ["Dropbox"])
    }

    func testSearchIsCaseInsensitive() {
        XCTAssertEqual(names(run([item("GitHub")], search: "GITHUB")), ["GitHub"])
    }

    /// The transliterating search, checked where it takes effect — on what the list shows.
    func testCyrillicQueryFindsALatinItem() {
        XCTAssertEqual(names(run([item("GitHub"), item("Dropbox")], search: "гит")), ["GitHub"])
    }

    func testLatinQueryFindsACyrillicItem() {
        XCTAssertEqual(names(run([item("Гитхаб"), item("Dropbox")], search: "git")), ["Гитхаб"])
    }

    /// Search narrows the current filter; it does not reach back into items the filter hid.
    func testSearchStaysWithinTheFilter() {
        let vault = [item("GitHub Work", folder: "work"), item("GitHub Home", folder: "home")]
        XCTAssertEqual(names(run(vault, filter: .folder("work"), search: "github")), ["GitHub Work"])
    }

    func testSearchDoesNotSurfaceTrashedItems() {
        XCTAssertEqual(names(run([item("GitHub", deleted: true)], search: "git")), [])
    }

    func testEmptySearchChangesNothing() {
        let vault = [item("A"), item("B")]
        XCTAssertEqual(run(vault, search: ""), run(vault))
    }

    /// An index entry is preferred to recomputing `searchableText`, and a stale index must not
    /// hide an item: anything missing from it falls back.
    func testSearchUsesTheIndexAndFallsBackWithoutIt() {
        let vault = [item("Indexed", id: "i"), item("Unindexed", id: "u")]
        let out = VaultListPipeline.run(.init(vault: vault, filter: .all, sort: .name, searchText: "zzz",
                                              searchIndex: ["i": "zzz lives only in the index"],
                                              recent: RecentCiphersStore()))
        XCTAssertEqual(names(out), ["Indexed"])

        let fallback = VaultListPipeline.run(.init(vault: vault, filter: .all, sort: .name,
                                                   searchText: "unindexed", searchIndex: [:],
                                                   recent: RecentCiphersStore()))
        XCTAssertEqual(names(fallback), ["Unindexed"])
    }

    // MARK: Counts

    /// The sidebar counts sections, not the list: filter and search must not change them.
    func testCountsIgnoreTheFilterAndTheSearch() {
        let vault = [item("A", favorite: true), item("B"), item("Gone", deleted: true)]
        let plain = run(vault).counts
        XCTAssertEqual(run(vault, filter: .favorites).counts, plain)
        XCTAssertEqual(run(vault, search: "nothing matches").counts, plain)
    }

    func testCountsTally() {
        let vault = [
            item("L1", favorite: true, folder: "f", collections: ["c"]),
            item("L2", folder: "f"),
            item("N", type: .secureNote, collections: ["c", "d"]),
            item("Gone", favorite: true, folder: "f", deleted: true),
        ]
        let c = run(vault).counts
        XCTAssertEqual(c.all, 3)
        XCTAssertEqual(c.trash, 1)
        XCTAssertEqual(c.favorites, 1, "a trashed favourite must not count")
        XCTAssertEqual(c.byType[.login], 2)
        XCTAssertEqual(c.byType[.secureNote], 1)
        XCTAssertEqual(c.byFolder["f"], 2, "a trashed item must not count toward its folder")
        XCTAssertEqual(c.byCollection["c"], 2)
        XCTAssertEqual(c.byCollection["d"], 1)
    }

    /// Recent counts only items that still exist, so the sidebar never offers an empty section.
    func testRecentCountSkipsItemsThatNoLongerExist() {
        var recent = RecentCiphersStore()
        recent.record("Kept"); recent.record("Removed")
        XCTAssertEqual(run([item("Kept")], recent: recent).counts.recent, 1)
    }

    func testEmptyVault() {
        let out = run([])
        XCTAssertTrue(out.list.isEmpty)
        XCTAssertEqual(out.counts, VaultCounts())
    }
}
