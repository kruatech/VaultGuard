import XCTest
import Foundation

/// `RecentCiphersStore` is the "recently used" list: ordered, de-duplicated, capped,
/// persisted. The ordering and the de-duplication are the whole feature — a list that repeats
/// an entry, or that keeps the first use rather than the latest, stops answering the question
/// it exists for.
final class RecentCiphersStoreTests: XCTestCase {

    /// A private suite so nothing here touches the real app's defaults.
    private var defaults: UserDefaults!
    private let suiteName = "RecentCiphersStoreTests"

    override func setUp() {
        super.setUp()
        UserDefaults.standard.removePersistentDomain(forName: suiteName)
        defaults = UserDefaults(suiteName: suiteName)
    }

    override func tearDown() {
        UserDefaults.standard.removePersistentDomain(forName: suiteName)
        defaults = nil
        super.tearDown()
    }

    private func cipher(_ id: String) -> VaultCipher {
        VaultCipher(id: id, organizationId: nil, folderId: nil, collectionIds: nil,
                    type: .login, name: id, notes: nil,
                    login: CipherLogin(username: "u", password: "p", totp: nil, uris: nil),
                    card: nil, secureNote: nil, identity: nil,
                    fields: nil, attachments: nil, favorite: false, reprompt: nil,
                    creationDate: nil, revisionDate: nil, deletedDate: nil)
    }

    // MARK: Ordering

    func testMostRecentComesFirst() {
        var store = RecentCiphersStore()
        store.record("a"); store.record("b"); store.record("c")
        XCTAssertEqual(store.ids, ["c", "b", "a"])
    }

    /// Using something again moves it to the front instead of adding a second entry.
    func testReuseMovesToFrontWithoutDuplicating() {
        var store = RecentCiphersStore()
        store.record("a"); store.record("b"); store.record("a")
        XCTAssertEqual(store.ids, ["a", "b"])
    }

    func testEmptyIdIsIgnored() {
        var store = RecentCiphersStore()
        store.record("")
        XCTAssertTrue(store.ids.isEmpty)
    }

    // MARK: Cap

    func testListIsCappedAndDropsTheOldest() {
        var store = RecentCiphersStore()
        for i in 0..<(RecentCiphersStore.limit + 5) { store.record("id\(i)") }
        XCTAssertEqual(store.ids.count, RecentCiphersStore.limit)
        XCTAssertEqual(store.ids.first, "id\(RecentCiphersStore.limit + 4)")
        XCTAssertFalse(store.ids.contains("id0"), "the oldest should have fallen off")
    }

    /// Re-recording something already on a full list must not grow it.
    func testReuseOnAFullListKeepsTheCap() {
        var store = RecentCiphersStore()
        for i in 0..<RecentCiphersStore.limit { store.record("id\(i)") }
        store.record("id0")
        XCTAssertEqual(store.ids.count, RecentCiphersStore.limit)
        XCTAssertEqual(store.ids.first, "id0")
    }

    // MARK: Ordering a vault

    func testOrderReturnsUsedItemsNewestFirst() {
        var store = RecentCiphersStore()
        store.record("a"); store.record("c")
        let ordered = store.order([cipher("a"), cipher("b"), cipher("c")])
        XCTAssertEqual(ordered.map { $0.id }, ["c", "a"])
    }

    /// The input order is irrelevant — the list is ranked by use, not by however the vault
    /// happens to be sorted.
    func testOrderIgnoresTheInputOrder() {
        var store = RecentCiphersStore()
        store.record("c"); store.record("a")
        let ordered = store.order([cipher("c"), cipher("b"), cipher("a")])
        XCTAssertEqual(ordered.map { $0.id }, ["a", "c"])
    }

    /// An id left over from an item that has since been deleted must not show up.
    func testDeletedItemsDropOut() {
        var store = RecentCiphersStore()
        store.record("a"); store.record("b")
        XCTAssertEqual(store.order([cipher("a")]).map { $0.id }, ["a"])
    }

    func testNothingUsedMeansAnEmptyResult() {
        XCTAssertTrue(RecentCiphersStore().order([cipher("a")]).isEmpty)
    }

    // MARK: Count

    /// The count has to agree with what the list will actually show, or the sidebar offers a
    /// section that opens empty.
    func testCountMatchesTheOrderedList() {
        var store = RecentCiphersStore()
        store.record("a"); store.record("b")
        let vault = [cipher("a")]
        XCTAssertEqual(store.count(in: vault), store.order(vault).count)
        XCTAssertEqual(store.count(in: vault), 1)
    }

    func testCountIsZeroWhenNothingWasUsed() {
        XCTAssertEqual(RecentCiphersStore().count(in: [cipher("a")]), 0)
    }

    // MARK: Persistence

    func testSavedListIsReloaded() {
        var store = RecentCiphersStore()
        store.record("a"); store.record("b")
        store.save(for: "acct", to: defaults)

        let reloaded = RecentCiphersStore(loadingFor: "acct", from: defaults)
        XCTAssertEqual(reloaded.ids, ["b", "a"])
    }

    /// Accounts must not see each other's list.
    func testListsAreScopedPerAccount() {
        var first = RecentCiphersStore()
        first.record("a")
        first.save(for: "one", to: defaults)

        var second = RecentCiphersStore()
        second.record("z")
        second.save(for: "two", to: defaults)

        XCTAssertEqual(RecentCiphersStore(loadingFor: "one", from: defaults).ids, ["a"])
        XCTAssertEqual(RecentCiphersStore(loadingFor: "two", from: defaults).ids, ["z"])
    }

    /// With no account signed in the list lands under the neutral key, the same way the
    /// manual folder order does.
    func testNilAccountUsesTheNeutralKey() {
        XCTAssertEqual(RecentCiphersStore.key(accountId: nil), "recentCiphers")
        XCTAssertEqual(RecentCiphersStore.key(accountId: "abc"), "recentCiphers.abc")
    }

    /// Removing an account must not leave a list for a later account reusing the id.
    func testClearRemovesTheStoredList() {
        var store = RecentCiphersStore()
        store.record("a")
        store.save(for: "acct", to: defaults)

        RecentCiphersStore.clear(for: "acct", in: defaults)
        XCTAssertTrue(RecentCiphersStore(loadingFor: "acct", from: defaults).ids.isEmpty)
    }

    func testLoadingAnUnknownAccountGivesAnEmptyList() {
        XCTAssertTrue(RecentCiphersStore(loadingFor: "never-saved", from: defaults).ids.isEmpty)
    }
}
