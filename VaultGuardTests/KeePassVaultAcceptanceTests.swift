import XCTest
import Foundation

/// End-to-end acceptance tests for the KeePass write path.
///
/// These replace a set of UI tests that tried to prove the same things by driving the app.
/// Those needed a signed runner, an accessibility grant, a sandbox-readable fixture and a
/// security-scoped bookmark, and none of that had anything to do with what was being checked.
/// Everything below goes through the same objects the app uses — `KeePassBackend`,
/// `KDBXWriter`, `KDBXReader`, `KDBXVaultMapper` — with the file kept in memory.
///
/// "Acceptance" here means the assertions are about what a user would observe: an entry they
/// added is there after reopening the file, one they deleted is in the trash rather than gone,
/// a restore brings it back. Not about how any of it is stored.
final class KeePassVaultAcceptanceTests: XCTestCase {

    private let password = "v3pass"

    /// The same KDBX 3.1 database `KDBXv3Tests` uses, embedded here because that test keeps its
    /// copy private. Saving converts it to KDBX 4 — the writer emits only that container — so
    /// every round trip below is also a conversion test.
    private let fixtureB64 =
        "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" +
        "RFl2D2lyQzg="

    private var fixture: Data { Data(base64Encoded: fixtureB64)! }

    /// A light KDF so a test that saves three times does not spend seconds in Argon2.
    private func reopen(_ data: Data) throws -> KeePassBackend {
        let backend = KeePassBackend(fileData: data, password: password)
        return backend
    }

    /// Save and reopen: the only way to tell a change that was applied from one that was
    /// merely applied in memory.
    private func roundTrip(_ backend: KeePassBackend) async throws -> DecryptedVault {
        let saved = try backend.serialize(profileOverride: .lightArgon2d)
        let reopened = try reopen(saved)
        return try await reopened.load()
    }

    private func newLogin(_ name: String, user: String = "user", password: String = "pw") -> VaultCipher {
        VaultCipher(id: "", organizationId: nil, folderId: nil, collectionIds: nil,
                    type: .login, name: name, notes: nil,
                    login: CipherLogin(username: user, password: password, totp: nil, uris: nil),
                    card: nil, secureNote: nil, identity: nil,
                    fields: nil, attachments: nil, favorite: false, reprompt: nil,
                    creationDate: nil, revisionDate: nil, deletedDate: nil)
    }

    private func live(_ vault: DecryptedVault) -> [String] {
        vault.ciphers.filter { $0.deletedDate == nil }.map(\.name).sorted()
    }

    private func trashed(_ vault: DecryptedVault) -> [String] {
        vault.ciphers.filter { $0.deletedDate != nil }.map(\.name).sorted()
    }

    // MARK: Baseline

    func testFixtureOpensWithItsEntriesAndAnEmptyTrash() async throws {
        let vault = try await reopen(fixture).load()
        XCTAssertFalse(vault.ciphers.isEmpty)
        XCTAssertTrue(trashed(vault).isEmpty, "the fixture should start with nothing in the trash")
    }

    // MARK: Adding

    func testAddedEntriesSurviveSaveAndReopen() async throws {
        let backend = try reopen(fixture)
        _ = try await backend.load()

        for name in ["Added One", "Added Two", "Added Three"] {
            _ = try backend.addCipher(newLogin(name))
        }
        let vault = try await roundTrip(backend)

        for name in ["Added One", "Added Two", "Added Three"] {
            XCTAssertTrue(live(vault).contains(name), "\(name) is missing after reopening")
        }
    }

    /// The credentials go in with the entry, not just its title.
    func testAddedEntryKeepsItsUsernameAndPassword() async throws {
        let backend = try reopen(fixture)
        _ = try await backend.load()
        _ = try backend.addCipher(newLogin("Credentials", user: "alice", password: "s3cret"))

        let vault = try await roundTrip(backend)
        let entry = try XCTUnwrap(vault.ciphers.first { $0.name == "Credentials" })
        XCTAssertEqual(entry.login?.username, "alice")
        XCTAssertEqual(entry.login?.password, "s3cret")
    }

    /// Adding must not disturb what was already there — the bug a careless rewrite would cause.
    func testAddingLeavesExistingEntriesAlone() async throws {
        let before = live(try await reopen(fixture).load())

        let backend = try reopen(fixture)
        _ = try await backend.load()
        _ = try backend.addCipher(newLogin("Newcomer"))
        let after = live(try await roundTrip(backend))

        XCTAssertEqual(Set(before).subtracting(after), [], "an existing entry disappeared")
        XCTAssertEqual(Set(after).subtracting(before), ["Newcomer"])
    }

    // MARK: Deleting

    /// Delete moves an entry to the Recycle Bin rather than erasing it. The fixture has the bin
    /// enabled but no bin group yet, so the first delete has to create one.
    func testDeleteMovesAnEntryToTheTrash() async throws {
        let backend = try reopen(fixture)
        let vault = try await backend.load()
        let victim = try XCTUnwrap(vault.ciphers.first)

        try backend.deleteCipher(id: victim.id)
        let after = try await roundTrip(backend)

        XCTAssertFalse(live(after).contains(victim.name), "it is still in the main list")
        XCTAssertTrue(trashed(after).contains(victim.name), "it is not in the trash either — erased?")
    }

    func testDeletingOneLeavesTheOthersInPlace() async throws {
        let backend = try reopen(fixture)
        let vault = try await backend.load()
        let victim = try XCTUnwrap(vault.ciphers.first)
        let survivors = vault.ciphers.dropFirst().map(\.name).sorted()

        try backend.deleteCipher(id: victim.id)
        // Hoisted out of the assertion: an autoclosure cannot contain `await`.
        let after = try await roundTrip(backend)
        XCTAssertEqual(live(after), survivors)
    }

    /// Several deletions, then one save — the shape the bulk action uses, which writes the file
    /// once rather than once per entry.
    func testSeveralDeletionsInOneSave() async throws {
        let backend = try reopen(fixture)
        let vault = try await backend.load()
        let victims = Array(vault.ciphers.prefix(2))
        XCTAssertEqual(victims.count, 2, "the fixture needs at least two entries for this")

        for victim in victims { try backend.deleteCipher(id: victim.id) }
        let after = try await roundTrip(backend)

        for victim in victims {
            XCTAssertFalse(live(after).contains(victim.name))
            XCTAssertTrue(trashed(after).contains(victim.name))
        }
        XCTAssertEqual(live(after).count, vault.ciphers.count - victims.count)
    }

    /// Added and original entries behave the same once saved — the request's full round trip.
    func testAddSeveralThenTrashPartOfThem() async throws {
        let backend = try reopen(fixture)
        let vault = try await backend.load()
        let original = try XCTUnwrap(vault.ciphers.first)

        let keep = try backend.addCipher(newLogin("Keep Me"))
        let discard = try backend.addCipher(newLogin("Trash Me"))
        try backend.deleteCipher(id: discard.id)
        try backend.deleteCipher(id: original.id)

        let after = try await roundTrip(backend)
        XCTAssertTrue(live(after).contains(keep.name))
        XCTAssertEqual(trashed(after).sorted(), ["Trash Me", original.name].sorted())
        XCTAssertFalse(live(after).contains("Trash Me"))
    }

    // MARK: Restoring and purging

    func testRestoreBringsAnEntryBackOutOfTheTrash() async throws {
        let backend = try reopen(fixture)
        let vault = try await backend.load()
        let victim = try XCTUnwrap(vault.ciphers.first)

        try backend.deleteCipher(id: victim.id)
        let afterDelete = try await roundTrip(backend)
        XCTAssertTrue(trashed(afterDelete).contains(victim.name))

        try backend.restoreCipher(id: victim.id)
        let after = try await roundTrip(backend)
        XCTAssertTrue(live(after).contains(victim.name), "restore did not bring it back")
        XCTAssertFalse(trashed(after).contains(victim.name))
    }

    /// Permanent deletion is the one operation with no way back, so it must actually remove
    /// the entry rather than leave it in the bin.
    func testPermanentDeleteRemovesTheEntryEntirely() async throws {
        let backend = try reopen(fixture)
        let vault = try await backend.load()
        let victim = try XCTUnwrap(vault.ciphers.first)

        try backend.deleteCipher(id: victim.id)
        try backend.permanentlyDeleteCipher(id: victim.id)
        let after = try await roundTrip(backend)

        XCTAssertFalse(live(after).contains(victim.name))
        XCTAssertFalse(trashed(after).contains(victim.name), "it is still in the trash")
    }

    // MARK: Editing and moving

    func testEditingAnEntryPersists() async throws {
        let backend = try reopen(fixture)
        let vault = try await backend.load()
        var edited = try XCTUnwrap(vault.ciphers.first)
        edited.name = "Renamed"
        edited.login = CipherLogin(username: "changed", password: "changed-pw", totp: nil, uris: nil)

        try backend.updateCipher(edited)
        let after = try await roundTrip(backend)

        let found = try XCTUnwrap(after.ciphers.first { $0.id == edited.id })
        XCTAssertEqual(found.name, "Renamed")
        XCTAssertEqual(found.login?.username, "changed")
        XCTAssertEqual(found.login?.password, "changed-pw")
    }

    func testMovingAnEntryIntoANewFolderPersists() async throws {
        let backend = try reopen(fixture)
        let vault = try await backend.load()
        let entry = try XCTUnwrap(vault.ciphers.first)

        let folder = try backend.addFolder(name: "Moved Here")
        try backend.moveCipher(id: entry.id, toFolderId: folder.id)
        let after = try await roundTrip(backend)

        let target = try XCTUnwrap(after.folders.first { $0.name.hasSuffix("Moved Here") })
        XCTAssertEqual(after.ciphers.first { $0.id == entry.id }?.folderId, target.id)
    }

    // MARK: Nothing is lost along the way

    /// A save must not quietly drop the entries it is not touching. Ids are compared rather
    /// than names so a rename cannot mask a loss.
    func testRepeatedSavesPreserveEveryEntry() async throws {
        var data = fixture
        let expected = Set(try await reopen(fixture).load().ciphers.map(\.id))

        for round in 1...3 {
            let backend = try reopen(data)
            _ = try await backend.load()
            _ = try backend.addCipher(newLogin("Round \(round)"))
            data = try backend.serialize(profileOverride: .lightArgon2d)
        }

        let final = try await reopen(data).load()
        XCTAssertTrue(expected.isSubset(of: Set(final.ciphers.map(\.id))),
                      "an entry from the original file was lost across saves")
        for round in 1...3 {
            XCTAssertTrue(live(final).contains("Round \(round)"), "Round \(round) was lost")
        }
    }

    /// The password is still required after a save: the conversion must not produce a file that
    /// opens with anything else.
    func testSavedFileStillRequiresThePassword() async throws {
        let backend = try reopen(fixture)
        _ = try await backend.load()
        _ = try backend.addCipher(newLogin("Anything"))
        let saved = try backend.serialize(profileOverride: .lightArgon2d)

        XCTAssertNoThrow(try KDBXReader.unlock(data: saved, password: password))
        XCTAssertThrowsError(try KDBXReader.unlock(data: saved, password: "wrong"))
    }
}
