import XCTest
import Foundation

/// The save snapshot is what lets a KeePass save run its KDF off the main thread. Its whole job
/// is isolation: once taken, nothing that happens to the backend may change what gets written.
/// These tests hold it to that.
final class KeePassSaveSnapshotTests: XCTestCase {

    private let password = "v3pass"

    /// The KDBX 3.1 database `KDBXv3Tests` uses.
    private let fixtureB64 =
        "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" +
        "RFl2D2lyQzg="

    private var fixture: Data { Data(base64Encoded: fixtureB64)! }

    private func openBackend() async throws -> (KeePassBackend, DecryptedVault) {
        let backend = KeePassBackend(fileData: fixture, password: password)
        return (backend, try await backend.load())
    }

    private func newLogin(_ name: String) -> VaultCipher {
        VaultCipher(id: "", organizationId: nil, folderId: nil, collectionIds: nil,
                    type: .login, name: name, notes: nil,
                    login: CipherLogin(username: "u", password: "p", totp: nil, uris: nil),
                    card: nil, secureNote: nil, identity: nil,
                    fields: nil, attachments: nil, favorite: false, reprompt: nil,
                    creationDate: nil, revisionDate: nil, deletedDate: nil)
    }

    private func names(in data: Data) async throws -> Set<String> {
        let vault = try await KeePassBackend(fileData: data, password: password).load()
        return Set(vault.ciphers.map(\.name))
    }

    // MARK: Isolation

    /// The race this exists to prevent: an edit landing after the snapshot was taken but before
    /// it was built. The build must write the state at snapshot time, not the edit.
    func testEditAfterTheSnapshotIsNotWritten() async throws {
        let (backend, _) = try await openBackend()
        let snapshot = try backend.makeSaveSnapshot(profileOverride: .lightArgon2d)

        _ = try backend.addCipher(newLogin("Added After Snapshot"))

        let written = try KeePassBackend.build(snapshot)
        let saved = try await names(in: written)       // outside the assertion: no `await` there
        XCTAssertFalse(saved.contains("Added After Snapshot"),
                       "an edit made after the snapshot reached the file")
    }

    /// And the converse: an edit before the snapshot is in it.
    func testEditBeforeTheSnapshotIsWritten() async throws {
        let (backend, _) = try await openBackend()
        _ = try backend.addCipher(newLogin("Added Before Snapshot"))

        let written = try KeePassBackend.build(try backend.makeSaveSnapshot(profileOverride: .lightArgon2d))
        let saved = try await names(in: written)
        XCTAssertTrue(saved.contains("Added Before Snapshot"))
    }

    /// Two snapshots taken around an edit describe two different states, and each builds to
    /// its own. This is what makes chaining saves in call order correct.
    func testSuccessiveSnapshotsCaptureSuccessiveStates() async throws {
        let (backend, _) = try await openBackend()
        let first = try backend.makeSaveSnapshot(profileOverride: .lightArgon2d)
        _ = try backend.addCipher(newLogin("Second State"))
        let second = try backend.makeSaveSnapshot(profileOverride: .lightArgon2d)

        let firstNames = try await names(in: KeePassBackend.build(first))
        let secondNames = try await names(in: KeePassBackend.build(second))
        XCTAssertFalse(firstNames.contains("Second State"))
        XCTAssertTrue(secondNames.contains("Second State"))
    }

    // MARK: Verification

    func testVerifyAcceptsWhatTheSnapshotBuilt() throws {
        let backend = KeePassBackend(fileData: fixture, password: password)
        let snapshot = try backend.makeSaveSnapshot(profileOverride: .lightArgon2d)
        XCTAssertNoThrow(try KeePassBackend.verify(try KeePassBackend.build(snapshot), against: snapshot))
    }

    /// Verification compares against the entries fixed at snapshot time. A file written from a
    /// different state — here, one with an extra entry — must be rejected, or the save path would
    /// accept a file that does not hold what the user saved.
    func testVerifyRejectsAFileThatDoesNotMatchTheSnapshot() async throws {
        let (backend, _) = try await openBackend()
        let before = try backend.makeSaveSnapshot(profileOverride: .lightArgon2d)
        _ = try backend.addCipher(newLogin("Extra"))
        let after = try KeePassBackend.build(try backend.makeSaveSnapshot(profileOverride: .lightArgon2d))

        XCTAssertThrowsError(try KeePassBackend.verify(after, against: before))
    }

    func testVerifyRejectsBytesThatAreNotTheFile() throws {
        let snapshot = try KeePassBackend(fileData: fixture, password: password)
            .makeSaveSnapshot(profileOverride: .lightArgon2d)
        XCTAssertThrowsError(try KeePassBackend.verify(Data("not a database".utf8), against: snapshot))
    }

    // MARK: The synchronous wrappers

    /// `serialize` and `verifyRoundTrip` are now built on the snapshot. They must still agree
    /// with each other, as the tests elsewhere in the suite rely on them.
    func testSerializeAndVerifyRoundTripStillAgree() throws {
        let backend = KeePassBackend(fileData: fixture, password: password)
        let data = try backend.serialize(profileOverride: .lightArgon2d)
        XCTAssertNoThrow(try backend.verifyRoundTrip(data))
    }

    // MARK: Re-reading after an edit

    /// `currentVault()` is the synchronous re-read used after a save; it must reflect edits
    /// already applied to the document, without a KDF or a disk read.
    func testCurrentVaultReflectsAppliedEdits() async throws {
        let (backend, original) = try await openBackend()
        _ = try backend.addCipher(newLogin("Visible Immediately"))

        let current = try backend.currentVault()
        XCTAssertEqual(current.ciphers.count, original.ciphers.count + 1)
        XCTAssertTrue(current.ciphers.contains { $0.name == "Visible Immediately" })
    }
}
