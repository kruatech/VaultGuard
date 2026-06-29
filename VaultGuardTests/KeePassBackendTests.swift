import XCTest
import Foundation
import CryptoKit

/// KeePass write path through the backend: edit / add / delete entries in the in-memory
/// document, serialize to a fresh KDBX 4, read it back, and verify. (Real-format validity is
/// separately confirmed by a Python mirror that pykeepass reads.)
final class KeePassBackendTests: XCTestCase {

    private let fixtureB64 =
        "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"

    private var fixture: Data { Data(base64Encoded: fixtureB64)! }
    private let light = KDBXProfile.lightArgon2d

    private func reopen(_ data: Data, password: String) async throws -> DecryptedVault {
        try await KeePassBackend(fileData: data, password: password, keyfile: nil).load()
    }

    func testReadAndFlags() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        XCTAssertFalse(backend.isReadOnly)
        XCTAssertEqual(backend.kind, .keepass)
        let vault = try await backend.load()
        XCTAssertEqual(vault.ciphers.count, 2)
        XCTAssertEqual(vault.folders.count, 1)
    }

    func testUpdateRoundTrip() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        let vault = try await backend.load()
        var ex = try XCTUnwrap(vault.ciphers.first { $0.name == "Example" })
        ex.login?.password = "CHANGED-PW"
        ex.login?.username = "alice2"
        try backend.updateCipher(ex)

        let data = try backend.serialize(profileOverride: light)
        let v2 = try await reopen(data, password: "test-password")
        let ex2 = try XCTUnwrap(v2.ciphers.first { $0.name == "Example" })
        XCTAssertEqual(ex2.login?.password, "CHANGED-PW")
        XCTAssertEqual(ex2.login?.username, "alice2")
        XCTAssertEqual(ex2.login?.uris?.first?.uri, "https://example.com")   // untouched field kept
        let root = try XCTUnwrap(v2.ciphers.first { $0.name == "Root Login" })
        XCTAssertEqual(root.login?.password, "hunter2")                       // other entry intact
    }

    func testAddRoundTrip() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        _ = try await backend.load()
        let newC = VaultCipher(
            id: "", organizationId: nil, folderId: nil, collectionIds: nil,
            type: .login, name: "Added", notes: "n",
            login: CipherLogin(username: "newu", password: "newp", totp: nil, uris: nil),
            card: nil, secureNote: nil, identity: nil, fields: nil, attachments: nil,
            favorite: false, reprompt: nil, creationDate: nil, revisionDate: nil, deletedDate: nil)
        let stored = try backend.addCipher(newC)
        XCTAssertFalse(stored.id.isEmpty)

        let data = try backend.serialize(profileOverride: light)
        let v2 = try await reopen(data, password: "test-password")
        XCTAssertEqual(v2.ciphers.count, 3)
        let added = try XCTUnwrap(v2.ciphers.first { $0.name == "Added" })
        XCTAssertEqual(added.login?.username, "newu")
        XCTAssertEqual(added.login?.password, "newp")
        XCTAssertNil(added.folderId)
    }

    func testDeleteRoundTrip() async throws {
        // Physical removal via permanentlyDeleteCipher. The recycle-bin path (the default for
        // deleteCipher) is covered by testDeleteMovesToRecycleBin / testDeleteFromRecycleBinIsPermanent.
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        let vault = try await backend.load()
        let ex = try XCTUnwrap(vault.ciphers.first { $0.name == "Example" })
        try backend.permanentlyDeleteCipher(id: ex.id)

        let data = try backend.serialize(profileOverride: light)
        let v2 = try await reopen(data, password: "test-password")
        XCTAssertEqual(v2.ciphers.count, 1)
        XCTAssertNil(v2.ciphers.first { $0.name == "Example" })
        XCTAssertNotNil(v2.ciphers.first { $0.name == "Root Login" })
    }

    // MARK: safe-save (verify + destructive guard)

    func testVerifyRoundTripPasses() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        _ = try await backend.load()
        let data = try backend.serialize(profileOverride: light)
        XCTAssertNoThrow(try backend.verifyRoundTrip(data))
    }

    func testVerifyRejectsGarbage() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        _ = try await backend.load()
        XCTAssertThrowsError(try backend.verifyRoundTrip(Data([0x00, 0x01, 0x02, 0x03, 0x04])))
    }

    func testCleanFixtureHasNoLossyFeatures() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        _ = try await backend.load()
        XCTAssertEqual(try backend.lossyFeaturesOnSave(), [])
    }

    func testLossyDetectorDoesNotFlagAttachments() throws {
        // Attachments are now passed through losslessly, so they are no longer flagged.
        let xml = "<KeePassFile><Root><Group><Entry>" +
                  "<Binary><Key>a.txt</Key><Value Ref=\"0\"/></Binary>" +
                  "</Entry></Group></Root></KeePassFile>"
        let doc = try XMLDocument(data: Data(xml.utf8), options: [])
        XCTAssertEqual(KDBXEditor.lossyFeatures(in: doc), [])
    }

    func testLossyDetectorCleanDoc() throws {
        let xml = "<KeePassFile><Root><Group><Entry>" +
                  "<String><Key>Title</Key><Value>x</Value></String>" +
                  "</Entry></Group></Root></KeePassFile>"
        let doc = try XMLDocument(data: Data(xml.utf8), options: [])
        XCTAssertEqual(KDBXEditor.lossyFeatures(in: doc), [])
    }
    // KDBX 4 fixture WITH one attachment ("note.txt" = "secret-bytes-12345"), light Argon2,
    // password "editpw". Entry "WithFile" (user "u", pass "pw").
    private let attFixtureB64 =
        "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"
    private var attFixture: Data { Data(base64Encoded: attFixtureB64)! }

    func testAttachmentSurvivesEditRoundTrip() async throws {
        let backend = KeePassBackend(fileData: attFixture, password: "editpw", keyfile: nil)
        let vault = try await backend.load()
        var e = try XCTUnwrap(vault.ciphers.first { $0.name == "WithFile" })
        e.login?.password = "edited-pw"
        try backend.updateCipher(e)

        let data = try backend.serialize(profileOverride: light)
        // File-level: the inner-header binary and its XML reference are preserved.
        let db = try KDBXReader.unlock(data: data, password: "editpw")
        XCTAssertEqual(db.binaries.count, 1)
        XCTAssertTrue(String(data: db.xml, encoding: .utf8)?.contains("note.txt") ?? false)
        // The edit applied, and no lossy guard fires anymore.
        XCTAssertEqual(try backend.lossyFeaturesOnSave(), [])
        let v2 = try await KeePassBackend(fileData: data, password: "editpw", keyfile: nil).load()
        XCTAssertEqual(v2.ciphers.first { $0.name == "WithFile" }?.login?.password, "edited-pw")
    }
    func testSerializePreservesProfile() async throws {
        // att_out fixture is AES-CBC + Argon2d. serialize() with no override keeps that profile.
        let backend = KeePassBackend(fileData: attFixture, password: "editpw", keyfile: nil)
        _ = try await backend.load()
        let data = try backend.serialize()
        let db = try KDBXReader.unlock(data: data, password: "editpw")
        guard case .aesCBC = db.profile.cipher else { return XCTFail("cipher changed") }
        guard case .argon2d = db.profile.kdf else { return XCTFail("kdf changed") }
    }
    // MARK: group CRUD

    func testAddFolderRoundTrip() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        _ = try await backend.load()
        let f = try backend.addFolder(name: "NewFolder")
        XCTAssertFalse(f.id.isEmpty)
        let data = try backend.serialize(profileOverride: light)
        let v2 = try await reopen(data, password: "test-password")
        XCTAssertNotNil(v2.folders.first { $0.name == "NewFolder" })
    }

    func testRenameFolderRoundTrip() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        let vault = try await backend.load()
        let email = try XCTUnwrap(vault.folders.first { $0.name == "Email" })
        try backend.renameFolder(id: email.id, newName: "Mail")
        let data = try backend.serialize(profileOverride: light)
        let v2 = try await reopen(data, password: "test-password")
        XCTAssertNotNil(v2.folders.first { $0.name == "Mail" })
        XCTAssertNil(v2.folders.first { $0.name == "Email" })
        XCTAssertEqual(v2.ciphers.first { $0.name == "Example" }?.folderId, email.id)
    }

    func testMoveCipherRoundTrip() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        let vault = try await backend.load()
        let email = try XCTUnwrap(vault.folders.first { $0.name == "Email" })
        let root = try XCTUnwrap(vault.ciphers.first { $0.name == "Root Login" })
        XCTAssertNil(root.folderId)
        try backend.moveCipher(id: root.id, toFolderId: email.id)
        let data = try backend.serialize(profileOverride: light)
        let v2 = try await reopen(data, password: "test-password")
        XCTAssertEqual(v2.ciphers.first { $0.name == "Root Login" }?.folderId, email.id)
    }

    func testDeleteFolderRoundTrip() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        let vault = try await backend.load()
        let email = try XCTUnwrap(vault.folders.first { $0.name == "Email" })
        try backend.deleteFolder(id: email.id)
        let data = try backend.serialize(profileOverride: light)
        let v2 = try await reopen(data, password: "test-password")
        // The group is moved into the Recycle Bin: its entry surfaces in trash, siblings intact.
        let ex = v2.ciphers.first { $0.name == "Example" }
        XCTAssertNotNil(ex)
        XCTAssertNotNil(ex?.deletedDate)
        XCTAssertNotNil(v2.folders.first { $0.name == "Recycle Bin" })
        XCTAssertNotNil(v2.ciphers.first { $0.name == "Root Login" })
    }
    // MARK: history & times

    func testEditCreatesHistory() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        let vault = try await backend.load()
        var ex = try XCTUnwrap(vault.ciphers.first { $0.name == "Example" })
        ex.login?.password = "v2"
        try backend.updateCipher(ex)
        let data = try backend.serialize(profileOverride: light)
        let db = try KDBXReader.unlock(data: data, password: "test-password")
        let doc = try XMLDocument(data: db.xml, options: [])
        let hist = try doc.nodes(forXPath: "//Entry[not(ancestor::History)][String[Key=\'Title\' and Value=\'Example\']]/History/Entry")
        XCTAssertEqual(hist.count, 1)
        let v2 = try await reopen(data, password: "test-password")
        XCTAssertEqual(v2.ciphers.first { $0.name == "Example" }?.login?.password, "v2")
    }

    func testEditTwiceGrowsHistory() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        let vault = try await backend.load()
        var ex = try XCTUnwrap(vault.ciphers.first { $0.name == "Example" })
        ex.login?.password = "v2"; try backend.updateCipher(ex)
        ex.login?.password = "v3"; try backend.updateCipher(ex)
        let data = try backend.serialize(profileOverride: light)
        let db = try KDBXReader.unlock(data: data, password: "test-password")
        let doc = try XMLDocument(data: db.xml, options: [])
        let hist = try doc.nodes(forXPath: "//Entry[not(ancestor::History)][String[Key=\'Title\' and Value=\'Example\']]/History/Entry")
        XCTAssertEqual(hist.count, 2)
        let v2 = try await reopen(data, password: "test-password")
        XCTAssertEqual(v2.ciphers.first { $0.name == "Example" }?.login?.password, "v3")
    }

    func testNewEntryHasTimes() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        _ = try await backend.load()
        let newC = VaultCipher(
            id: "", organizationId: nil, folderId: nil, collectionIds: nil,
            type: .login, name: "Timed", notes: nil,
            login: CipherLogin(username: "u", password: "p", totp: nil, uris: nil),
            card: nil, secureNote: nil, identity: nil, fields: nil, attachments: nil,
            favorite: false, reprompt: nil, creationDate: nil, revisionDate: nil, deletedDate: nil)
        _ = try backend.addCipher(newC)
        let data = try backend.serialize(profileOverride: light)
        let db = try KDBXReader.unlock(data: data, password: "test-password")
        let doc = try XMLDocument(data: db.xml, options: [])
        let times = try doc.nodes(forXPath: "//Entry[not(ancestor::History)][String[Key=\'Title\' and Value=\'Timed\']]/Times/CreationTime")
        XCTAssertEqual(times.count, 1)
    }

    // MARK: recycle bin

    func testDeleteMovesToRecycleBin() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        let vault = try await backend.load()
        let ex = try XCTUnwrap(vault.ciphers.first { $0.name == "Example" })
        try backend.deleteCipher(id: ex.id)
        let data = try backend.serialize(profileOverride: light)
        let v2 = try await reopen(data, password: "test-password")
        let moved = v2.ciphers.first { $0.name == "Example" }
        XCTAssertNotNil(moved)                       // not destroyed
        XCTAssertNotNil(moved?.deletedDate)          // shows up in trash
        XCTAssertNotNil(v2.folders.first { $0.name == "Recycle Bin" })
        XCTAssertNotNil(v2.ciphers.first { $0.name == "Root Login" })   // sibling intact
    }

    func testDeleteFromRecycleBinIsPermanent() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        let vault = try await backend.load()
        let ex = try XCTUnwrap(vault.ciphers.first { $0.name == "Example" })
        try backend.deleteCipher(id: ex.id)
        let data1 = try backend.serialize(profileOverride: light)

        let backend2 = KeePassBackend(fileData: data1, password: "test-password", keyfile: nil)
        let vault2 = try await backend2.load()
        let ex2 = try XCTUnwrap(vault2.ciphers.first { $0.name == "Example" })
        XCTAssertNotNil(ex2.deletedDate)             // confirm it is in the bin
        try backend2.deleteCipher(id: ex2.id)        // delete again → permanent
        let data2 = try backend2.serialize(profileOverride: light)
        let v3 = try await reopen(data2, password: "test-password")
        XCTAssertNil(v3.ciphers.first { $0.name == "Example" })
    }

    func testRestoreCipher() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        let vault = try await backend.load()
        let ex = try XCTUnwrap(vault.ciphers.first { $0.name == "Example" })
        try backend.deleteCipher(id: ex.id)
        try backend.restoreCipher(id: ex.id)
        let data = try backend.serialize(profileOverride: light)
        let v2 = try await reopen(data, password: "test-password")
        let restored = try XCTUnwrap(v2.ciphers.first { $0.name == "Example" })
        XCTAssertNil(restored.deletedDate)           // out of the bin
    }
    // KDBX 4 fixture WITH gzip compression (CompressionFlags=1), light Argon2d, password "cpw".
    // Same contents as the main fixture (Example alice/S3cr3t!Pass, Root Login bob/hunter2).
    private let compressedFixtureB64 =
        "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"
    private var compressedFixture: Data { Data(base64Encoded: compressedFixtureB64)! }

    func testReadsGzipCompressedFixture() async throws {
        let backend = KeePassBackend(fileData: compressedFixture, password: "cpw", keyfile: nil)
        let vault = try await backend.load()
        XCTAssertEqual(vault.ciphers.first { $0.name == "Example" }?.login?.password, "S3cr3t!Pass")
        XCTAssertEqual(vault.ciphers.first { $0.name == "Root Login" }?.login?.password, "hunter2")
    }

    func testCompressionPreservedOnWrite() async throws {
        let backend = KeePassBackend(fileData: compressedFixture, password: "cpw", keyfile: nil)
        _ = try await backend.load()
        let data = try backend.serialize()        // no override -> preserves compression=1 (gzip on write)
        let v2 = try await reopen(data, password: "cpw")
        XCTAssertEqual(v2.ciphers.first { $0.name == "Example" }?.login?.password, "S3cr3t!Pass")
        XCTAssertEqual(v2.ciphers.first { $0.name == "Root Login" }?.login?.password, "hunter2")
    }

    func testTimesMappedToModel() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        _ = try await backend.load()
        let c = VaultCipher(
            id: "", organizationId: nil, folderId: nil, collectionIds: nil,
            type: .login, name: "Dated", notes: nil,
            login: CipherLogin(username: "u", password: "p", totp: nil, uris: nil),
            card: nil, secureNote: nil, identity: nil, fields: nil, attachments: nil,
            favorite: false, reprompt: nil, creationDate: nil, revisionDate: nil, deletedDate: nil)
        _ = try backend.addCipher(c)
        let data = try backend.serialize(profileOverride: light)
        let v2 = try await reopen(data, password: "test-password")
        let dated = try XCTUnwrap(v2.ciphers.first { $0.name == "Dated" })
        XCTAssertNotNil(dated.creationDate)
        XCTAssertNotNil(dated.revisionDate)
        if let d = dated.creationDate { XCTAssertLessThan(abs(d.timeIntervalSinceNow), 86_400) }
    }

    // MARK: key-file v2 (#9)

    func testKeyfileV2HashValidation() throws {
        let key = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let hashHex = Data(SHA256.hash(data: key)).prefix(4).map { String(format: "%02X", $0) }.joined()
        let body = key.map { String(format: "%02X", $0) }.joined()
        let v2 = "<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"\(hashHex)\">\(body)</Data></Key></KeyFile>"
        XCTAssertEqual(KDBXReader.keyfileKey(Data(v2.utf8)), key)

        // Corrupted integrity hash → parse fails, falls back to SHA256(file) (not the key).
        let badHash = (hashHex == "00000000") ? "11111111" : "00000000"
        let bad = "<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"\(badHash)\">\(body)</Data></Key></KeyFile>"
        XCTAssertNotEqual(KDBXReader.keyfileKey(Data(bad.utf8)), key)
    }

    func testNestedFolderCreation() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        _ = try await backend.load()
        let leaf = try backend.addFolder(name: "Work/Servers")
        XCTAssertEqual(leaf.name, "Work/Servers")
        _ = try backend.addFolder(name: "Work/Other")          // reuse the existing "Work"
        let data = try backend.serialize(profileOverride: light)
        let v2 = try await reopen(data, password: "test-password")
        XCTAssertNotNil(v2.folders.first { $0.name == "Work" })
        XCTAssertNotNil(v2.folders.first { $0.name == "Work/Servers" })
        XCTAssertNotNil(v2.folders.first { $0.name == "Work/Other" })
        XCTAssertEqual(v2.folders.filter { $0.name == "Work" }.count, 1)   // created once
    }

    // MARK: attachments (#2)

    func testExistingAttachmentSurfaces() async throws {
        let backend = KeePassBackend(fileData: attFixture, password: "editpw", keyfile: nil)
        let vault = try await backend.load()
        let withFile = try XCTUnwrap(vault.ciphers.first { $0.name == "WithFile" })
        let att = try XCTUnwrap(withFile.attachments?.first { $0.fileName == "note.txt" })
        let ref = try XCTUnwrap(att.id.flatMap { Int($0) })
        XCTAssertEqual(backend.attachmentData(ref: ref), Data("secret-bytes-12345".utf8))
    }

    func testAddAttachmentRoundTrip() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        let vault = try await backend.load()
        let example = try XCTUnwrap(vault.ciphers.first { $0.name == "Example" })
        let payload = Data("hello world".utf8)
        let added = try backend.addAttachment(cipherId: example.id, fileName: "test.txt", data: payload)
        XCTAssertEqual(added.fileName, "test.txt")

        let data = try backend.serialize(profileOverride: light)
        let reopened = KeePassBackend(fileData: data, password: "test-password", keyfile: nil)
        let v2 = try await reopened.load()
        let ex2 = try XCTUnwrap(v2.ciphers.first { $0.name == "Example" })
        let a2 = try XCTUnwrap(ex2.attachments?.first { $0.fileName == "test.txt" })
        let ref = try XCTUnwrap(a2.id.flatMap { Int($0) })
        XCTAssertEqual(reopened.attachmentData(ref: ref), payload)
    }

    func testRemoveAttachmentRoundTrip() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "test-password", keyfile: nil)
        let vault = try await backend.load()
        let example = try XCTUnwrap(vault.ciphers.first { $0.name == "Example" })
        let first = try backend.addAttachment(cipherId: example.id, fileName: "a.txt", data: Data("AAA".utf8))
        let second = try backend.addAttachment(cipherId: example.id, fileName: "b.txt", data: Data("BBBB".utf8))
        try backend.removeAttachment(cipherId: example.id, ref: try XCTUnwrap(Int(first.id ?? "")))

        let data = try backend.serialize(profileOverride: light)
        let reopened = KeePassBackend(fileData: data, password: "test-password", keyfile: nil)
        let v2 = try await reopened.load()
        let ex2 = try XCTUnwrap(v2.ciphers.first { $0.name == "Example" })
        let names = Set((ex2.attachments ?? []).compactMap { $0.fileName })
        XCTAssertEqual(names, ["b.txt"])                       // a.txt reference removed
        // b.txt keeps its ref (orphaned binary left in pool → indices stay stable)
        let bRef = try XCTUnwrap(Int(second.id ?? ""))
        XCTAssertEqual(reopened.attachmentData(ref: bRef), Data("BBBB".utf8))
    }

    // MARK: create new database

    func testEmptyDatabaseRoundTrip() async throws {
        let doc = try KDBXWriter.emptyDatabase(name: "My Vault")
        let data = try KDBXWriter.build(plaintextXML: doc, password: "newpw", keyfile: nil, profile: light)
        let backend = KeePassBackend(fileData: data, password: "newpw", keyfile: nil)
        let vault = try await backend.load()
        XCTAssertEqual(vault.profileName, "My Vault")
        XCTAssertTrue(vault.ciphers.isEmpty)

        // A fresh database is fully usable: add an entry, round-trip it.
        let added = VaultCipher(id: "", organizationId: nil, folderId: nil, collectionIds: nil,
                                type: .login, name: "First", notes: nil,
                                login: CipherLogin(username: "u", password: "p", totp: nil, uris: nil),
                                card: nil, secureNote: nil, identity: nil, fields: nil, attachments: nil,
                                favorite: false, reprompt: nil, creationDate: nil, revisionDate: nil, deletedDate: nil)
        _ = try backend.addCipher(added)
        let v2 = try await reopen(try backend.serialize(profileOverride: light), password: "newpw")
        XCTAssertEqual(v2.ciphers.map { $0.name }, ["First"])

        // Wrong password is rejected.
        let bad = KeePassBackend(fileData: data, password: "wrong", keyfile: nil)
        do { _ = try await bad.load(); XCTFail("wrong password opened a database") } catch {}
    }

    // MARK: export Bitwarden → KDBX

    func testExportToKDBXRoundTrip() async throws {
        let login = VaultCipher(
            id: "1", organizationId: "org1", folderId: "f1", collectionIds: nil,
            type: .login, name: "GitHub", notes: "my note",
            login: CipherLogin(username: "octocat", password: "s3cr3t", totp: "JBSWY3DPEHPK3PXP",
                               uris: [CipherUri(uri: "https://github.com", match: nil),
                                      CipherUri(uri: "https://gist.github.com", match: nil)]),
            card: nil, secureNote: nil, identity: nil,
            fields: [CipherField(name: "API Key", value: "abc123", type: .hidden)],
            attachments: [CipherAttachment(id: "a1", fileName: "key.txt", size: nil, sizeName: nil, url: nil, key: nil)],
            favorite: true, reprompt: nil, creationDate: nil, revisionDate: nil, deletedDate: nil)

        let card = VaultCipher(
            id: "2", organizationId: nil, folderId: nil, collectionIds: nil,
            type: .card, name: "Visa", notes: nil, login: nil,
            card: CipherCard(cardholderName: "John Doe", brand: "Visa", number: "4111111111111111",
                             expMonth: "12", expYear: "2027", code: "123"),
            secureNote: nil, identity: nil, fields: nil, attachments: nil,
            favorite: false, reprompt: nil, creationDate: nil, revisionDate: nil, deletedDate: nil)

        let deleted = VaultCipher(
            id: "3", organizationId: nil, folderId: nil, collectionIds: nil,
            type: .login, name: "OldAcct", notes: nil,
            login: CipherLogin(username: "old", password: "x", totp: nil, uris: nil),
            card: nil, secureNote: nil, identity: nil, fields: nil, attachments: nil,
            favorite: false, reprompt: nil, creationDate: nil, revisionDate: nil, deletedDate: Date())

        let (doc, binaries) = VaultMigrator.exportToKDBX(
            databaseName: "Export",
            ciphers: [login, card, deleted],
            folders: [VaultFolder(id: "f1", name: "Work", revisionDate: nil)],
            collections: [],
            organizations: [VaultOrganization(id: "org1", name: "Acme")],
            attachmentBytes: ["a1": Data("file-bytes-XYZ".utf8)])

        let data = try KDBXWriter.build(plaintextXML: doc, password: "exp", keyfile: nil, profile: light, binaries: binaries)
        let vault = try await reopen(data, password: "exp")

        let gh = try XCTUnwrap(vault.ciphers.first { $0.name == "GitHub" })
        XCTAssertEqual(gh.login?.username, "octocat")
        XCTAssertEqual(gh.login?.password, "s3cr3t")
        XCTAssertEqual(gh.login?.uris?.first?.uri, "https://github.com")
        XCTAssertEqual(gh.fields?.first { $0.name == "API Key" }?.value, "abc123")
        XCTAssertEqual(gh.login?.totp, "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP")
        XCTAssertEqual(gh.fields?.first { $0.name == "KP2A_URL_1" }?.value, "https://gist.github.com")
        XCTAssertNotNil(gh.attachments?.first { $0.fileName == "key.txt" })
        XCTAssertNotNil(vault.folders.first { $0.name == "Organizations/Acme/Work" })

        let visa = try XCTUnwrap(vault.ciphers.first { $0.name == "Visa" })
        XCTAssertEqual(visa.fields?.first { $0.name == "Number" }?.value, "4111111111111111")
        XCTAssertEqual(visa.fields?.first { $0.name == "CVV" }?.value, "123")

        let old = try XCTUnwrap(vault.ciphers.first { $0.name == "OldAcct" })
        XCTAssertNotNil(old.deletedDate)
    }

    // MARK: import KDBX → Bitwarden shape

    func testImportFromKDBXTransform() async throws {
        let login = VaultCipher(
            id: "1", organizationId: nil, folderId: "f1", collectionIds: nil,
            type: .login, name: "GitHub", notes: "n",
            login: CipherLogin(username: "octocat", password: "s3cr3t", totp: "JBSWY3DPEHPK3PXP",
                               uris: [CipherUri(uri: "https://github.com", match: nil),
                                      CipherUri(uri: "https://gist.github.com", match: nil)]),
            card: nil, secureNote: nil, identity: nil,
            fields: [CipherField(name: "API Key", value: "abc123", type: .hidden)],
            attachments: nil, favorite: false, reprompt: nil,
            creationDate: nil, revisionDate: nil, deletedDate: nil)
        let deleted = VaultCipher(
            id: "2", organizationId: nil, folderId: nil, collectionIds: nil,
            type: .login, name: "OldAcct", notes: nil,
            login: CipherLogin(username: "old", password: "x", totp: nil, uris: nil),
            card: nil, secureNote: nil, identity: nil, fields: nil, attachments: nil,
            favorite: false, reprompt: nil, creationDate: nil, revisionDate: nil, deletedDate: Date())

        let (doc, binaries) = VaultMigrator.exportToKDBX(
            databaseName: "X", ciphers: [login, deleted],
            folders: [VaultFolder(id: "f1", name: "Work", revisionDate: nil)],
            collections: [], organizations: [])
        let data = try KDBXWriter.build(plaintextXML: doc, password: "p", keyfile: nil, profile: light, binaries: binaries)
        let vault = try await KeePassBackend(fileData: data, password: "p", keyfile: nil).load()

        let imported = VaultMigrator.importFromKDBX(ciphers: vault.ciphers, folders: vault.folders)

        XCTAssertNil(imported.first { $0.cipher.name == "OldAcct" })          // recycle-bin skipped
        let gh = try XCTUnwrap(imported.first { $0.cipher.name == "GitHub" })
        XCTAssertEqual(gh.cipher.login?.totp, "otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP")
        XCTAssertEqual(gh.cipher.login?.uris?.count, 2)
        XCTAssertEqual(gh.cipher.login?.uris?.last?.uri, "https://gist.github.com")
        XCTAssertEqual(gh.folderPath, "Work")
        XCTAssertNil(gh.cipher.fields?.first { $0.name == "otp" })            // folded into totp
        XCTAssertNil(gh.cipher.fields?.first { $0.name.hasPrefix("KP2A_URL_") })
        XCTAssertNotNil(gh.cipher.fields?.first { $0.name == "API Key" })     // real custom field kept
        XCTAssertEqual(gh.cipher.id, "")                                      // server assigns id
    }

    // MARK: Bitwarden Send crypto

    func testSendCryptoRoundTrip() throws {
        let crypto = CryptoService()
        crypto.restoreSession(userKey: Data((0..<64).map { _ in UInt8.random(in: 0...255) }), passwordHash: "")
        let material = try crypto.makeSendKeyMaterial()
        let enc = try crypto.encryptSendString("the secret payload", key: material.cryptoKey)
        XCTAssertEqual(try crypto.decryptData(enc, key: material.cryptoKey), Data("the secret payload".utf8))
        XCTAssertFalse(material.encryptedKey.isEmpty)
        XCTAssertEqual(material.fragment.count, 22)            // 16 bytes, base64url, no padding
        XCTAssertFalse(material.fragment.contains("="))
        XCTAssertFalse(material.fragment.contains("+") || material.fragment.contains("/"))

        // File Send path: encrypt a buffer with the send key, decrypt it back.
        let fileBytes = Data((0..<200).map { _ in UInt8.random(in: 0...255) })
        let encBuf = try crypto.encryptBuffer(fileBytes, key: material.cryptoKey)
        XCTAssertEqual(try crypto.decryptRawBuffer(encBuf, key: material.cryptoKey), fileBytes)
    }
    // MARK: Bitwarden JSON import

    func testImportBitwardenJSON() throws {
        let json = """
        {
          "encrypted": false,
          "folders": [ { "id": "f1", "name": "Work/Servers" } ],
          "items": [
            { "type": 1, "name": "GitHub", "folderId": "f1", "favorite": true, "reprompt": 1,
              "notes": "note",
              "login": { "username": "octocat", "password": "p",
                         "totp": "JBSW", "uris": [ { "match": null, "uri": "https://github.com" } ] },
              "fields": [ { "name": "API", "value": "x", "type": 1 } ] },
            { "type": 3, "name": "Visa",
              "card": { "cardholderName": "John", "brand": "Visa", "number": "4111",
                        "expMonth": "12", "expYear": "2027", "code": "123" } },
            { "type": 2, "name": "Note", "secureNote": { "type": 0 }, "notes": "secret" },
            { "type": 4, "name": "Me",
              "identity": { "firstName": "Jane", "lastName": "Doe", "email": "j@d.com", "ssn": "111" } }
          ]
        }
        """
        let entries = try VaultMigrator.importBitwardenJSON(data: Data(json.utf8))
        XCTAssertEqual(entries.count, 4)

        let gh = try XCTUnwrap(entries.first { $0.cipher.name == "GitHub" })
        XCTAssertEqual(gh.cipher.type, .login)
        XCTAssertEqual(gh.cipher.login?.username, "octocat")
        XCTAssertEqual(gh.cipher.login?.totp, "JBSW")
        XCTAssertEqual(gh.cipher.login?.uris?.first?.uri, "https://github.com")
        XCTAssertEqual(gh.cipher.favorite, true)
        XCTAssertEqual(gh.cipher.reprompt, 1)
        XCTAssertEqual(gh.cipher.fields?.first?.name, "API")
        XCTAssertEqual(gh.cipher.fields?.first?.type, .hidden)
        XCTAssertEqual(gh.folderPath, "Work/Servers")

        let visa = try XCTUnwrap(entries.first { $0.cipher.name == "Visa" })
        XCTAssertEqual(visa.cipher.type, .card)
        XCTAssertEqual(visa.cipher.card?.number, "4111")
        XCTAssertEqual(visa.cipher.card?.expMonth, "12")

        let note = try XCTUnwrap(entries.first { $0.cipher.name == "Note" })
        XCTAssertEqual(note.cipher.type, .secureNote)
        XCTAssertEqual(note.cipher.notes, "secret")

        let me = try XCTUnwrap(entries.first { $0.cipher.name == "Me" })
        XCTAssertEqual(me.cipher.type, .identity)
        XCTAssertEqual(me.cipher.identity?.email, "j@d.com")
    }
    // MARK: Import dedup

    func testDedupEntries() throws {
        func mk(_ name: String, user: String? = nil, type: CipherType = .login) -> VaultCipher {
            VaultCipher(id: "", organizationId: nil, folderId: nil, collectionIds: nil,
                        type: type, name: name, notes: nil,
                        login: type == .login ? CipherLogin(username: user, password: nil, totp: nil, uris: nil) : nil,
                        card: nil, secureNote: nil, identity: nil, fields: nil, attachments: nil,
                        favorite: false, reprompt: nil, creationDate: nil, revisionDate: nil, deletedDate: nil)
        }
        let existing = [mk("GitHub", user: "octocat")]
        let incoming = [
            VaultMigrator.ImportedEntry(cipher: mk("GitHub", user: "octocat"), folderPath: nil), // dup of existing
            VaultMigrator.ImportedEntry(cipher: mk("GitLab", user: "me"), folderPath: nil),       // new
            VaultMigrator.ImportedEntry(cipher: mk("GitLab", user: "me"), folderPath: "X"),        // dup within batch
            VaultMigrator.ImportedEntry(cipher: mk("GitHub", user: "other"), folderPath: nil),     // same name, diff user → new
        ]
        let out = VaultMigrator.dedupEntries(incoming, against: existing)
        XCTAssertEqual(out.count, 2)
        XCTAssertTrue(out.contains { $0.cipher.name == "GitLab" })
        XCTAssertTrue(out.contains { $0.cipher.name == "GitHub" && $0.cipher.login?.username == "other" })
        XCTAssertFalse(out.contains { $0.cipher.login?.username == "octocat" })
    }
    // MARK: CSV import

    func testImportLastPassCSV() throws {
        let csv = """
        url,username,password,totp,extra,name,grouping,fav
        https://github.com,octocat,p@ss,JBSW,my note,GitHub,Dev/Work,1
        http://sn,,,,Secret text,My Note,Personal,0
        """
        let entries = try VaultMigrator.importCSV(data: Data(csv.utf8))
        XCTAssertEqual(entries.count, 2)
        let gh = try XCTUnwrap(entries.first { $0.cipher.name == "GitHub" })
        XCTAssertEqual(gh.cipher.type, .login)
        XCTAssertEqual(gh.cipher.login?.username, "octocat")
        XCTAssertEqual(gh.cipher.login?.totp, "JBSW")
        XCTAssertEqual(gh.cipher.login?.uris?.first?.uri, "https://github.com")
        XCTAssertEqual(gh.cipher.notes, "my note")
        XCTAssertEqual(gh.cipher.favorite, true)
        XCTAssertEqual(gh.folderPath, "Dev/Work")
        let note = try XCTUnwrap(entries.first { $0.cipher.name == "My Note" })
        XCTAssertEqual(note.cipher.type, .secureNote)
        XCTAssertEqual(note.cipher.notes, "Secret text")
    }

    func testImportBitwardenCSV() throws {
        let csv = """
        folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp,reprompt
        Work,1,login,GitHub,note,API: xyz,https://github.com,octocat,pw,JBSW,0
        ,0,note,Secret,my secret,,,,,,
        """
        let entries = try VaultMigrator.importCSV(data: Data(csv.utf8))
        XCTAssertEqual(entries.count, 2)
        let gh = try XCTUnwrap(entries.first { $0.cipher.name == "GitHub" })
        XCTAssertEqual(gh.cipher.type, .login)
        XCTAssertEqual(gh.cipher.login?.username, "octocat")
        XCTAssertEqual(gh.cipher.login?.totp, "JBSW")
        XCTAssertEqual(gh.cipher.favorite, true)
        XCTAssertEqual(gh.folderPath, "Work")
        XCTAssertEqual(gh.cipher.fields?.first?.name, "API")
        XCTAssertEqual(gh.cipher.fields?.first?.value, "xyz")
        let note = try XCTUnwrap(entries.first { $0.cipher.name == "Secret" })
        XCTAssertEqual(note.cipher.type, .secureNote)
        XCTAssertEqual(note.cipher.notes, "my secret")
    }

    func testCSVQuotingAndCommas() throws {
        let csv = "name,notes\n\"He said \"\"hi\"\"\",\"a, b, c\"\n"
        let rows = VaultMigrator.parseCSV(csv)
        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows[1][0], "He said \"hi\"")
        XCTAssertEqual(rows[1][1], "a, b, c")
    }
    // MARK: FIDO2 / passkey crypto

    func testFido2WebAuthnFormats() throws {
        let (cred, key) = try Fido2.createCredential(rpId: "example.com", userHandle: Data("u".utf8), userName: "user")
        XCTAssertEqual(cred.credentialId.count, 32)
        XCTAssertEqual(key.rawRepresentation, cred.privateKey)

        let (x, y) = Fido2.coordinates(key.publicKey)
        XCTAssertEqual(x.count, 32)
        XCTAssertEqual(y.count, 32)

        let cose = Fido2.coseKey(x: x, y: y)
        XCTAssertEqual(cose.count, 77)
        XCTAssertEqual([UInt8](cose.prefix(10)), [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20])

        let acd = Fido2.attestedCredentialData(aaguid: Data(count: 16), credentialId: cred.credentialId, coseKey: cose)
        XCTAssertEqual(acd.count, 16 + 2 + 32 + 77)

        let flagsAT = Fido2.Flags.userPresent | Fido2.Flags.userVerified | Fido2.Flags.attestedCredentialData
        let authData = Fido2.authenticatorData(rpId: "example.com", flags: flagsAT, signCount: 0, attestedCredentialData: acd)
        XCTAssertEqual(authData.count, 164)
        XCTAssertEqual(authData.prefix(32), Data(SHA256.hash(data: Data("example.com".utf8))))
        XCTAssertEqual(authData[authData.startIndex + 32], 0x45)

        let attObj = Fido2.attestationObject(authData: authData)
        XCTAssertEqual(attObj.count, 194)
        XCTAssertEqual([UInt8](attObj.prefix(5)), [0xa3, 0x63, 0x66, 0x6d, 0x74])

        // Assertion: sign authData(no AT) || clientDataHash and verify with the public key.
        let assertAuth = Fido2.authenticatorData(rpId: "example.com",
            flags: Fido2.Flags.userPresent | Fido2.Flags.userVerified, signCount: 1, attestedCredentialData: nil)
        let clientDataHash = Data(SHA256.hash(data: Data("{}".utf8)))
        let sig = try Fido2.assertionSignature(privateKey: key, authenticatorData: assertAuth, clientDataHash: clientDataHash)
        let parsed = try P256.Signing.ECDSASignature(derRepresentation: sig)
        XCTAssertTrue(key.publicKey.isValidSignature(parsed, for: assertAuth + clientDataHash))

        // Restore the key from its stored raw scalar.
        let restored = try P256.Signing.PrivateKey(rawRepresentation: cred.privateKey)
        XCTAssertEqual(restored.publicKey.rawRepresentation, key.publicKey.rawRepresentation)
    }
    func testPasskeyCredentialCodable() throws {
        let (c1, _) = try Fido2.createCredential(rpId: "github.com", userHandle: Data([1, 2, 3]), userName: "octocat")
        var c2 = c1
        c2.counter = 7
        let blob = try JSONEncoder().encode([c1, c2])
        let back = try JSONDecoder().decode([Fido2.Credential].self, from: blob)
        XCTAssertEqual(back.count, 2)
        XCTAssertEqual(back[0].credentialId, c1.credentialId)
        XCTAssertEqual(back[0].privateKey, c1.privateKey)
        XCTAssertEqual(back[0].userHandle, Data([1, 2, 3]))
        XCTAssertEqual(back[0].rpId, "github.com")
        XCTAssertEqual(back[0].userName, "octocat")
        XCTAssertEqual(back[1].counter, 7)
        // The stored private key restores a usable signing key.
        let key = try P256.Signing.PrivateKey(rawRepresentation: back[0].privateKey)
        XCTAssertEqual(key.rawRepresentation, c1.privateKey)
    }
}
