import XCTest
import Foundation

/// Write path round-trip: read the fixture → make an editable plaintext XMLDocument →
/// KDBXWriter.build a fresh KDBX 4 → read it back → values match. Proves the encoder
/// (header, VariantDictionary, key schedule, HMAC blocks, AES-CBC, inner stream) is the
/// exact inverse of the reader. (Real-format validity is separately confirmed by a Python
/// mirror that pykeepass reads.)
final class KDBXWriterTests: XCTestCase {

    private let fixtureB64 =
        "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"

    private var fixture: Data { Data(base64Encoded: fixtureB64)! }
    private let light = KDBXProfile.lightArgon2d

    private func editableFixture() throws -> XMLDocument {
        let db = try KDBXReader.unlock(data: fixture, password: "test-password")
        let stream = try XCTUnwrap(KDBXProtectedStream(streamID: db.innerStreamID, key: db.innerStreamKey))
        return try KDBXEditor.makeEditable(xml: db.xml, stream: stream)
    }

    private func readBack(_ data: Data, password: String) throws -> DecryptedVault {
        let db = try KDBXReader.unlock(data: data, password: password)
        let stream = try XCTUnwrap(KDBXProtectedStream(streamID: db.innerStreamID, key: db.innerStreamKey))
        return KDBXVaultMapper.map(xml: db.xml, stream: stream)
    }

    func testRoundTripUnchanged() throws {
        let doc = try editableFixture()
        let data = try KDBXWriter.build(plaintextXML: doc, password: "newpw", profile: light)
        let vault = try readBack(data, password: "newpw")

        XCTAssertEqual(vault.ciphers.count, 2)
        XCTAssertEqual(vault.folders.first?.name, "Email")
        let ex = try XCTUnwrap(vault.ciphers.first { $0.name == "Example" })
        XCTAssertEqual(ex.login?.username, "alice")
        XCTAssertEqual(ex.login?.password, "S3cr3t!Pass")
        XCTAssertEqual(ex.login?.uris?.first?.uri, "https://example.com")
        let root = try XCTUnwrap(vault.ciphers.first { $0.name == "Root Login" })
        XCTAssertEqual(root.login?.password, "hunter2")
    }

    func testWriteWrongPasswordRejected() throws {
        let data = try KDBXWriter.build(plaintextXML: try editableFixture(), password: "newpw", profile: light)
        XCTAssertThrowsError(try KDBXReader.unlock(data: data, password: "bad")) { error in
            guard case KDBXError.wrongCredentials = error else { return XCTFail("got \(error)") }
        }
    }

    func testEditPasswordRoundTrip() throws {
        let doc = try editableFixture()
        // Change "Example" entry's password via the document, then write + read back.
        let nodes = try doc.nodes(forXPath: "//Entry[String[Key='Title' and Value='Example']]/String[Key='Password']/Value")
        let valueNode = try XCTUnwrap(nodes.first as? XMLElement)
        valueNode.stringValue = "EDITED-PASS"

        let data = try KDBXWriter.build(plaintextXML: doc, password: "newpw", profile: light)
        let vault = try readBack(data, password: "newpw")
        let ex = try XCTUnwrap(vault.ciphers.first { $0.name == "Example" })
        XCTAssertEqual(ex.login?.password, "EDITED-PASS")
        // Untouched entry still intact.
        let root = try XCTUnwrap(vault.ciphers.first { $0.name == "Root Login" })
        XCTAssertEqual(root.login?.password, "hunter2")
    }
    func testPreservesChaChaArgon2idProfile() throws {
        let profile = KDBXProfile(versionMajor: 4, versionMinor: 1, cipher: .chacha20, compression: 0,
                                  kdf: .argon2id(memoryKiB: 1024, iterations: 2, parallelism: 1))
        let data = try KDBXWriter.build(plaintextXML: try editableFixture(), password: "x", profile: profile)
        let db = try KDBXReader.unlock(data: data, password: "x")
        guard case .chacha20 = db.profile.cipher else { return XCTFail("cipher not chacha20") }
        guard case .argon2id = db.profile.kdf else { return XCTFail("kdf not argon2id") }
        XCTAssertEqual(db.profile.versionMajor, 4)
        let vault = try readBack(data, password: "x")
        XCTAssertEqual(vault.ciphers.count, 2)
    }

    func testPreservesAESKDFProfile() throws {
        let profile = KDBXProfile(versionMajor: 4, versionMinor: 0, cipher: .aesCBC, compression: 0,
                                  kdf: .aesKdf(rounds: 6000))
        let data = try KDBXWriter.build(plaintextXML: try editableFixture(), password: "x", profile: profile)
        let db = try KDBXReader.unlock(data: data, password: "x")
        guard case .aesCBC = db.profile.cipher else { return XCTFail("cipher not aes") }
        guard case .aesKdf(let rounds) = db.profile.kdf else { return XCTFail("kdf not aes-kdf") }
        XCTAssertEqual(rounds, 6000)
        XCTAssertEqual(db.profile.versionMinor, 0)
    }
}

