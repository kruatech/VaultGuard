import XCTest
import Foundation

/// Richer fixture: nested groups, custom fields (protected + plain), TOTP, and — most
/// importantly — an entry that comes AFTER a multi-version <History> block. The "After"
/// entry only decrypts correctly if history protected values were consumed from the inner
/// stream in document order, so this test proves the keystream stays aligned across history.
final class KDBXRichMapperTests: XCTestCase {

    private let fixtureB64 =
        "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"

    private var fixture: Data { Data(base64Encoded: fixtureB64)! }

    func testRichMapping() throws {
        let db = try KDBXReader.unlock(data: fixture, password: "pw2")
        let stream = try XCTUnwrap(KDBXProtectedStream(streamID: db.innerStreamID, key: db.innerStreamKey))
        let vault = KDBXVaultMapper.map(xml: db.xml, stream: stream)

        // Nested folders named by full path.
        let paths = Set(vault.folders.map { $0.name })
        XCTAssertTrue(paths.contains("Work"))
        XCTAssertTrue(paths.contains("Work/Servers"))

        // Entry inside the nested group, current password (NOT a historical one).
        let admin = try XCTUnwrap(vault.ciphers.first { $0.name == "DB Admin" })
        XCTAssertEqual(admin.login?.username, "root")
        XCTAssertEqual(admin.login?.password, "finalpass2")
        XCTAssertEqual(admin.login?.uris?.first?.uri, "https://db.local")
        XCTAssertEqual(admin.login?.totp, "JBSWY3DPEHPK3PXP")    // from "TOTP Seed"
        let servers = try XCTUnwrap(vault.folders.first { $0.name == "Work/Servers" })
        XCTAssertEqual(admin.folderId, servers.id)

        // Custom fields: protected → hidden, plain → text.
        let token = try XCTUnwrap(admin.fields?.first { $0.name == "API Token" })
        XCTAssertEqual(token.value, "tok-12345")
        XCTAssertEqual(token.type, .hidden)
        let env = try XCTUnwrap(admin.fields?.first { $0.name == "Environment" })
        XCTAssertEqual(env.value, "prod")
        XCTAssertEqual(env.type, .text)

        // The entry AFTER the history block — keystream alignment proof.
        let after = try XCTUnwrap(vault.ciphers.first { $0.name == "After" })
        XCTAssertEqual(after.login?.username, "zoe")
        XCTAssertEqual(after.login?.password, "ZZsecret")
        XCTAssertNil(after.folderId)
    }
}
