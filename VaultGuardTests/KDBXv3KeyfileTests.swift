import XCTest
import Foundation
import CryptoKit

/// KDBX 3.1 opened with a password *and* a key file.
///
/// The key-file component joins the composite key before the KDF runs, so getting it wrong
/// does not produce a subtly different vault — the file simply refuses to open. The v3 path
/// had no coverage of it at all: `KDBXReaderTests` exercises key files on v4 only.
///
/// Fixture: the KDBX 3.1 container from `KDBXv3Tests`, re-encrypted with a composite key that
/// includes a 32-byte key file. Regenerate with
/// `scripts/make-kdbx3-attachment-fixture.py --keyfile`.
final class KDBXv3KeyfileTests: XCTestCase {

    /// KeePass takes exactly 32 raw bytes as the key-file component verbatim, with no hashing.
    private var keyfile: Data { Data((0..<32).map { UInt8($0) }) }

    private let fixtureB64 =
        "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" +
        "/hItuPmism0="

    private var fixture: Data { Data(base64Encoded: fixtureB64)! }

    func testOpensWithPasswordAndKeyfile() throws {
        let db = try KDBXReader.unlock(data: fixture, password: "v3pass", keyfile: keyfile)
        XCTAssertEqual(db.profile.versionMajor, 3)
        XCTAssertEqual(db.innerStreamID, 2)                 // Salsa20
        XCTAssertFalse(db.xml.isEmpty)
    }

    /// Without the key file the composite key is different, so the container must reject it
    /// rather than decrypt to garbage.
    func testPasswordAloneIsRejected() {
        XCTAssertThrowsError(try KDBXReader.unlock(data: fixture, password: "v3pass"))
    }

    func testWrongKeyfileIsRejected() {
        let wrong = Data(repeating: 0xAB, count: 32)
        XCTAssertThrowsError(try KDBXReader.unlock(data: fixture, password: "v3pass", keyfile: wrong))
    }

    func testWrongPasswordWithRightKeyfileIsRejected() {
        XCTAssertThrowsError(try KDBXReader.unlock(data: fixture, password: "nope", keyfile: keyfile))
    }

    /// The failure is specifically "wrong credentials" — a corrupt-file error here would send
    /// the user looking for a damaged database instead of a missing key file.
    func testRejectionReportsWrongCredentials() {
        do {
            _ = try KDBXReader.unlock(data: fixture, password: "v3pass")
            XCTFail("expected the open to fail without the key file")
        } catch let error as KDBXError {
            guard case .wrongCredentials = error else {
                return XCTFail("expected .wrongCredentials, got \(error)")
            }
        } catch {
            XCTFail("expected a KDBXError, got \(error)")
        }
    }

    /// The whole vault is readable through the normal path, not just the container header.
    func testVaultMapsThroughTheBackend() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "v3pass", keyfile: keyfile)
        let vault = try await backend.load()
        XCTAssertFalse(vault.ciphers.isEmpty)
    }
}
