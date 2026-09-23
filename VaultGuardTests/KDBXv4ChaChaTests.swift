import XCTest
import Foundation
import CryptoKit

/// KDBX 4 with ChaCha20 as the outer cipher, Argon2id as the KDF, and the inner-header binary
/// pool populated.
///
/// The suite's real-file coverage was lopsided: `KDBXReaderTests` uses a KeePassXC database
/// with AES-256-CBC and Argon2**d**, `KDBXv3Tests` covers the 3.1 container, and ChaCha20,
/// Argon2**id** and attachments were only exercised by writing a file with `KDBXWriter` and
/// reading it back — which shows the two agree with each other, not that either agrees with
/// the format.
///
/// This fixture is built independently of `KDBXWriter`, from the specification the reader
/// implements. Regenerate with `scripts/make-kdbx4-chacha-fixture.py`.
final class KDBXv4ChaChaTests: XCTestCase {

    private let password = "chacha-pass"
    private let expected = ["first attachment\n", "second attachment payload\n"]

    private let fixtureB64 =
        "A9mimmf7S7UBAAQAAhAAAADWA4ori29MtaUkM5ox27WaAwQAAAABAAAABCAAAAAQERITFBUWFxgZGhscHR4fICEiIyQlJicoKSor" +
        "LC0uLwcMAAAAQEFCQ0RFRkdISUpLC4sAAAAAAUIFAAAAJFVVSUQQAAAAnimLGVbbR3OyPfw+xvCh5kIBAAAAUyAAAABQUVJTVFVW" +
        "V1hZWltcXV5fYGFiY2RlZmdoaWprbG1ubwUBAAAASQgAAAACAAAAAAAAAAUBAAAATQgAAAAAABAAAAAAAAQBAAAAUAQAAAABAAAA" +
        "BAEAAABWBAAAABMAAAAAAAQAAAANCg0KvcJV7iXfB8Z/yQtLUZNq2tJxEaHi10061Y2r2C9SOSKWuNzXAhZXTm5eCTWJiLIEwVYc" +
        "t1sbwLQSwwAcG//Z5IfNNyRf5Qcb7ToipS26tq9HTLE/WXqtrYDAeUxbv1/7cgEAAOX9FIoa45XzEuyBqUU9YNhjbAYQszwOSMOX" +
        "XKEiqz9nCx0/QvomUnOIOXG56wj8KxDu3r1Q7Q4SjcZ2LjJpa7Ny9vjEEHzQ4TXAZnwr4dieGb9LcM1BU7QJte//bNn1OIUh6+u9" +
        "UUbliSQYmeIxjst8g/cC7pilSDGpjrP+5bbSGlJ361Tv8fuWIDgotMkllnzqKIsMkvy/pG7ptHk3ERSS9URiEnDQ4JF0Q65Ab64Z" +
        "wtfJimCIA22dzojqwQW5QK5/IWhR0C3SoH74EAuV+WhE+Prxj2AL8r5plOHzHDbmsFF3LzNxQ/8x4ZgxKmiiDeotRGn9xl3HuYPh" +
        "pP//YSFuCtZy/XK3mvVgTq8h/WNeWGvbMXu0fKawcihzUcfXb2VYjyb0rHmxFPec6pAI7aH9BKHE+qBZj8phdYon24/MBBgy8WlT" +
        "Lmn6+sAR8koFibeHLvzYeQtGb3O+p7Z3c56/3xbsX6cbcc5d3MUgvsJRwqpEFVYw4ftwM8hOnNhjpAlUoxSobTrqVKJ0E2n//PjN" +
        "9gAAAAA="

    private var fixture: Data { Data(base64Encoded: fixtureB64)! }

    private func openFixture() throws -> KDBXDatabase {
        try KDBXReader.unlock(data: fixture, password: password)
    }

    // MARK: Container

    func testOpensWithChaChaAndArgon2id() throws {
        let db = try openFixture()
        XCTAssertEqual(db.profile.versionMajor, 4)
        guard case .chacha20 = db.profile.cipher else { return XCTFail("outer cipher is not ChaCha20") }
        guard case .argon2id = db.profile.kdf else { return XCTFail("KDF is not Argon2id") }
    }

    func testInnerStreamIsChaCha20() throws {
        let db = try openFixture()
        XCTAssertEqual(db.innerStreamID, 3)
        XCTAssertNotNil(KDBXProtectedStream(streamID: db.innerStreamID, key: db.innerStreamKey))
    }

    /// The payload is gzip'd, so a failure here means the decompression step and not the
    /// cipher.
    func testCompressedPayloadIsInflated() throws {
        let xml = try XCTUnwrap(String(data: try openFixture().xml, encoding: .utf8))
        XCTAssertTrue(xml.hasPrefix("<KeePassFile>"))
        XCTAssertTrue(xml.contains("<Value>alice</Value>"))
    }

    // MARK: Credentials

    func testWrongPasswordIsRejected() {
        XCTAssertThrowsError(try KDBXReader.unlock(data: fixture, password: "nope"))
    }

    /// The header HMAC is what a wrong password actually fails, so the error has to say
    /// "credentials" rather than "corrupt file".
    func testWrongPasswordReportsWrongCredentials() {
        do {
            _ = try KDBXReader.unlock(data: fixture, password: "nope")
            XCTFail("expected the open to fail")
        } catch let error as KDBXError {
            guard case .wrongCredentials = error else {
                return XCTFail("expected .wrongCredentials, got \(error)")
            }
        } catch {
            XCTFail("expected a KDBXError, got \(error)")
        }
    }

    // MARK: Attachments

    /// Inner-header items are kept verbatim as `[flags:1][data:N]`, in reference order.
    func testBinaryPoolIsReadInOrder() throws {
        let db = try openFixture()
        XCTAssertEqual(db.binaries.count, expected.count)
        let decoded = db.binaries.map { String(data: $0.dropFirst(), encoding: .utf8) }
        XCTAssertEqual(decoded, expected)
    }

    /// The flag byte is preserved rather than stripped — the writer re-emits these items as
    /// they came in, and losing the byte would shift every attachment by one.
    func testFlagByteIsPreserved() throws {
        let first = try XCTUnwrap(openFixture().binaries.first)
        XCTAssertEqual(first.first, 0x01)
        XCTAssertEqual(first.count, expected[0].utf8.count + 1)
    }

    /// The whole path the app uses: attachments reach the mapper with real names and sizes.
    func testMapperSurfacesBothAttachments() throws {
        let db = try openFixture()
        let stream = try XCTUnwrap(KDBXProtectedStream(streamID: db.innerStreamID, key: db.innerStreamKey))
        let vault = KDBXVaultMapper.map(xml: db.xml, stream: stream, binaries: db.binaries)

        let entry = try XCTUnwrap(vault.ciphers.first)
        let attachments = try XCTUnwrap(entry.attachments)
        XCTAssertEqual(attachments.map { $0.fileName }, ["one.txt", "two.txt"])
        XCTAssertEqual(attachments.map { $0.id }, ["0", "1"])
        XCTAssertEqual(attachments.map { $0.size },
                       expected.map { String($0.utf8.count) })
    }

    func testBackendReturnsBothAttachmentBodies() async throws {
        let backend = KeePassBackend(fileData: fixture, password: password)
        _ = try await backend.load()
        for (index, text) in expected.enumerated() {
            let bytes = try XCTUnwrap(backend.attachmentData(ref: index))
            XCTAssertEqual(String(data: bytes, encoding: .utf8), text)
        }
    }

    /// Re-serializing keeps the profile and the attachments: this is the write-back path for
    /// a ChaCha20 database, and silently switching it to AES would be a downgrade the user
    /// never asked for.
    func testReserializeKeepsCipherKdfAndAttachments() async throws {
        let backend = KeePassBackend(fileData: fixture, password: password)
        _ = try await backend.load()

        let rebuilt = try backend.serialize()
        let reread = try KDBXReader.unlock(data: rebuilt, password: password)

        guard case .chacha20 = reread.profile.cipher else { return XCTFail("cipher changed") }
        guard case .argon2id = reread.profile.kdf else { return XCTFail("KDF changed") }
        XCTAssertEqual(reread.binaries.count, expected.count)
        XCTAssertEqual(reread.binaries.map { String(data: $0.dropFirst(), encoding: .utf8) },
                       expected)
    }
}
