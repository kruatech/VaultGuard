import XCTest
import Foundation
import CryptoKit

/// KDBX 3 attachments.
///
/// KDBX 4 keeps attachment bytes in a binary pool in the inner header; KDBX 3 keeps them in
/// the XML, as base64 inside `<Meta><Binaries>`, with entries pointing at them by `Ref`.
/// Only the KDBX 4 location was ever read, so a v3 database's attachments reached the UI with
/// a size of zero and could not be opened.
///
/// Fixture: the KDBX 3.1 container from `KDBXv3Tests` (same password, same KDF parameters),
/// re-serialized with one gzipped binary added to `<Meta><Binaries>` and a `<Binary>` element
/// referencing it from the first entry.
final class KDBXv3AttachmentTests: XCTestCase {

    /// Exact bytes of the embedded attachment.
    private let expectedPlaintext = "VaultGuard KDBX3 attachment fixture\n"

    private let fixtureB64 =
        "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"

    private var fixture: Data { Data(base64Encoded: fixtureB64)! }

    private func openFixture() throws -> KDBXDatabase {
        try KDBXReader.unlock(data: fixture, password: "v3pass")
    }

    /// The fixture must still be a normal, readable KDBX 3.1 file — otherwise the rest of
    /// these assertions would be testing a broken container rather than the attachment path.
    func testFixtureIsStillAReadableV3Database() throws {
        let db = try openFixture()
        XCTAssertEqual(db.profile.versionMajor, 3)
        XCTAssertEqual(db.innerStreamID, 2)                 // Salsa20
        let stream = try XCTUnwrap(KDBXProtectedStream(streamID: db.innerStreamID, key: db.innerStreamKey))
        XCTAssertEqual(stream.decrypt("BjJG7RMj0w=="), "secretA")
    }

    /// The XML pool is lifted into the same array KDBX 4 fills from the inner header.
    func testMetaBinariesAreLiftedIntoTheBinaryPool() throws {
        let db = try openFixture()
        XCTAssertEqual(db.binaries.count, 1)
        // Inner-header item layout: [flags:1][data:N].
        let item = try XCTUnwrap(db.binaries.first)
        XCTAssertGreaterThan(item.count, 1)
        XCTAssertEqual(String(data: item.dropFirst(), encoding: .utf8), expectedPlaintext)
    }

    /// `Compressed="True"` on the element means the base64 holds gzip, not the file.
    func testCompressedBinaryIsInflated() throws {
        let db = try openFixture()
        let bytes = try XCTUnwrap(db.binaries.first).dropFirst()
        XCTAssertFalse(bytes.starts(with: [0x1f, 0x8b]), "still gzip — inflation did not happen")
        XCTAssertEqual(bytes.count, expectedPlaintext.utf8.count)
    }

    /// The mapper turns the pool entry into an attachment with a real name and size, which is
    /// what the detail view shows. A size of zero here is the original bug.
    func testMapperSurfacesTheAttachmentWithARealSize() throws {
        let db = try openFixture()
        let stream = try XCTUnwrap(KDBXProtectedStream(streamID: db.innerStreamID, key: db.innerStreamKey))
        let vault = KDBXVaultMapper.map(xml: db.xml, stream: stream, binaries: db.binaries)

        let withAttachment = vault.ciphers.filter { !($0.attachments ?? []).isEmpty }
        XCTAssertEqual(withAttachment.count, 1)
        let att = try XCTUnwrap(withAttachment.first?.attachments?.first)
        XCTAssertEqual(att.fileName, "note.txt")
        XCTAssertEqual(att.id, "0")
        XCTAssertEqual(att.size, String(expectedPlaintext.utf8.count))
        XCTAssertNotEqual(att.size, "0")
    }

    /// The backend is what the "open attachment" button goes through; before the fix it had
    /// nothing to hand back.
    func testBackendReturnsTheAttachmentBytes() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "v3pass")
        _ = try await backend.load()
        let bytes = try XCTUnwrap(backend.attachmentData(ref: 0))
        XCTAssertEqual(String(data: bytes, encoding: .utf8), expectedPlaintext)
    }

    /// A reference that does not exist must come back nil rather than trapping on an index.
    func testUnknownReferenceIsNil() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "v3pass")
        _ = try await backend.load()
        XCTAssertNil(backend.attachmentData(ref: 99))
        XCTAssertNil(backend.attachmentData(ref: -1))
    }


    /// Saving a KDBX 3 file emits KDBX 4, whose readers take attachments from the inner
    /// header. The base64 copy in `<Meta><Binaries>` is then dead weight — every attachment
    /// would be written twice — so the editable document drops it.
    func testLegacyBinaryPoolIsDroppedOnConversion() async throws {
        let backend = KeePassBackend(fileData: fixture, password: "v3pass")
        _ = try await backend.load()

        // A light KDF keeps the re-encryption from dominating the test's runtime.
        let converted = try backend.serialize(profileOverride: .lightArgon2d)
        let reread = try KDBXReader.unlock(data: converted, password: "v3pass")

        XCTAssertEqual(reread.profile.versionMajor, 4, "the writer emits KDBX 4")
        let xml = try XCTUnwrap(String(data: reread.xml, encoding: .utf8))
        XCTAssertFalse(xml.contains("<Binaries"), "the XML pool should be gone")

        // The attachment itself survives, now in the inner header.
        XCTAssertEqual(reread.binaries.count, 1)
        XCTAssertEqual(String(data: try XCTUnwrap(reread.binaries.first).dropFirst(), encoding: .utf8),
                       expectedPlaintext)
        XCTAssertTrue(xml.contains("Ref=\"0\""), "the entry still points at binary 0")
    }
}
