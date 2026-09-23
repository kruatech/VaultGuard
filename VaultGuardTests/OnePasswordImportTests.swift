import XCTest
import Foundation

/// Import from 1Password's unencrypted export.
///
/// The fixture is a real ZIP built by an independent tool, holding the JSON shape 1Password
/// documents: `export.attributes` stored, `export.data` deflated, and a `files/` entry — so
/// both branches of the ZIP reader are exercised by opening it.
final class OnePasswordImportTests: XCTestCase {

    private let fixtureB64 =
        "UEsDBBQAAAAAAAAAIQAbPR6KVgAAAFYAAAARAAAAZXhwb3J0LmF0dHJpYnV0ZXN7InZlcnNpb24iOiAzLCAiZGVzY3JpcHRpb24i" +
        "OiAiMVBhc3N3b3JkIFVuZW5jcnlwdGVkIEV4cG9ydCIsICJjcmVhdGVkQXQiOiAxNTg1MzMzNTY5fVBLAwQUAAAACAAAACEAdXFb" +
        "X+kCAAANCAAACwAAAGV4cG9ydC5kYXRhjVVdb9owFP0rkZ9pISSggTRNLW21bh1Da9cPTTyY+Ba8GhvZToAh/vuuHQKEAgVecm/u" +
        "Offr2FkQmiQqldaQ9p8FodZqfFoU3i4dA2mTJ5BsTiokTTlD86LTCcmyQjKail3gKuQxxHCZo3ugjZJUoMfOJ97j0NzCOAevMNxh" +
        "Xml2KxnMSDuskEQDtcAuLFrNMK63PrUaTSxjwjbuqBHFzThuVIix6EUemlieAXIlaA+Vnv/O+Ws1l4CBpVz4WoUacnnDQbC8joyK" +
        "1BMInji8R236SA1o/4hVOtBD3syDJzV8KKnlSm4HLisbUhNhN/Y964QaM1Wa7bD23rGuA5d9BCsLpicod29o4EwEGEhccN6N5VY4" +
        "pntIUs3tfJPyPiySlSN7t92ivk7n+oZUiuIXJFEyASrAvQvrUdwgS9dcgfwp4czyMQRb3XgeZSfbNNbZ3ktTO2pXq85Rff6CheNw" +
        "Pn+7vH96ia56119736PeM8pk2cd/hagMdMZh6jlWOa+0mgzUzMlSC7RH1k4MUk6n03OWvztP1LiaB+SdCjoAkY//A5Drroimwr4D" +
        "sME5zOh4IqDqF2Lp0KUg2Pybk55QKSN9P6RC3vWSvGtbgtXJCBXLPpbsgVE8aGpGiC+li8gpR6JePhJ7FbSlnP3CSahmIyUY6GB1" +
        "QDz7xr2tAWM1l0N3jQSXZRXJdDzwsTk6QbukQQ2M2w6SdvPANonD8q/Mh5PirzzxByjYIc+yI/Iu08BswvU8cHdOAc9d2wxjJe3o" +
        "BShWVa9FuLdj0n3khpaXFZ+0rPiEZd0ykHbd9mZ1cv/qXrk2trQ171k59ixNyvJ0BN3BO8dB+B1AGU4Z02BMAd6Ya2zhymkA71Dc" +
        "UfDDXX04InextckvPqRo/ePudrl7PAtrtZp7675h2gWIDNMe2Qi2FaxrK5bSOGkpUXkppZv5b4rDWV3PBzJ3XXw5b/OUvK3Wkbyp" +
        "fJNqKoMCdCj5E3D3QfGD6S//A1BLAwQUAAAAAAAAACEAk2hZWA8AAAAPAAAADQAAAGZpbGVzL2RvYy50eHRhdHRhY2htZW50IGJv" +
        "ZHlQSwECFAMUAAAAAAAAACEAGz0eilYAAABWAAAAEQAAAAAAAAAAAAAAgAEAAAAAZXhwb3J0LmF0dHJpYnV0ZXNQSwECFAMUAAAA" +
        "CAAAACEAdXFbX+kCAAANCAAACwAAAAAAAAAAAAAAgAGFAAAAZXhwb3J0LmRhdGFQSwECFAMUAAAAAAAAACEAk2hZWA8AAAAPAAAA" +
        "DQAAAAAAAAAAAAAAgAGXAwAAZmlsZXMvZG9jLnR4dFBLBQYAAAAAAwADALMAAADRAwAAAAA="

    private var archive: Data { Data(base64Encoded: fixtureB64)! }

    private func imported() throws -> [VaultMigrator.ImportedEntry] {
        try VaultMigrator.import1PUX(data: archive)
    }

    private func entry(_ name: String) throws -> VaultCipher {
        try XCTUnwrap(try imported().first { $0.cipher.name == name }?.cipher)
    }

    // MARK: ZIP reader

    func testArchiveListsItsEntries() throws {
        let names = try ZipArchive.entryNames(in: archive)
        XCTAssertEqual(names.sorted(), ["export.attributes", "export.data", "files/doc.txt"])
    }

    /// `export.attributes` is stored and `export.data` is deflated, so reading both covers
    /// the reader's two paths.
    func testStoredAndDeflatedEntriesBothRead() throws {
        let attributes = try ZipArchive.extract("export.attributes", from: archive)
        XCTAssertTrue(try XCTUnwrap(String(data: attributes, encoding: .utf8))
            .contains("1Password Unencrypted Export"))

        let data = try ZipArchive.extract("export.data", from: archive)
        XCTAssertTrue(try XCTUnwrap(String(data: data, encoding: .utf8)).hasPrefix("{"))
    }

    func testMissingEntryThrows() {
        XCTAssertThrowsError(try ZipArchive.extract("nope.txt", from: archive))
    }

    /// Anything that is not an archive has to be refused rather than half-parsed.
    func testNonArchiveInputIsRejected() {
        XCTAssertThrowsError(try ZipArchive.entryNames(in: Data("not a zip".utf8)))
        XCTAssertThrowsError(try ZipArchive.entryNames(in: Data()))
    }

    // MARK: Item mapping

    /// The archived item is 1Password's trash; importing it would restore what the user threw
    /// away, into a vault where they can no longer tell which is which.
    func testArchivedItemsAreSkipped() throws {
        let names = try imported().map { $0.cipher.name }
        XCTAssertFalse(names.contains("Trashed"))
        XCTAssertEqual(names.count, 5)
    }

    /// The vault name becomes the folder, so a multi-vault export does not collapse into one
    /// flat list.
    func testVaultNameBecomesTheFolderPath() throws {
        XCTAssertTrue(try imported().allSatisfy { $0.folderPath == "Personal" })
    }

    func testLoginFieldsAreReadByDesignation() throws {
        let cipher = try entry("Dropbox")
        XCTAssertEqual(cipher.type, .login)
        XCTAssertEqual(cipher.login?.username, "alice")
        XCTAssertEqual(cipher.login?.password, "s3cret")
    }

    /// `favIndex` is an ordering, not a flag: anything above zero means favourite.
    func testFavIndexAboveZeroMeansFavourite() throws {
        XCTAssertTrue(try entry("Dropbox").favorite)
        XCTAssertFalse(try entry("Visa").favorite)
    }

    /// The primary `url` also appears in `urls`; it must not be imported twice.
    func testUrlsAreCollectedWithoutDuplicates() throws {
        let uris = try XCTUnwrap(try entry("Dropbox").login?.uris)
        XCTAssertEqual(uris.compactMap { $0.uri }, ["https://www.dropbox.com/", "https://db.example/"])
    }

    /// A section field typed `totp` is the item's one-time password, not a custom field.
    func testTotpSectionBecomesTheLoginTotp() throws {
        let cipher = try entry("Dropbox")
        XCTAssertEqual(cipher.login?.totp, "otpauth://totp/X?secret=JBSWY3DPEHPK3PXP")
        XCTAssertFalse((cipher.fields ?? []).contains { $0.value.hasPrefix("otpauth://") })
    }

    /// A concealed section field keeps its section as context and stays hidden.
    func testConcealedSectionFieldBecomesAHiddenCustomField() throws {
        let field = try XCTUnwrap(try entry("Dropbox").fields?.first)
        XCTAssertEqual(field.name, "Security / PIN")
        XCTAssertEqual(field.value, "12345")
        XCTAssertEqual(field.type, .hidden)
    }

    /// Tags have no counterpart in the target shape; dropping them silently would lose
    /// something the user wrote deliberately.
    func testTagsAreAppendedToTheNotes() throws {
        let notes = try XCTUnwrap(try entry("Dropbox").notes)
        XCTAssertTrue(notes.contains("a note"))
        XCTAssertTrue(notes.contains("Tags: work, cloud"))
    }

    // MARK: Typed categories

    func testCreditCardCategoryMapsToACard() throws {
        let cipher = try entry("Visa")
        XCTAssertEqual(cipher.type, .card)
        XCTAssertEqual(cipher.card?.cardholderName, "A B")
        XCTAssertEqual(cipher.card?.number, "4111111111111111")
        XCTAssertEqual(cipher.card?.code, "123")
    }

    /// 1Password writes a month-year as the number YYYYMM.
    func testExpiryNumberIsSplitIntoMonthAndYear() throws {
        let card = try XCTUnwrap(try entry("Visa").card)
        XCTAssertEqual(card.expYear, "2030")
        XCTAssertEqual(card.expMonth, "1")
    }

    func testIdentityCategoryMapsToAnIdentity() throws {
        let cipher = try entry("Ann Lee")
        XCTAssertEqual(cipher.type, .identity)
        XCTAssertEqual(cipher.identity?.firstName, "Ann")
        XCTAssertEqual(cipher.identity?.lastName, "Lee")
    }

    /// An address is a nested object; flattened into one readable line rather than dropped.
    func testNestedAddressIsFlattened() throws {
        let field = try XCTUnwrap(try entry("Ann Lee").fields?.first)
        XCTAssertEqual(field.value, "1 Main, Riga, LV-1000, lv")
    }

    func testSecureNoteCategoryMapsToANote() throws {
        let cipher = try entry("Notes")
        XCTAssertEqual(cipher.type, .secureNote)
        XCTAssertEqual(cipher.notes, "just a note")
    }

    /// An unrecognised category keeps its title, notes and fields as a note instead of being
    /// guessed into a shape it does not fit.
    func testUnknownCategoryFallsBackToANote() throws {
        let cipher = try entry("Weird")
        XCTAssertEqual(cipher.type, .secureNote)
        XCTAssertEqual(cipher.notes, "unknown category")
    }

    // MARK: Degenerate input

    func testEmptyExportYieldsNothing() throws {
        let json = Data(#"{"accounts":[]}"#.utf8)
        XCTAssertTrue(try OnePasswordImporter.parseExportData(json).isEmpty)
    }

    func testExportWithoutAccountsKeyYieldsNothing() throws {
        XCTAssertTrue(try OnePasswordImporter.parseExportData(Data("{}".utf8)).isEmpty)
    }

    func testMalformedJSONThrows() {
        XCTAssertThrowsError(try OnePasswordImporter.parseExportData(Data("not json".utf8)))
    }

    /// An item with no title has nothing to show in a list, so it is skipped rather than
    /// imported as a blank row.
    func testUntitledItemIsSkipped() throws {
        let json = Data(#"""
        {"accounts":[{"vaults":[{"attrs":{"name":"V"},"items":[
          {"state":"active","categoryUuid":"001","overview":{"title":""},"details":{}}]}]}]}
        """#.utf8)
        XCTAssertTrue(try OnePasswordImporter.parseExportData(json).isEmpty)
    }

    /// With no title but a URL, the URL is a usable name.
    func testUrlStandsInForAMissingTitle() throws {
        let json = Data(#"""
        {"accounts":[{"vaults":[{"attrs":{"name":"V"},"items":[
          {"state":"active","categoryUuid":"001",
           "overview":{"url":"https://example.test/"},"details":{}}]}]}]}
        """#.utf8)
        XCTAssertEqual(try OnePasswordImporter.parseExportData(json).first?.cipher.name,
                       "https://example.test/")
    }
}
