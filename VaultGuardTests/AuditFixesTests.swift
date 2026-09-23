import XCTest
import Foundation

// Coverage for the behaviour changed while working through the audit, plus the gaps it
// listed. Grouped by the unit under test rather than by audit item.

// MARK: - Search query expansion

/// A Cyrillic query must find a Latin entry and vice versa, and a query typed on the wrong
/// keyboard layout must still match. Assertions are on the produced variant set rather than
/// on `AppState.filteredCiphers`, so they hold without building a vault.
final class SearchQueryExpanderTests: XCTestCase {

    /// The user's own example: "гит" has to reach "github".
    func testCyrillicQueryTransliteratesToLatin() {
        let variants = SearchQueryExpander.variants(for: "гит")
        XCTAssertTrue(variants.contains("git"))
        XCTAssertTrue(variants.contains { "github".contains($0) })
    }

    func testLatinQueryTransliteratesToCyrillic() {
        let variants = SearchQueryExpander.variants(for: "git")
        XCTAssertTrue(variants.contains("гит"))
        XCTAssertTrue(variants.contains { "гитхаб".contains($0) })
    }

    /// "пше" is "git" typed while the ЙЦУКЕН layout was active.
    func testWrongKeyboardLayoutIsUndone() {
        XCTAssertTrue(SearchQueryExpander.variants(for: "пше").contains("git"))
    }

    /// "х" alone transliterates to h/kh/x, so the ambiguous branches must all be produced.
    func testAmbiguousLettersBranch() {
        let variants = SearchQueryExpander.variants(for: "гитх")
        XCTAssertTrue(variants.contains("gith"))
        XCTAssertTrue(variants.contains("gitkh"))
        XCTAssertTrue(variants.contains("gitx"))
    }

    /// "кс" has a one-letter Latin spelling; without it "яндекс" only ever reached "yandeks".
    func testKsDigraphReachesX() {
        XCTAssertTrue(SearchQueryExpander.variants(for: "яндекс").contains("yandex"))
    }

    func testRoundTripThroughBothScripts() {
        XCTAssertTrue(SearchQueryExpander.variants(for: "сбер").contains("sber"))
        XCTAssertTrue(SearchQueryExpander.variants(for: "sber").contains("сбер"))
    }

    /// Below the threshold the query is used verbatim: two transliterated letters match far
    /// too much to be useful.
    func testSingleCharacterIsNotExpanded() {
        XCTAssertEqual(SearchQueryExpander.variants(for: "я"), ["я"])
    }

    func testEmptyQueryProducesNothing() {
        XCTAssertTrue(SearchQueryExpander.variants(for: "").isEmpty)
        XCTAssertTrue(SearchQueryExpander.variants(for: "   ").isEmpty)
    }

    /// Element 0 is the query as typed, the set is capped, and nothing repeats.
    func testVariantSetIsBoundedOrderedAndUnique() {
        let variants = SearchQueryExpander.variants(for: "щёлкающий")
        XCTAssertEqual(variants.first, "щёлкающий")
        XCTAssertLessThanOrEqual(variants.count, SearchQueryExpander.maxVariants)
        XCTAssertEqual(Set(variants).count, variants.count)
        XCTAssertFalse(variants.contains(""))
    }

    func testQueryIsTrimmedAndLowercased() {
        XCTAssertEqual(SearchQueryExpander.variants(for: "  GitHub  ").first, "github")
    }
}

// MARK: - TOTP

final class TOTPServiceAuditTests: XCTestCase {
    private let totp = TOTPService.shared
    private let secret = "JBSWY3DPEHPK3PXP"

    /// HOTP is counter-based. Parsing it as TOTP produced a well-formed but wrong code that
    /// the user would type and have rejected; refusing is the honest answer.
    func testHotpIsRejectedRatherThanMisgenerated() {
        let uri = "otpauth://hotp/Example:alice?secret=\(secret)&counter=1"
        XCTAssertNil(totp.generateCode(secret: uri))
    }

    func testTotpUriStillWorksAfterHotpGuard() throws {
        let uri = "otpauth://totp/Example:alice?secret=\(secret)"
        XCTAssertEqual(try XCTUnwrap(totp.generateCode(secret: uri)).count, 6)
    }

    /// `otpauth://steam/` (the host form, as opposed to the `steam://` scheme).
    func testOtpauthSteamHostUsesSteamAlphabet() throws {
        let alphabet = Set("23456789BCDFGHJKMNPQRTVWXY")
        let code = try XCTUnwrap(totp.generateCode(secret: "otpauth://steam/Valve?secret=\(secret)"))
        XCTAssertEqual(code.count, 5)
        XCTAssertTrue(code.allSatisfy { alphabet.contains($0) })
    }

    func testEncoderSteamParameterUsesSteamAlphabet() throws {
        let uri = "otpauth://totp/Valve?secret=\(secret)&period=30&encoder=steam"
        XCTAssertEqual(try XCTUnwrap(totp.generateCode(secret: uri)).count, 5)
    }

    /// A zero or negative period must never reach the division in `secondsRemaining`.
    func testZeroPeriodDoesNotDivideByZero() {
        let uri = "otpauth://totp/Example?secret=\(secret)&period=0"
        XCTAssertGreaterThan(totp.period(for: uri), 0)
        XCTAssertGreaterThan(totp.secondsRemaining(for: uri), 0)
        XCTAssertNotNil(totp.generateCode(secret: uri))
    }

    func testNegativePeriodIsClamped() {
        let uri = "otpauth://totp/Example?secret=\(secret)&period=-5"
        XCTAssertGreaterThan(totp.period(for: uri), 0)
    }

    /// Ten digits exceeds UInt32, so the modulus must be computed in UInt64.
    func testTenDigitsDoesNotTrap() throws {
        let uri = "otpauth://totp/Example?secret=\(secret)&digits=10"
        XCTAssertEqual(try XCTUnwrap(totp.generateCode(secret: uri)).count, 10)
    }

    func testProgressStaysInUnitRange() {
        let p = totp.progress(for: secret)
        XCTAssertGreaterThan(p, 0)
        XCTAssertLessThanOrEqual(p, 1)
    }
}

// MARK: - KeePass mapping

/// Exercises `KDBXVaultMapper.map` with hand-written XML. `stream: nil` is the editable form,
/// where protected values already hold plaintext, so no cipher setup is needed.
final class KDBXVaultMapperAuditTests: XCTestCase {

    private func vault(entry: String) -> DecryptedVault {
        let xml = """
        <KeePassFile><Meta><DatabaseName>T</DatabaseName></Meta><Root><Group>
        <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name>
        \(entry)
        </Group></Root></KeePassFile>
        """
        return KDBXVaultMapper.map(xml: Data(xml.utf8), stream: nil)
    }

    private func entryXML(strings: [(String, String)], times: String = "", tags: String? = nil) -> String {
        let kv = strings.map {
            "<String><Key>\($0.0)</Key><Value>\($0.1)</Value></String>"
        }.joined()
        let tagsXML = tags.map { "<Tags>\($0)</Tags>" } ?? ""
        return "<Entry><UUID>BBBBBBBBBBBBBBBBBBBBBB==</UUID>\(tagsXML)\(times)\(kv)</Entry>"
    }

    // MARK: TOTP Settings

    /// Only the seed used to be read, so `60;8` silently generated a 30-second 6-digit code.
    func testTotpSettingsPeriodAndDigitsAreHonoured() throws {
        let v = vault(entry: entryXML(strings: [
            ("Title", "Example"),
            ("TOTP Seed", "JBSWY3DPEHPK3PXP"),
            ("TOTP Settings", "60;8"),
        ]))
        let totp = try XCTUnwrap(v.ciphers.first?.login?.totp)
        XCTAssertEqual(TOTPService.shared.period(for: totp), 60)
        XCTAssertEqual(try XCTUnwrap(TOTPService.shared.generateCode(secret: totp)).count, 8)
    }

    /// `S` in the digits slot is KeePassXC's marker for the Steam alphabet.
    func testTotpSettingsSteamMarker() throws {
        let v = vault(entry: entryXML(strings: [
            ("Title", "Valve"),
            ("TOTP Seed", "JBSWY3DPEHPK3PXP"),
            ("TOTP Settings", "30;S"),
        ]))
        let totp = try XCTUnwrap(v.ciphers.first?.login?.totp)
        let code = try XCTUnwrap(TOTPService.shared.generateCode(secret: totp))
        XCTAssertEqual(code.count, 5)
        XCTAssertTrue(code.allSatisfy { Set("23456789BCDFGHJKMNPQRTVWXY").contains($0) })
    }

    /// KeeTrayTOTP appends a third `;`-separated field; it carries nothing we need.
    func testTotpSettingsIgnoresTrailingFields() throws {
        let v = vault(entry: entryXML(strings: [
            ("Title", "Valve"),
            ("TOTP Seed", "JBSWY3DPEHPK3PXP"),
            ("TOTP Settings", "30;S;http://steampowered.com"),
        ]))
        let totp = try XCTUnwrap(v.ciphers.first?.login?.totp)
        XCTAssertEqual(try XCTUnwrap(TOTPService.shared.generateCode(secret: totp)).count, 5)
    }

    /// `otp` is the modern attribute and already a complete URI, so it wins.
    func testOtpAttributeTakesPrecedenceOverLegacyPair() throws {
        let uri = "otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&amp;period=45"
        let v = vault(entry: entryXML(strings: [
            ("Title", "Example"),
            ("otp", uri),
            ("TOTP Seed", "JBSWY3DPEHPK3PXP"),
            ("TOTP Settings", "60;8"),
        ]))
        XCTAssertEqual(TOTPService.shared.period(for: try XCTUnwrap(v.ciphers.first?.login?.totp)), 45)
    }

    func testSeedWithoutSettingsIsPassedThroughVerbatim() throws {
        let v = vault(entry: entryXML(strings: [
            ("Title", "Example"),
            ("TOTP Seed", "JBSWY3DPEHPK3PXP"),
        ]))
        XCTAssertEqual(v.ciphers.first?.login?.totp, "JBSWY3DPEHPK3PXP")
    }

    func testSpacedSeedIsCleanedBeforeBuildingTheURI() throws {
        let v = vault(entry: entryXML(strings: [
            ("Title", "Example"),
            ("TOTP Seed", "JBSW Y3DP EHPK 3PXP"),
            ("TOTP Settings", "30;6"),
        ]))
        let totp = try XCTUnwrap(v.ciphers.first?.login?.totp)
        XCTAssertFalse(totp.contains(" "))
        XCTAssertNotNil(TOTPService.shared.generateCode(secret: totp))
    }

    /// The TOTP attributes must not also surface as custom fields.
    func testTotpAttributesDoNotLeakIntoCustomFields() {
        let v = vault(entry: entryXML(strings: [
            ("Title", "Example"),
            ("TOTP Seed", "JBSWY3DPEHPK3PXP"),
            ("TOTP Settings", "30;6"),
            ("Custom", "keep me"),
        ]))
        let names = (v.ciphers.first?.fields ?? []).map { $0.name }
        XCTAssertEqual(names, ["Custom"])
    }

    // MARK: Expiry

    /// KeePass always writes an ExpiryTime; only `<Expires>` says whether it counts. Reading
    /// the date without the flag would mark half a database as expired.
    func testExpiryIgnoredWhenExpiresFlagIsFalse() {
        let times = "<Times><Expires>False</Expires><ExpiryTime>\(Self.kdbxTime(-86_400))</ExpiryTime></Times>"
        let v = vault(entry: entryXML(strings: [("Title", "Example")], times: times))
        XCTAssertNil(v.ciphers.first?.keepassExpiry)
        XCTAssertFalse(v.ciphers.first?.isExpired ?? true)
    }

    func testPastExpiryMarksEntryExpired() {
        let times = "<Times><Expires>True</Expires><ExpiryTime>\(Self.kdbxTime(-86_400))</ExpiryTime></Times>"
        let v = vault(entry: entryXML(strings: [("Title", "Example")], times: times))
        XCTAssertNotNil(v.ciphers.first?.keepassExpiry)
        XCTAssertTrue(v.ciphers.first?.isExpired ?? false)
    }

    func testFutureExpiryIsNotExpired() {
        let times = "<Times><Expires>True</Expires><ExpiryTime>\(Self.kdbxTime(86_400))</ExpiryTime></Times>"
        let v = vault(entry: entryXML(strings: [("Title", "Example")], times: times))
        XCTAssertNotNil(v.ciphers.first?.keepassExpiry)
        XCTAssertFalse(v.ciphers.first?.isExpired ?? true)
    }

    func testEntryWithoutTimesHasNoExpiry() {
        let v = vault(entry: entryXML(strings: [("Title", "Example")]))
        XCTAssertNil(v.ciphers.first?.keepassExpiry)
        XCTAssertFalse(v.ciphers.first?.isExpired ?? true)
    }

    // MARK: Tags

    /// KeePass 2.x separates with ";", KeePassXC with ",". Both are accepted.
    func testTagsSplitOnSemicolon() {
        let v = vault(entry: entryXML(strings: [("Title", "Example")], tags: "work;email;archive"))
        XCTAssertEqual(v.ciphers.first?.keepassTags, ["work", "email", "archive"])
    }

    func testTagsSplitOnComma() {
        let v = vault(entry: entryXML(strings: [("Title", "Example")], tags: "work, email"))
        XCTAssertEqual(v.ciphers.first?.keepassTags, ["work", "email"])
    }

    func testEmptyTagPiecesAreDropped() {
        let v = vault(entry: entryXML(strings: [("Title", "Example")], tags: "a;;  ;b"))
        XCTAssertEqual(v.ciphers.first?.keepassTags, ["a", "b"])
    }

    func testNoTagsElementYieldsNil() {
        let v = vault(entry: entryXML(strings: [("Title", "Example")]))
        XCTAssertNil(v.ciphers.first?.keepassTags)
    }

    /// KDBX timestamp: base64 of a little-endian Int64, seconds since 0001-01-01.
    private static func kdbxTime(_ offset: TimeInterval) -> String {
        KeePassBackend.kdbxTimeString(Date().addingTimeInterval(offset))
    }
}

// MARK: - Endpoint resolution

final class BitwardenEndpointsTests: XCTestCase {

    func testBitwardenComRegion() {
        for host in ["https://bitwarden.com", "https://www.bitwarden.com", "https://vault.bitwarden.com"] {
            let e = BitwardenEndpoints.resolve(for: host)
            XCTAssertEqual(e.api, "https://api.bitwarden.com", host)
            XCTAssertEqual(e.identity, "https://identity.bitwarden.com", host)
        }
    }

    func testBitwardenEuRegion() {
        for host in ["https://bitwarden.eu", "https://www.bitwarden.eu", "https://vault.bitwarden.eu"] {
            let e = BitwardenEndpoints.resolve(for: host)
            XCTAssertEqual(e.api, "https://api.bitwarden.eu", host)
            XCTAssertEqual(e.identity, "https://identity.bitwarden.eu", host)
        }
    }

    /// Self-hosted and Vaultwarden are served under one host at /api and /identity.
    func testSelfHostedGetsPathSuffixes() {
        let e = BitwardenEndpoints.resolve(for: "https://vault.example.com")
        XCTAssertEqual(e.api, "https://vault.example.com/api")
        XCTAssertEqual(e.identity, "https://vault.example.com/identity")
    }

    func testSelfHostedWithPortAndSubpath() {
        let e = BitwardenEndpoints.resolve(for: "https://box.lan:8443/bw")
        XCTAssertEqual(e.api, "https://box.lan:8443/bw/api")
        XCTAssertEqual(e.identity, "https://box.lan:8443/bw/identity")
    }

    /// Host matching is case-insensitive, so a typed-in capitalised host still resolves.
    func testHostMatchIsCaseInsensitive() {
        XCTAssertEqual(BitwardenEndpoints.resolve(for: "https://VAULT.Bitwarden.com").api,
                       "https://api.bitwarden.com")
    }

    /// A cloud host must be matched on the host itself, not a substring of it — otherwise a
    /// look-alike domain would be handed the real Bitwarden endpoints.
    func testLookAlikeHostIsNotTreatedAsCloud() {
        let e = BitwardenEndpoints.resolve(for: "https://bitwarden.com.evil.test")
        XCTAssertEqual(e.api, "https://bitwarden.com.evil.test/api")
    }

    func testKnownCloudHostTableCoversEveryAlias() {
        XCTAssertNotNil(BitwardenEndpoints.knownCloudHosts["vault.bitwarden.com"])
        XCTAssertNotNil(BitwardenEndpoints.knownCloudHosts["vault.bitwarden.eu"])
        XCTAssertNil(BitwardenEndpoints.knownCloudHosts["vault.example.com"])
    }
}

// MARK: - Bitwarden JSON export

/// The export is the mirror of the importer, so a round trip is the strongest check available
/// without a real Bitwarden server.
final class VaultMigratorExportTests: XCTestCase {

    private func login(_ name: String, user: String, pass: String, folderId: String? = nil,
                       favorite: Bool = false, reprompt: Int? = nil) -> VaultCipher {
        VaultCipher(id: UUID().uuidString, organizationId: nil, folderId: folderId, collectionIds: nil,
                    type: .login, name: name, notes: "note for \(name)",
                    login: CipherLogin(username: user, password: pass, totp: nil,
                                       uris: [CipherUri(uri: "https://\(name).test", match: nil)]),
                    card: nil, secureNote: nil, identity: nil,
                    fields: [CipherField(name: "custom", value: "value", type: .text)],
                    attachments: nil, favorite: favorite, reprompt: reprompt,
                    creationDate: nil, revisionDate: nil, deletedDate: nil)
    }

    func testRoundTripPreservesCoreFields() throws {
        let folder = VaultFolder(id: "f1", name: "Work", revisionDate: nil)
        let source = login("alpha", user: "a@test", pass: "s3cret", folderId: "f1",
                           favorite: true, reprompt: 1)
        let data = try VaultMigrator.exportBitwardenJSON(ciphers: [source], folders: [folder])
        let imported = try VaultMigrator.importBitwardenJSON(data: data)

        XCTAssertEqual(imported.count, 1)
        let c = try XCTUnwrap(imported.first).cipher
        XCTAssertEqual(c.name, "alpha")
        XCTAssertEqual(c.type, .login)
        XCTAssertEqual(c.notes, "note for alpha")
        XCTAssertEqual(c.login?.username, "a@test")
        XCTAssertEqual(c.login?.password, "s3cret")
        XCTAssertEqual(c.login?.uris?.first?.uri, "https://alpha.test")
        XCTAssertEqual(c.fields?.first?.name, "custom")
        XCTAssertTrue(c.favorite)
        XCTAssertEqual(c.reprompt, 1)
        XCTAssertEqual(try XCTUnwrap(imported.first).folderPath, "Work")
    }

    func testExportIsMarkedUnencrypted() throws {
        let data = try VaultMigrator.exportBitwardenJSON(ciphers: [login("a", user: "u", pass: "p")], folders: [])
        let obj = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(obj["encrypted"] as? Bool, false)
        // ...which also means the importer must accept it rather than reject it as encrypted.
        XCTAssertNoThrow(try VaultMigrator.importBitwardenJSON(data: data))
    }

    /// Trashed items are not part of the vault the user is moving.
    func testDeletedItemsAreExcluded() throws {
        var trashed = login("trashed", user: "u", pass: "p")
        trashed.deletedDate = Date()
        let data = try VaultMigrator.exportBitwardenJSON(
            ciphers: [login("kept", user: "u", pass: "p"), trashed], folders: [])
        let imported = try VaultMigrator.importBitwardenJSON(data: data)
        XCTAssertEqual(imported.map { $0.cipher.name }, ["kept"])
    }

    /// Only folders something references are written, so an export never recreates empty groups.
    func testUnreferencedFoldersAreDropped() throws {
        let used = VaultFolder(id: "f1", name: "Used", revisionDate: nil)
        let unused = VaultFolder(id: "f2", name: "Unused", revisionDate: nil)
        let data = try VaultMigrator.exportBitwardenJSON(
            ciphers: [login("a", user: "u", pass: "p", folderId: "f1")], folders: [used, unused])
        let obj = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let names = (obj["folders"] as? [[String: Any]])?.compactMap { $0["name"] as? String }
        XCTAssertEqual(names, ["Used"])
    }

    func testEveryCipherTypeSurvivesTheRoundTrip() throws {
        var note = login("n", user: "u", pass: "p")
        note.type = .secureNote
        note.login = nil
        note.secureNote = CipherSecureNote(type: 0)

        var card = login("c", user: "u", pass: "p")
        card.type = .card
        card.login = nil
        card.card = CipherCard(cardholderName: "A B", brand: "Visa", number: "4111111111111111",
                               expMonth: "01", expYear: "2030", code: "123")

        var identity = login("i", user: "u", pass: "p")
        identity.type = .identity
        identity.login = nil
        identity.identity = CipherIdentity(title: nil, firstName: "Ann", middleName: nil, lastName: "Lee",
                                           company: nil, email: nil, phone: nil, ssn: nil, username: nil,
                                           passportNumber: nil, licenseNumber: nil,
                                           address1: nil, address2: nil, address3: nil,
                                           city: nil, state: nil, postalCode: nil, country: nil)

        let data = try VaultMigrator.exportBitwardenJSON(ciphers: [note, card, identity], folders: [])
        let imported = try VaultMigrator.importBitwardenJSON(data: data)
        XCTAssertEqual(imported.map { $0.cipher.type }, [.secureNote, .card, .identity])
        XCTAssertEqual(imported[1].cipher.card?.number, "4111111111111111")
        XCTAssertEqual(imported[2].cipher.identity?.lastName, "Lee")
    }

    func testEmptyVaultProducesValidEmptyExport() throws {
        let data = try VaultMigrator.exportBitwardenJSON(ciphers: [], folders: [])
        XCTAssertEqual(try VaultMigrator.importBitwardenJSON(data: data).count, 0)
    }
}

// MARK: - Cipher decryption

/// `decryptCipher` is reached through a decoded `SyncCipher`, so these build the server's JSON
/// shape. A fresh `CryptoService` holds no keys, which is exactly the state the placeholder
/// paths are meant to describe.
final class VaultDecryptorTests: XCTestCase {

    private func syncCipher(_ json: [String: Any]) throws -> SyncCipher {
        try JSONDecoder().decode(SyncCipher.self, from: JSONSerialization.data(withJSONObject: json))
    }

    private func decrypt(_ json: [String: Any], crypto: CryptoService = CryptoService()) throws -> VaultCipher? {
        VaultDecryptor.decryptCipher(try syncCipher(json), crypto: crypto,
                                     noName: "NO_NAME", noOrgKey: "NO_ORG_KEY",
                                     undecryptable: "UNDECRYPTABLE")
    }

    /// An item whose name is present but undecryptable must say so rather than masquerade as
    /// an unnamed entry.
    func testUndecryptableNameGetsItsOwnPlaceholder() throws {
        let c = try decrypt(["id": "1", "type": 1, "name": "2.abc|def|ghi"])
        XCTAssertEqual(c?.name, "UNDECRYPTABLE")
    }

    /// No name at all is a different situation from a name that failed to decrypt.
    func testAbsentNameFallsBackToNoName() throws {
        let c = try decrypt(["id": "1", "type": 1])
        XCTAssertEqual(c?.name, "NO_NAME")
    }

    /// Without the organisation's key the item cannot be read at all, and the placeholder
    /// should point at the cause rather than at the symptom.
    func testMissingOrganisationKeyGetsItsOwnPlaceholder() throws {
        let c = try decrypt(["id": "1", "type": 1, "organizationId": "org-1", "name": "2.abc|def|ghi"])
        XCTAssertEqual(c?.name, "NO_ORG_KEY")
    }

    func testUnknownTypeIsDropped() throws {
        XCTAssertNil(try decrypt(["id": "1", "type": 99, "name": "x"]))
    }

    func testMissingIdIsDropped() throws {
        XCTAssertNil(try decrypt(["type": 1, "name": "x"]))
    }

    func testMissingTypeIsDropped() throws {
        XCTAssertNil(try decrypt(["id": "1", "name": "x"]))
    }

    /// Flags and dates travel outside the encrypted payload, so they survive even when nothing
    /// can be decrypted.
    func testPlainMetadataSurvivesFailedDecryption() throws {
        let c = try decrypt([
            "id": "1", "type": 1, "name": "2.abc|def|ghi",
            "favorite": true, "reprompt": 1,
            "revisionDate": "2026-01-02T03:04:05.000Z",
            "deletedDate": "2026-02-03T04:05:06.000Z",
        ])
        XCTAssertEqual(c?.favorite, true)
        XCTAssertEqual(c?.reprompt, 1)
        XCTAssertNotNil(c?.revisionDate)
        XCTAssertNotNil(c?.deletedDate)
    }

    /// An empty ciphers array is a valid sync, not a failure.
    func testEmptySyncDecryptsToAnEmptyVault() throws {
        let data = try JSONSerialization.data(withJSONObject: ["ciphers": [], "folders": []])
        let vault = VaultDecryptor.decrypt(data: data, crypto: CryptoService(),
                                           noName: "NO_NAME", noOrgKey: "NO_ORG_KEY",
                                           undecryptable: "UNDECRYPTABLE")
        XCTAssertEqual(vault?.ciphers.count, 0)
        XCTAssertEqual(vault?.folders.count, 0)
    }

    func testMalformedSyncPayloadReturnsNil() {
        XCTAssertNil(VaultDecryptor.decrypt(data: Data("not json".utf8), crypto: CryptoService(),
                                            noName: "", noOrgKey: "", undecryptable: ""))
    }
}
