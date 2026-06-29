import XCTest
import Foundation

// CryptoService.swift and SecureData.swift are compiled directly into the
// VaultGuardTests target (see project.yml), so their internal types are visible
// here without `@testable import`.
//
// Scope: this suite covers the cryptographic core of `CryptoService` —
// EncString parsing, authenticated AES-CBC round-trips and tamper rejection,
// raw attachment buffers, KDF behaviour, the password generator, and HKDF.
//
// NOT covered here (no source reviewed yet — would require VaultDecryptor /
// VaultBackend / VaultMigrator and the on-disk vault format): vault-file
// round-trip, corrupted-file handling, atomic save, and old→new migration.
// Those belong in a separate VaultFormatTests / VaultMigratorTests file.

final class CryptoServiceTests: XCTestCase {

    // MARK: - Helpers

    /// Deterministic 64-byte key (32 enc + 32 mac). Different `seed` → different key.
    private func key64(_ seed: Int = 0) -> SymmetricCryptoKey {
        SymmetricCryptoKey(key: Data((0..<64).map { UInt8(((($0 &* 31) &+ seed) % 251 + 1) & 0xFF) }))
    }

    /// Assert that `expr` throws the expected `CryptoError` case.
    /// `CryptoError` is not Equatable, so cases are compared by their description
    /// (which includes any associated value, e.g. `unsupportedEncType(99)`).
    private func assertThrows<T>(_ expr: @autoclosure () throws -> T,
                                 _ expected: CryptoError,
                                 _ message: String = "",
                                 file: StaticString = #file, line: UInt = #line) {
        XCTAssertThrowsError(try expr(), message, file: file, line: line) { err in
            guard let e = err as? CryptoError else {
                return XCTFail("expected CryptoError, got \(err)", file: file, line: line)
            }
            XCTAssertEqual(String(describing: e), String(describing: expected),
                           message, file: file, line: line)
        }
    }

    // MARK: - EncString parser

    func testEncStringRejectsEmpty() {
        XCTAssertNil(EncString(string: ""))
    }

    func testEncStringRejectsNonNumericType() {
        XCTAssertNil(EncString(string: "x." + Data([1,2,3]).base64EncodedString()))
    }

    func testEncStringRejectsUnknownType() {
        XCTAssertNil(EncString(string: "99." + Data([1,2,3]).base64EncodedString()))
    }

    func testEncStringRejectsWrongArity() {
        // type 2 requires exactly 3 pipe-separated parts; supply 2.
        let two = "2." + Data([1]).base64EncodedString() + "|" + Data([2]).base64EncodedString()
        XCTAssertNil(EncString(string: two))
    }

    func testEncStringRejectsBadBase64() {
        XCTAssertNil(EncString(string: "2.@@@|@@@|@@@"))
    }

    // MARK: - Symmetric key shapes

    func testKeyShapes() {
        XCTAssertTrue(SymmetricCryptoKey(key: Data(count: 64)).hasMacKey, "64-byte key splits into enc+mac")
        XCTAssertTrue(SymmetricCryptoKey(key: Data(count: 32)).hasMacKey, "32-byte key is HKDF-expanded")
        XCTAssertFalse(SymmetricCryptoKey(key: Data(count: 16)).hasMacKey, "short key has no MAC key")
    }

    // MARK: - Authenticated AES-CBC round-trip

    func testEncryptDecryptRoundTripASCII() throws {
        let key = key64()
        let pt = Data("hello world".utf8)
        let s = try CryptoService().encryptData(pt, key: key)
        XCTAssertEqual(try CryptoService().decryptData(s, key: key), pt)
    }

    func testRoundTripUnicode() throws {
        let key = key64()
        let pt = Data("Pâté café — Ω ≈ 🔐 пароль".utf8)
        let s = try CryptoService().encryptData(pt, key: key)
        XCTAssertEqual(try CryptoService().decryptData(s, key: key), pt)
    }

    func testRoundTripEmptyData() throws {
        let key = key64()
        let s = try CryptoService().encryptData(Data(), key: key)
        XCTAssertEqual(try CryptoService().decryptData(s, key: key), Data())
    }

    func testRoundTripLargeData() throws {
        let key = key64()
        let pt = Data((0..<100_000).map { UInt8($0 & 0xFF) })
        let s = try CryptoService().encryptData(pt, key: key)
        XCTAssertEqual(try CryptoService().decryptData(s, key: key), pt)
    }

    // MARK: - Tamper / wrong-key rejection (this is the security-critical part)

    func testWrongKeyFailsWithMacMismatch() throws {
        let s = try CryptoService().encryptData(Data("secret".utf8), key: key64(1))
        assertThrows(try CryptoService().decryptData(s, key: key64(2)), .macMismatch,
                     "decrypting with a different key must fail closed")
    }

    func testTamperedCiphertextFails() throws {
        let key = key64()
        let enc = EncString(string: try CryptoService().encryptData(Data("payload value".utf8), key: key))!
        var ct = enc.ct; ct[ct.startIndex] ^= 0xFF
        let bad = EncString(type: enc.type, iv: enc.iv, ct: ct, mac: enc.mac).serialize()
        assertThrows(try CryptoService().decryptData(bad, key: key), .macMismatch)
    }

    func testTamperedIVFails() throws {
        let key = key64()
        let enc = EncString(string: try CryptoService().encryptData(Data("payload value".utf8), key: key))!
        var iv = enc.iv!; iv[iv.startIndex] ^= 0xFF
        let bad = EncString(type: enc.type, iv: iv, ct: enc.ct, mac: enc.mac).serialize()
        assertThrows(try CryptoService().decryptData(bad, key: key), .macMismatch)
    }

    func testTamperedMacFails() throws {
        let key = key64()
        let enc = EncString(string: try CryptoService().encryptData(Data("payload value".utf8), key: key))!
        var mac = enc.mac!; mac[mac.startIndex] ^= 0xFF
        let bad = EncString(type: enc.type, iv: enc.iv, ct: enc.ct, mac: mac).serialize()
        assertThrows(try CryptoService().decryptData(bad, key: key), .macMismatch)
    }

    func testUnauthenticatedTypeRejected() {
        // type 0 (AES-CBC, no MAC) parses but must be refused at decrypt time.
        let s = "0." + Data([1,2,3]).base64EncodedString() + "|" + Data([4,5,6]).base64EncodedString()
        XCTAssertNotNil(EncString(string: s), "type 0 still parses")
        assertThrows(try CryptoService().decryptData(s, key: key64()), .unauthenticatedNotAllowed)
    }

    func testGarbageStringThrowsInvalidEncString() {
        assertThrows(try CryptoService().decryptData("not-an-enc-string", key: key64()), .invalidEncString,
                     "corrupted input must throw, not crash")
    }

    // MARK: - Raw attachment buffer

    func testRawBufferRoundTrip() throws {
        let key = key64()
        let data = Data("attachment file contents".utf8)
        let buf = try CryptoService().encryptBuffer(data, key: key)
        XCTAssertEqual(try CryptoService().decryptRawBuffer(buf, key: key), data)
    }

    func testRawBufferTamperFails() throws {
        let key = key64()
        var buf = try CryptoService().encryptBuffer(Data("attachment file contents".utf8), key: key)
        buf[buf.count - 1] ^= 0xFF
        assertThrows(try CryptoService().decryptRawBuffer(buf, key: key), .macMismatch)
    }

    func testRawBufferUnknownTypeRejected() {
        var b = Data([UInt8(99)]); b.append(Data(count: 60))
        assertThrows(try CryptoService().decryptRawBuffer(b, key: key64()), .unsupportedEncType(99))
    }

    // MARK: - Session-key instance API

    func testSessionEncryptDecrypt() {
        let svc = CryptoService()
        svc.restoreSession(userKey: Data((0..<64).map { UInt8($0) }), passwordHash: "hash==")
        XCTAssertTrue(svc.hasKeys)
        let c = svc.encrypt("secret value")
        XCTAssertNotNil(c)
        XCTAssertEqual(svc.decrypt(c), "secret value")
    }

    func testEncryptEmptyOrNilReturnsNil() {
        let svc = CryptoService()
        svc.restoreSession(userKey: Data((0..<64).map { UInt8($0) }), passwordHash: "h")
        XCTAssertNil(svc.encrypt(""))
        XCTAssertNil(svc.encrypt(nil))
        XCTAssertNil(svc.decrypt(nil))
        XCTAssertNil(svc.decrypt(""))
    }

    func testClearKeysWipesSession() {
        let svc = CryptoService()
        svc.restoreSession(userKey: Data((0..<64).map { UInt8($0) }), passwordHash: "h")
        let c = svc.encrypt("secret value")
        svc.clearKeys()
        XCTAssertFalse(svc.hasKeys)
        XCTAssertNil(svc.decrypt(c), "no plaintext after keys are cleared")
    }

    func testAttachmentRoundTrip() throws {
        let svc = CryptoService()
        svc.restoreSession(userKey: Data((0..<64).map { UInt8(($0 &* 7) & 0xFF) }), passwordHash: "h")
        let file = Data((0..<5000).map { UInt8($0 & 0xFF) })
        let (enc, keyStr) = try svc.encryptAttachment(file)
        XCTAssertEqual(try svc.decryptAttachmentData(enc, attachmentKeyString: keyStr), file)
    }

    func testAttachmentTamperFails() throws {
        let svc = CryptoService()
        svc.restoreSession(userKey: Data((0..<64).map { UInt8(($0 &* 7) & 0xFF) }), passwordHash: "h")
        var (enc, keyStr) = try svc.encryptAttachment(Data("attachment".utf8))
        enc[enc.count - 1] ^= 0xFF
        assertThrows(try svc.decryptAttachmentData(enc, attachmentKeyString: keyStr), .macMismatch)
    }

    // MARK: - KDF

    func testPbkdf2DeterministicAndEmailLowercased() throws {
        let a = CryptoService()
        try a.deriveKeys(password: "correct horse", email: "User@Example.com",
                         kdf: 0, kdfIterations: 10_000, kdfMemory: nil, kdfParallelism: nil)
        let b = CryptoService()
        try b.deriveKeys(password: "correct horse", email: "user@example.com",
                         kdf: 0, kdfIterations: 10_000, kdfMemory: nil, kdfParallelism: nil)
        XCTAssertNotNil(a.passwordHash)
        XCTAssertEqual(a.passwordHash, b.passwordHash, "same inputs (email case-insensitive) → same hash")
    }

    func testPbkdf2WrongPasswordDiffers() throws {
        let a = CryptoService()
        try a.deriveKeys(password: "correct", email: "a@b.com",
                         kdf: 0, kdfIterations: 10_000, kdfMemory: nil, kdfParallelism: nil)
        let b = CryptoService()
        try b.deriveKeys(password: "wrong", email: "a@b.com",
                         kdf: 0, kdfIterations: 10_000, kdfMemory: nil, kdfParallelism: nil)
        XCTAssertNotEqual(a.passwordHash, b.passwordHash)
    }

    func testUnsupportedKdfThrows() {
        assertThrows(try CryptoService().deriveKeys(password: "p", email: "a@b.com",
                     kdf: 7, kdfIterations: 1, kdfMemory: nil, kdfParallelism: nil),
                     .unsupportedKdf(7))
    }

    func testArgon2MissingParamsThrows() {
        assertThrows(try CryptoService().deriveKeys(password: "p", email: "a@b.com",
                     kdf: 1, kdfIterations: 2, kdfMemory: nil, kdfParallelism: nil),
                     .missingKdfParams)
    }

    func testArgon2idDeterministic() throws {
        // Small parameters keep the test fast while still exercising the Argon2 path.
        let a = CryptoService()
        try a.deriveKeys(password: "pw", email: "a@b.com",
                         kdf: 1, kdfIterations: 2, kdfMemory: 16, kdfParallelism: 1)
        let b = CryptoService()
        try b.deriveKeys(password: "pw", email: "a@b.com",
                         kdf: 1, kdfIterations: 2, kdfMemory: 16, kdfParallelism: 1)
        XCTAssertNotNil(a.passwordHash)
        XCTAssertEqual(a.passwordHash, b.passwordHash)
    }

    // MARK: - HKDF

    func testHkdfDeterministicLengthAndInfoSeparation() {
        let prk = Data((0..<32).map { UInt8($0) })
        let enc1 = CryptoService.hkdfExpand(prk: prk, info: Data("enc".utf8), length: 64)
        let enc2 = CryptoService.hkdfExpand(prk: prk, info: Data("enc".utf8), length: 64)
        XCTAssertEqual(enc1, enc2)
        XCTAssertEqual(enc1.count, 64)
        let mac = CryptoService.hkdfExpand(prk: prk, info: Data("mac".utf8), length: 32)
        XCTAssertNotEqual(enc1.prefix(32), mac, "different info → different sub-key")
    }

    // MARK: - Password generator

    func testGenLength() {
        XCTAssertEqual(CryptoService.generatePassword(length: 32).count, 32)
    }

    func testGenMinLengthOne() {
        XCTAssertEqual(CryptoService.generatePassword(length: 1).count, 1)
    }

    func testGenOnlyLowercaseClass() {
        let p = CryptoService.generatePassword(length: 50, uppercase: false, lowercase: true,
                                               digits: false, symbols: false)
        XCTAssertTrue(p.allSatisfy { ("a"..."z").contains($0) })
    }

    func testGenContainsEachSelectedClass() {
        let p = CryptoService.generatePassword(length: 8, uppercase: true, lowercase: true,
                                               digits: true, symbols: true)
        let symbols = Set("!@#$%^&*()_+-=")
        XCTAssertTrue(p.contains { $0.isUppercase })
        XCTAssertTrue(p.contains { $0.isLowercase })
        XCTAssertTrue(p.contains { $0.isNumber })
        XCTAssertTrue(p.contains { symbols.contains($0) })
    }

    func testGenAllClassesDisabledFallsBackToLowercase() {
        let p = CryptoService.generatePassword(length: 12, uppercase: false, lowercase: false,
                                               digits: false, symbols: false)
        XCTAssertEqual(p.count, 12)
        XCTAssertTrue(p.allSatisfy { ("a"..."z").contains($0) })
    }

    func testGenProducesVariedOutput() {
        let set = Set((0..<50).map { _ in CryptoService.generatePassword(length: 20) })
        XCTAssertGreaterThan(set.count, 1, "generator must not be constant")
    }

    // MARK: - PasswordTemplate

    func testTemplateClampsLength() {
        let hi = PasswordTemplate(name: "t", length: 999, uppercase: true, lowercase: true,
                                  digits: true, symbols: true, excludeAmbiguous: false).sanitized()
        XCTAssertEqual(hi.length, PasswordTemplate.maxLength)
        let lo = PasswordTemplate(name: "t", length: 1, uppercase: true, lowercase: false,
                                  digits: false, symbols: false, excludeAmbiguous: false).sanitized()
        XCTAssertEqual(lo.length, PasswordTemplate.minLength)
    }

    func testTemplateEnsuresAtLeastOneClass() {
        let s = PasswordTemplate(name: "t", length: 10, uppercase: false, lowercase: false,
                                 digits: false, symbols: false, excludeAmbiguous: false).sanitized()
        XCTAssertTrue(s.lowercase)
    }
}
