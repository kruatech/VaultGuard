import XCTest
import Foundation

/// Tests for the Batch 1 crypto hardening.
/// Run on macOS (CryptoKit / CommonCrypto / Security are required).
final class CryptoServiceTests: XCTestCase {

    // MARK: - Helpers

    /// A random 64-byte key → 32-byte enc + 32-byte mac (no HKDF stretch path).
    private func makeKey() -> SymmetricCryptoKey {
        var bytes = [UInt8](repeating: 0, count: 64)
        _ = SecRandomCopyBytes(kSecRandomDefault, 64, &bytes)
        return SymmetricCryptoKey(key: Data(bytes))
    }

    // MARK: - EncString round-trip & integrity

    func testEncryptDecryptRoundTrip() throws {
        let crypto = CryptoService()
        let key = makeKey()
        let plaintext = "correct horse battery staple 🐎"

        let serialized = try crypto.encryptData(Data(plaintext.utf8), key: key)
        // Canonical authenticated type.
        XCTAssertTrue(serialized.hasPrefix("2."))

        let decrypted = try crypto.decryptData(serialized, key: key)
        XCTAssertEqual(String(data: decrypted, encoding: .utf8), plaintext)
    }

    func testTamperedCiphertextFailsMac() throws {
        let crypto = CryptoService()
        let key = makeKey()
        let serialized = try crypto.encryptData(Data("secret".utf8), key: key)

        // Flip one ciphertext byte → MAC must reject before AES runs.
        let enc = try XCTUnwrap(EncString(string: serialized))
        var ct = enc.ct
        ct[ct.startIndex] ^= 0x01
        let tampered = EncString(type: enc.type, iv: enc.iv, ct: ct, mac: enc.mac).serialize()

        XCTAssertThrowsError(try crypto.decryptData(tampered, key: key)) { error in
            guard case CryptoError.macMismatch = error else {
                return XCTFail("expected macMismatch, got \(error)")
            }
        }
    }

    func testUnauthenticatedType0IsRejected() throws {
        let crypto = CryptoService()
        let key = makeKey()

        // A *structurally valid* type-0 (AES-CBC, no MAC) string must still be refused.
        let iv = Data(repeating: 0, count: 16).base64EncodedString()
        let ct = Data(repeating: 1, count: 16).base64EncodedString()
        let type0 = "0.\(iv)|\(ct)"

        XCTAssertNotNil(EncString(string: type0), "type 0 should parse structurally")
        XCTAssertThrowsError(try crypto.decryptData(type0, key: key)) { error in
            guard case CryptoError.unauthenticatedNotAllowed = error else {
                return XCTFail("expected unauthenticatedNotAllowed, got \(error)")
            }
        }
    }

    // MARK: - Strict parser

    func testMalformedEncStringsRejected() {
        let bad = [
            "",
            "not-an-encstring",
            "9.aaa|bbb|ccc",                       // unknown type
            "2.\(b64(16))|\(b64(16))",              // type 2 needs 3 parts, only 2 given
            "0.\(b64(16))",                         // type 0 needs 2 parts
            "\(b64(16))|\(b64(16))",                // headerless (old lenient form) must fail now
            "2.not_base64|also_not|nope",
        ]
        for s in bad {
            XCTAssertNil(EncString(string: s), "should reject: \(s)")
        }
    }

    func testWellFormedType2Parses() {
        let s = "2.\(b64(16))|\(b64(32))|\(b64(32))"
        let enc = EncString(string: s)
        XCTAssertNotNil(enc)
        XCTAssertEqual(enc?.type, .aesCbc256_HmacSha256_B64)
        XCTAssertNotNil(enc?.mac)
    }

    // MARK: - Password generator

    func testGeneratorLength() {
        for len in [1, 8, 20, 64, 128] {
            XCTAssertEqual(CryptoService.generatePassword(length: len).count, len)
        }
    }

    func testGeneratorIncludesEachSelectedClass() {
        // Run several times because seeding is randomized.
        for _ in 0..<200 {
            let pw = CryptoService.generatePassword(length: 12, uppercase: true, lowercase: true, digits: true, symbols: true)
            XCTAssertTrue(pw.contains { $0.isUppercase })
            XCTAssertTrue(pw.contains { $0.isLowercase })
            XCTAssertTrue(pw.contains { $0.isNumber })
            XCTAssertTrue(pw.contains { "!@#$%^&*()_+-=".contains($0) })
        }
    }

    func testGeneratorSingleClass() {
        let pw = CryptoService.generatePassword(length: 30, uppercase: false, lowercase: false, digits: true, symbols: false)
        XCTAssertTrue(pw.allSatisfy { $0.isNumber })
    }

    func testGeneratorNoEmptyOnAllFalse() {
        // No class selected → must fall back to a non-empty charset, never crash/empty.
        let pw = CryptoService.generatePassword(length: 10, uppercase: false, lowercase: false, digits: false, symbols: false)
        XCTAssertEqual(pw.count, 10)
    }

    // MARK: - Attachment buffer (binary path)

    func testAttachmentBufferRoundTrip() throws {
        let crypto = CryptoService()
        let key = makeKey()
        var payload = [UInt8](repeating: 0, count: 5000)
        _ = SecRandomCopyBytes(kSecRandomDefault, payload.count, &payload)
        let original = Data(payload)

        let buffer = try crypto.encryptBuffer(original, key: key)
        // [type:1][iv:16][mac:32][ct...]
        XCTAssertEqual(buffer.first, UInt8(EncType.aesCbc256_HmacSha256_B64.rawValue))
        XCTAssertGreaterThan(buffer.count, 49)

        let decrypted = try crypto.decryptRawBuffer(buffer, key: key)
        XCTAssertEqual(decrypted, original)
    }

    func testAttachmentBufferTamperFailsMac() throws {
        let crypto = CryptoService()
        let key = makeKey()
        var buffer = try crypto.encryptBuffer(Data("attachment-bytes".utf8), key: key)

        // Flip a ciphertext byte (offset >= 49).
        let ctIndex = buffer.index(buffer.startIndex, offsetBy: 49)
        buffer[ctIndex] ^= 0x01

        XCTAssertThrowsError(try crypto.decryptRawBuffer(buffer, key: key)) { error in
            guard case CryptoError.macMismatch = error else {
                return XCTFail("expected macMismatch, got \(error)")
            }
        }
    }

    func testAttachmentBufferType0Rejected() throws {
        let crypto = CryptoService()
        let key = makeKey()
        var buffer = try crypto.encryptBuffer(Data("attachment-bytes".utf8), key: key)

        // Downgrade the type byte to unauthenticated AES-CBC.
        buffer[buffer.startIndex] = UInt8(EncType.aesCbc256_B64.rawValue)

        XCTAssertThrowsError(try crypto.decryptRawBuffer(buffer, key: key)) { error in
            guard case CryptoError.unauthenticatedNotAllowed = error else {
                return XCTFail("expected unauthenticatedNotAllowed, got \(error)")
            }
        }
    }

    // MARK: - Utils

    private func b64(_ n: Int) -> String { Data(repeating: 0, count: n).base64EncodedString() }
}
