import XCTest
import Foundation

/// Additional coverage for the strict `EncString` parser, `serialize()` round-trip,
/// the raw attachment-buffer path, and password-generator options. These exercise
/// branches not already covered by `CryptoServiceTests`.
final class EncStringParsingTests: XCTestCase {

    private func b64(_ n: Int) -> String { Data(repeating: 0, count: n).base64EncodedString() }

    // MARK: - RSA type parsing (arity per type)

    func testRSAType3ParsesSinglePart() {
        // rsa2048_OaepSha256_B64 == 3 → exactly 1 data part, no iv, no mac.
        let enc = EncString(string: "3.\(b64(256))")
        XCTAssertNotNil(enc)
        XCTAssertEqual(enc?.type, .rsa2048_OaepSha256_B64)
        XCTAssertNil(enc?.iv)
        XCTAssertNil(enc?.mac)
    }

    func testRSAType3RejectsExtraParts() {
        // A second `|` part is not valid for a 1-part RSA type.
        XCTAssertNil(EncString(string: "3.\(b64(256))|\(b64(32))"))
    }

    func testRSAType5ParsesTwoParts() {
        // rsa2048_OaepSha256_HmacSha256_B64 == 5 → ct + mac, no iv.
        let enc = EncString(string: "5.\(b64(256))|\(b64(32))")
        XCTAssertNotNil(enc)
        XCTAssertEqual(enc?.type, .rsa2048_OaepSha256_HmacSha256_B64)
        XCTAssertNil(enc?.iv)
        XCTAssertNotNil(enc?.mac)
    }

    func testRSAType5RejectsWrongArity() {
        // Type 5 needs exactly 2 parts; a single part must be rejected.
        XCTAssertNil(EncString(string: "5.\(b64(256))"))
    }

    // MARK: - serialize() round-trips through the parser

    func testSerializeRoundTripType2() {
        let original = "2.\(b64(16))|\(b64(32))|\(b64(32))"
        let enc = try? XCTUnwrap(EncString(string: original))
        let round = enc?.serialize()
        // Re-parsing the serialized form yields an equivalent structure.
        let reparsed = EncString(string: round ?? "")
        XCTAssertNotNil(reparsed)
        XCTAssertEqual(reparsed?.type, .aesCbc256_HmacSha256_B64)
        XCTAssertEqual(reparsed?.iv, enc?.iv)
        XCTAssertEqual(reparsed?.ct, enc?.ct)
        XCTAssertEqual(reparsed?.mac, enc?.mac)
    }

    // MARK: - Raw attachment buffer

    func testDecryptRawBufferRejectsUnauthenticatedType() {
        let crypto = CryptoService()
        var bytes = [UInt8](repeating: 0, count: 64)
        _ = SecRandomCopyBytes(kSecRandomDefault, 64, &bytes)
        let key = SymmetricCryptoKey(key: Data(bytes))

        // type byte 0 (AES-CBC, no MAC) in the raw layout must be refused.
        var buf = Data([UInt8(EncType.aesCbc256_B64.rawValue)])
        buf.append(Data(repeating: 0, count: 60)) // > 49 bytes so length guard passes

        XCTAssertThrowsError(try crypto.decryptRawBuffer(buf, key: key)) { error in
            guard case CryptoError.unauthenticatedNotAllowed = error else {
                return XCTFail("expected unauthenticatedNotAllowed, got \(error)")
            }
        }
    }

    func testDecryptRawBufferRejectsTooShort() {
        let crypto = CryptoService()
        let key = SymmetricCryptoKey(key: Data(repeating: 1, count: 64))
        // <= 49 bytes must fail the length guard.
        let tooShort = Data(repeating: 2, count: 49)
        XCTAssertThrowsError(try crypto.decryptRawBuffer(tooShort, key: key)) { error in
            guard case CryptoError.invalidEncString = error else {
                return XCTFail("expected invalidEncString, got \(error)")
            }
        }
    }

    // MARK: - Generator options

    func testGeneratorExcludeAmbiguousOmitsAmbiguousChars() {
        let ambiguous = Set<Character>("O0oIl1|`'\"")
        for _ in 0..<200 {
            let pw = CryptoService.generatePassword(
                length: 40, uppercase: true, lowercase: true,
                digits: true, symbols: true, excludeAmbiguous: true
            )
            XCTAssertFalse(pw.contains { ambiguous.contains($0) },
                           "ambiguous character leaked into: \(pw)")
        }
    }

    func testGeneratorDigitsOnlyProducesOnlyDigits() {
        let pw = CryptoService.generatePassword(
            length: 12, uppercase: false, lowercase: false,
            digits: true, symbols: false
        )
        XCTAssertEqual(pw.count, 12)
        XCTAssertTrue(pw.allSatisfy { $0.isNumber })
    }
}
