import XCTest
import Foundation

/// Tests for Batch 3 TOTP parsing. Code *values* are time-based, so these assert
/// structural properties (length, charset, parsed period) rather than fixed codes.
final class TOTPServiceTests: XCTestCase {
    private let totp = TOTPService.shared
    private let secret = "JBSWY3DPEHPK3PXP" // "Hello!\u{0}\u{0}" — common test secret

    func testRawBase32ProducesSixDigits() throws {
        let code = try XCTUnwrap(totp.generateCode(secret: secret))
        XCTAssertEqual(code.count, 6)
        XCTAssertTrue(code.allSatisfy { $0.isNumber })
        XCTAssertEqual(totp.period(for: secret), 30)
    }

    func testOtpauthDigitsAndPeriodHonoured() throws {
        let uri = "otpauth://totp/Example:alice?secret=\(secret)&digits=8&period=60&algorithm=SHA256"
        let code = try XCTUnwrap(totp.generateCode(secret: uri))
        XCTAssertEqual(code.count, 8)
        XCTAssertTrue(code.allSatisfy { $0.isNumber })
        XCTAssertEqual(totp.period(for: uri), 60)
    }

    func testSha512Parses() throws {
        let uri = "otpauth://totp/Example:bob?secret=\(secret)&algorithm=SHA512"
        let code = try XCTUnwrap(totp.generateCode(secret: uri))
        XCTAssertEqual(code.count, 6)
    }

    func testSteamProducesFiveCharCode() throws {
        let steamAlphabet = Set("23456789BCDFGHJKMNPQRTVWXY")
        let code = try XCTUnwrap(totp.generateCode(secret: "steam://\(secret)"))
        XCTAssertEqual(code.count, 5)
        XCTAssertTrue(code.allSatisfy { steamAlphabet.contains($0) })
    }

    func testInvalidSecretReturnsNil() {
        XCTAssertNil(totp.generateCode(secret: "not base32 @@@"))
    }

    func testRejectsUnsafeDigitLengths() {
        XCTAssertNil(totp.generateCode(secret: "otpauth://totp/Example:alice?secret=\(secret)&digits=4"))
        XCTAssertNil(totp.generateCode(secret: "otpauth://totp/Example:alice?secret=\(secret)&digits=11"))
    }

    func testSecondsRemainingWithinPeriod() {
        let remaining = totp.secondsRemaining(for: secret)
        XCTAssertGreaterThan(remaining, 0)
        XCTAssertLessThanOrEqual(remaining, 30)
    }
}
