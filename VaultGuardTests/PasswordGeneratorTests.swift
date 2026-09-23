import XCTest
import Foundation

/// `CryptoService.generatePassword` had no coverage, and it is the one place in the app whose
/// output is only as good as its randomness — a subtly biased or short-cycling generator
/// produces passwords that look fine and are not.
///
/// The statistical checks below use loose thresholds on purpose. They are there to catch a
/// generator that is broken, not to assert a distribution; a test that fails once a month on
/// chance teaches people to re-run it rather than read it.
final class PasswordGeneratorTests: XCTestCase {

    private let upper = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    private let lower = Set("abcdefghijklmnopqrstuvwxyz")
    private let digit = Set("0123456789")
    private let symbol = Set("!@#$%^&*()_+-=")

    // MARK: Shape

    func testLengthIsRespected() {
        for length in [1, 4, 8, 20, 64, 128] {
            XCTAssertEqual(CryptoService.generatePassword(length: length).count, length, "length \(length)")
        }
    }

    /// A length of zero or below would otherwise produce an empty password that the UI would
    /// happily save.
    func testNonPositiveLengthStillProducesAPassword() {
        XCTAssertEqual(CryptoService.generatePassword(length: 0).count, 1)
        XCTAssertEqual(CryptoService.generatePassword(length: -5).count, 1)
    }

    // MARK: Character classes

    func testOnlySelectedClassesAppear() {
        let digitsOnly = CryptoService.generatePassword(length: 40, uppercase: false, lowercase: false,
                                                        digits: true, symbols: false)
        XCTAssertTrue(digitsOnly.allSatisfy { digit.contains($0) }, digitsOnly)

        let lettersOnly = CryptoService.generatePassword(length: 40, uppercase: true, lowercase: true,
                                                         digits: false, symbols: false)
        XCTAssertTrue(lettersOnly.allSatisfy { upper.contains($0) || lower.contains($0) }, lettersOnly)
    }

    /// Every selected class must actually appear, or a site that demands a digit rejects a
    /// password the generator claimed was fine.
    func testEverySelectedClassIsPresent() {
        for _ in 0..<200 {
            let pw = CryptoService.generatePassword(length: 8)
            XCTAssertTrue(pw.contains(where: upper.contains), pw)
            XCTAssertTrue(pw.contains(where: lower.contains), pw)
            XCTAssertTrue(pw.contains(where: digit.contains), pw)
            XCTAssertTrue(pw.contains(where: symbol.contains), pw)
        }
    }

    /// With no class selected the generator must still return something usable rather than an
    /// empty string or a crash.
    func testNoClassSelectedFallsBackToLetters() {
        let pw = CryptoService.generatePassword(length: 16, uppercase: false, lowercase: false,
                                                digits: false, symbols: false)
        XCTAssertEqual(pw.count, 16)
        XCTAssertTrue(pw.allSatisfy { lower.contains($0) }, pw)
    }

    func testAmbiguousCharactersAreExcludedWhenAsked() {
        let ambiguous = Set("O0oIl1|`'\"")
        for _ in 0..<50 {
            let pw = CryptoService.generatePassword(length: 60, excludeAmbiguous: true)
            XCTAssertFalse(pw.contains(where: ambiguous.contains), pw)
        }
    }

    /// A length shorter than the number of selected classes cannot satisfy all of them; it
    /// must still produce exactly that many characters instead of overshooting.
    func testLengthBelowClassCountStillMatchesTheRequestedLength() {
        XCTAssertEqual(CryptoService.generatePassword(length: 2).count, 2)
        XCTAssertEqual(CryptoService.generatePassword(length: 3).count, 3)
    }

    // MARK: Randomness

    /// The clearest sign of a broken generator: repeated calls returning the same thing.
    func testPasswordsDoNotRepeat() {
        let generated = Set((0..<500).map { _ in CryptoService.generatePassword(length: 20) })
        XCTAssertEqual(generated.count, 500, "a 20-character password repeated within 500 draws")
    }

    /// The class-seeding step puts one character from each class at the front before the
    /// shuffle. If the shuffle were dropped or wrong, position 0 would always be uppercase.
    func testFirstCharacterIsNotPinnedToOneClass() {
        var classesSeen = Set<String>()
        for _ in 0..<300 {
            let first = CryptoService.generatePassword(length: 12).first!
            if upper.contains(first) { classesSeen.insert("upper") }
            else if lower.contains(first) { classesSeen.insert("lower") }
            else if digit.contains(first) { classesSeen.insert("digit") }
            else if symbol.contains(first) { classesSeen.insert("symbol") }
        }
        XCTAssertEqual(classesSeen.count, 4,
                       "the first character only ever came from \(classesSeen.sorted()) — is the shuffle running?")
    }

    /// Rough uniformity over the alphabet. With 16 symbols and 40 000 draws the expected count
    /// per symbol is 2500; the bound below is wide enough that only a real bias trips it.
    func testDigitsAreRoughlyUniform() {
        var counts = [Character: Int]()
        for _ in 0..<1000 {
            for c in CryptoService.generatePassword(length: 40, uppercase: false, lowercase: false,
                                                    digits: true, symbols: false) {
                counts[c, default: 0] += 1
            }
        }
        XCTAssertEqual(counts.count, 10, "not every digit was produced")
        let expected = 40_000 / 10
        for (digit, count) in counts {
            XCTAssertGreaterThan(count, expected / 2, "digit \(digit) came up far too rarely")
            XCTAssertLessThan(count, expected * 2, "digit \(digit) came up far too often")
        }
    }

    /// Every position must vary. A generator that fixed any position would still pass the
    /// uniformity check above.
    func testEveryPositionVaries() {
        let length = 12
        var perPosition = Array(repeating: Set<Character>(), count: length)
        for _ in 0..<200 {
            let pw = Array(CryptoService.generatePassword(length: length))
            for i in 0..<length { perPosition[i].insert(pw[i]) }
        }
        for (i, seen) in perPosition.enumerated() {
            XCTAssertGreaterThan(seen.count, 5, "position \(i) produced only \(seen.count) distinct characters")
        }
    }
}
