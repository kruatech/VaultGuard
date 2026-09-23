import XCTest
import Foundation

/// Host matching for AutoFill.
///
/// This is the check that decides whose password gets typed into a login form, and a mistake
/// here is silent — no error, no prompt, just the wrong credential offered for a site that
/// looks close enough. The look-alike cases below are the ones a naive `hasSuffix` gets
/// wrong, and they are the reason the implementation compares on label boundaries.
final class AutoFillHostMatcherTests: XCTestCase {

    private func host(_ s: String) -> String? { AutoFillHostMatcher.host(from: s) }
    private func matches(_ credential: String, _ request: String) -> Bool {
        AutoFillHostMatcher.hostMatches(credentialHost: credential, requestHost: request)
    }

    // MARK: Look-alike domains — the security-relevant cases

    /// `evil-example.com` ends with `example.com` as raw text. It is a different registrant.
    func testHyphenPrefixedLookAlikeIsRejected() {
        XCTAssertFalse(matches("example.com", "evil-example.com"))
        XCTAssertFalse(matches("evil-example.com", "example.com"))
    }

    /// `example.com.evil.com` is a subdomain of `evil.com`, not of `example.com`.
    func testDomainEmbeddedInAnotherIsRejected() {
        XCTAssertFalse(matches("example.com", "example.com.evil.com"))
    }

    /// Nothing about sharing a public suffix makes two sites related.
    func testDifferentSecondLevelDomainsDoNotMatch() {
        XCTAssertFalse(matches("example.com", "example.org"))
        XCTAssertFalse(matches("bank.com", "bank.com.co"))
    }

    func testSubstringWithoutALabelBoundaryIsRejected() {
        XCTAssertFalse(matches("ample.com", "example.com"))
        XCTAssertFalse(matches("example.com", "myexample.com"))
    }

    // MARK: Matches that should work

    func testExactHostMatches() {
        XCTAssertTrue(matches("example.com", "example.com"))
    }

    /// A credential saved for the apex should serve its subdomains, and vice versa — people
    /// save one and log in at the other constantly.
    func testSubdomainMatchesInBothDirections() {
        XCTAssertTrue(matches("example.com", "login.example.com"))
        XCTAssertTrue(matches("login.example.com", "example.com"))
        XCTAssertTrue(matches("example.com", "a.b.c.example.com"))
    }

    // MARK: Parsing

    func testBareHostIsAccepted() {
        XCTAssertEqual(host("example.com"), "example.com")
    }

    func testFullURLReducesToItsHost() {
        XCTAssertEqual(host("https://login.example.com/path?q=1"), "login.example.com")
        XCTAssertEqual(host("http://example.com:8443/x"), "example.com")
    }

    func testHostIsLowercasedAndTrimmed() {
        XCTAssertEqual(host("  HTTPS://Login.Example.COM/  "), "login.example.com")
        XCTAssertEqual(host("EXAMPLE.com"), "example.com")
    }

    /// A fully-qualified name ends in a dot; `example.com.` and `example.com` are the same host.
    func testTrailingDotsAreStripped() {
        XCTAssertEqual(host("example.com."), "example.com")
        XCTAssertEqual(host("https://example.com../"), "example.com")
    }

    // MARK: Non-web schemes

    /// Prepending "https://" to `androidapp://com.example.app` used to yield the host
    /// "androidapp", which every such entry shared — so unrelated Android apps matched each
    /// other. These must fail closed.
    func testAndroidAppSchemeHasNoHost() {
        XCTAssertNil(host("androidapp://com.example.app"))
        XCTAssertNil(host("androidapp://com.other.app"))
    }

    func testOtherNonWebSchemesHaveNoHost() {
        XCTAssertNil(host("iosapp://com.example.app"))
        XCTAssertNil(host("file:///etc/passwd"))
        XCTAssertNil(host("ftp://files.example.com"))
    }

    /// Only http and https carry a host for this purpose, in either case.
    func testWebSchemesAreAcceptedRegardlessOfCase() {
        XCTAssertEqual(host("HTTP://example.com"), "example.com")
        XCTAssertEqual(host("HtTpS://example.com"), "example.com")
    }

    /// A "://" that appears after a slash is not a scheme separator, so the identifier is
    /// still treated as a bare host rather than thrown away.
    func testSchemeLikeTextLaterInTheStringIsNotTreatedAsAScheme() {
        XCTAssertEqual(host("example.com/a://b"), "example.com")
    }

    // MARK: Empty and malformed input

    func testEmptyInputIsNil() {
        XCTAssertNil(host(""))
        XCTAssertNil(host("   "))
    }

    func testSchemeWithNothingAfterItIsNil() {
        XCTAssertNil(host("https://"))
    }

    /// Two unparseable identifiers must not become equal by both being nil — callers check
    /// for nil before matching, and this documents that contract.
    func testUnparseableIdentifiersProduceNoHostToCompare() {
        XCTAssertNil(host("androidapp://a"))
        XCTAssertNil(host("androidapp://b"))
    }
}
