import XCTest
import Foundation

/// The stored server address and the account id are computed differently on purpose: the id
/// keys the Keychain and must never change, while the address is used for every request and
/// must keep the path exactly as the server expects it.
final class AccountServerURLTests: XCTestCase {

    // MARK: The bug

    /// A path with capitals worked for the first sign-in — which uses the address as typed — and
    /// failed on the next biometric unlock, which read back an address lowercased throughout.
    func testPathKeepsItsCase() {
        XCTAssertEqual(Account.normalizeServer("https://Example.com/Vault"), "https://example.com/Vault")
        XCTAssertEqual(Account.normalizeServer("https://example.com/BW/api"), "https://example.com/BW/api")
    }

    func testSchemeAndHostAreLowercased() {
        XCTAssertEqual(Account.normalizeServer("HTTPS://Vault.Example.COM/Path"), "https://vault.example.com/Path")
    }

    func testPortIsKept() {
        XCTAssertEqual(Account.normalizeServer("https://Box.LAN:8443/BW/"), "https://box.lan:8443/BW")
    }

    // MARK: What must not change

    /// Changing how the id is computed would orphan every stored token and vault key. Addresses
    /// that differ only in path case therefore still map to one account.
    func testIdIsUnaffectedByPathCase() {
        XCTAssertEqual(Account.makeId(serverURL: "https://example.com/Vault", email: "a@b.c"),
                       Account.makeId(serverURL: "https://example.com/vault", email: "a@b.c"))
    }

    /// The id is still derived from the old, fully lowercased form — the exact value accounts
    /// created before this change were keyed by.
    func testIdStillUsesTheOriginalNormalisation() {
        XCTAssertEqual(Account.identityKey("  HTTPS://Example.com/Vault///  "), "https://example.com/vault")
    }

    /// Addresses without a path behave exactly as before.
    func testHostOnlyAddressesAreUnchanged() {
        XCTAssertEqual(Account.normalizeServer("  https://A.com///  "), "https://a.com")
        XCTAssertEqual(Account.normalizeServer("vault.example.com/"), "https://vault.example.com")
        XCTAssertEqual(Account.normalizeServer("HTTPS://Vault.Example.com/"), "https://vault.example.com")
    }

    func testMissingSchemeDefaultsToHTTPS() {
        XCTAssertEqual(Account.normalizeServer("example.com/Vault"), "https://example.com/Vault")
    }

    /// An explicit http:// is kept, not upgraded — the user may genuinely run a server without
    /// TLS on their network. The sign-in screen warns instead.
    func testExplicitHTTPIsKept() {
        XCTAssertEqual(Account.normalizeServer("http://192.168.1.10:8080"), "http://192.168.1.10:8080")
    }

    // MARK: Plain HTTP detection

    func testPlainHTTPIsDetected() {
        XCTAssertTrue(Account.usesPlainHTTP("http://192.168.1.10"))
        XCTAssertTrue(Account.usesPlainHTTP("  HTTP://nas.local  "))
    }

    func testHTTPSAndBareHostsAreNotFlagged() {
        XCTAssertFalse(Account.usesPlainHTTP("https://vault.example.com"))
        XCTAssertFalse(Account.usesPlainHTTP("vault.example.com"), "a bare host defaults to https")
        XCTAssertFalse(Account.usesPlainHTTP(""))
    }
}
