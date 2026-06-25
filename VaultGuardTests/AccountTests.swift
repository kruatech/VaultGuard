import XCTest

final class AccountTests: XCTestCase {

    func testMakeIdIsStableAcrossFormatting() {
        let a = Account.makeId(serverURL: "https://vault.example.com", email: "User@Example.com")
        let b = Account.makeId(serverURL: "https://vault.example.com/", email: "user@example.com")
        let c = Account.makeId(serverURL: "  HTTPS://VAULT.EXAMPLE.COM///  ", email: "  user@example.com  ")
        let d = Account.makeId(serverURL: "vault.example.com", email: "user@example.com")
        XCTAssertEqual(a, b, "trailing slash and email case must not change the id")
        XCTAssertEqual(a, c, "surrounding whitespace and server case must not change the id")
        XCTAssertEqual(a, d, "omitting https:// must not create a duplicate account")
    }

    func testMakeIdDiffersByEmailAndServer() {
        let base = Account.makeId(serverURL: "https://a.com", email: "x@a.com")
        XCTAssertNotEqual(base, Account.makeId(serverURL: "https://a.com", email: "y@a.com"))
        XCTAssertNotEqual(base, Account.makeId(serverURL: "https://b.com", email: "x@a.com"))
    }

    func testMakeIdIsHex64() {
        let id = Account.makeId(serverURL: "https://a.com", email: "x@a.com")
        XCTAssertEqual(id.count, 64, "SHA-256 hex digest is 64 chars")
        XCTAssertTrue(id.allSatisfy { $0.isHexDigit })
    }

    func testNormalizeServer() {
        XCTAssertEqual(Account.normalizeServer("  https://A.com///  "), "https://a.com")
        XCTAssertEqual(Account.normalizeServer("https://a.com"), "https://a.com")
        XCTAssertEqual(Account.normalizeServer("HTTPS://Vault.Example.com/"), "https://vault.example.com")
        XCTAssertEqual(Account.normalizeServer("vault.example.com/"), "https://vault.example.com")
    }

    func testCodableRoundTrip() throws {
        let accounts = [
            Account(id: "id1", serverURL: "https://a.com", email: "a@a.com", profileName: "Alice", addedAt: Date(timeIntervalSince1970: 1000)),
            Account(id: "id2", serverURL: "https://b.com", email: "b@b.com", profileName: "Bob", addedAt: Date(timeIntervalSince1970: 2000)),
        ]
        let data = try JSONEncoder().encode(accounts)
        let decoded = try JSONDecoder().decode([Account].self, from: data)
        XCTAssertEqual(decoded, accounts)
    }

    func testDisplayNameUsesLabelOrEmailAndHost() {
        let labeled = Account(id: "i", serverURL: "https://a.com", email: "a@a.com", profileName: "Alice", label: "Personal")
        let fallback = Account(id: "i", serverURL: "https://a.com", email: "a@a.com", profileName: "Alice")
        XCTAssertEqual(labeled.displayName, "Personal")
        XCTAssertEqual(fallback.displayName, "a@a.com · a.com")
    }

    func testServerHostExtraction() {
        let acc = Account(id: "i", serverURL: "https://vault.example.com", email: "a@a.com", profileName: "")
        XCTAssertEqual(acc.serverHost, "vault.example.com")
    }
}
