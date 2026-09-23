import XCTest
import Foundation

/// `PasswordAudit` is pure: ciphers in, findings out, no clock beyond the date it is handed.
/// That makes every rule here assertable exactly rather than approximately.
final class PasswordAuditTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func login(_ name: String, password: String?, username: String? = "user",
                       revision: Date? = nil, deleted: Date? = nil,
                       type: CipherType = .login) -> VaultCipher {
        VaultCipher(id: name, organizationId: nil, folderId: nil, collectionIds: nil,
                    type: type, name: name, notes: nil,
                    login: CipherLogin(username: username, password: password, totp: nil, uris: nil),
                    card: nil, secureNote: nil, identity: nil,
                    fields: nil, attachments: nil, favorite: false, reprompt: nil,
                    creationDate: nil, revisionDate: revision, deletedDate: deleted)
    }

    private func kinds(_ issues: [PasswordIssue], for name: String) -> [String] {
        issues.filter { $0.cipherName == name }.map {
            switch $0.kind {
            case .reused: return "reused"
            case .weak:   return "weak"
            case .empty:  return "empty"
            case .stale:  return "stale"
            }
        }.sorted()
    }

    // MARK: Reuse

    func testSharedPasswordIsReportedOnEveryItemThatUsesIt() {
        let issues = PasswordAudit.scan([
            login("a", password: "Sh4red-Passw0rd!x"),
            login("b", password: "Sh4red-Passw0rd!x"),
            login("c", password: "Different-Passw0rd!y"),
        ], now: now)
        XCTAssertTrue(kinds(issues, for: "a").contains("reused"))
        XCTAssertTrue(kinds(issues, for: "b").contains("reused"))
        XCTAssertFalse(kinds(issues, for: "c").contains("reused"))
    }

    /// The count in the finding is how many items share it, not how many others do.
    func testReuseCountIsTheSizeOfTheGroup() throws {
        let issues = PasswordAudit.scan([
            login("a", password: "Sh4red-Passw0rd!x"),
            login("b", password: "Sh4red-Passw0rd!x"),
            login("c", password: "Sh4red-Passw0rd!x"),
        ], now: now)
        let first = try XCTUnwrap(issues.first { if case .reused = $0.kind { return true }; return false })
        guard case .reused(let count) = first.kind else { return XCTFail("expected a reuse finding") }
        XCTAssertEqual(count, 3)
    }

    /// Empty passwords are not "the same password" — grouping them would report every blank
    /// item as reused with every other blank item.
    func testEmptyPasswordsAreNotTreatedAsReuse() {
        let issues = PasswordAudit.scan([
            login("a", password: ""),
            login("b", password: ""),
        ], now: now)
        XCTAssertTrue(issues.allSatisfy { if case .reused = $0.kind { return false }; return true })
    }

    // MARK: Weak

    func testWeakPasswordIsReported() {
        let issues = PasswordAudit.scan([login("a", password: "abc")], now: now)
        XCTAssertEqual(kinds(issues, for: "a"), ["weak"])
    }

    func testStrongPasswordIsNotReported() {
        let issues = PasswordAudit.scan([
            login("a", password: "Tr0ub4dor&3-correct-horse-battery")
        ], now: now)
        XCTAssertFalse(kinds(issues, for: "a").contains("weak"))
    }

    // MARK: Empty

    /// A login with a username but no password is usually a lossy import.
    func testLoginWithUsernameAndNoPasswordIsReported() {
        let issues = PasswordAudit.scan([login("a", password: nil, username: "user")], now: now)
        XCTAssertEqual(kinds(issues, for: "a"), ["empty"])
    }

    /// With neither field there is nothing to say — an empty stub is not a password problem.
    func testLoginWithNeitherFieldIsSilent() {
        let issues = PasswordAudit.scan([login("a", password: nil, username: nil)], now: now)
        XCTAssertEqual(kinds(issues, for: "a"), [])
    }

    // MARK: Stale

    func testPasswordOlderThanTheThresholdIsReported() {
        let old = now.addingTimeInterval(-Double(PasswordAudit.staleAfterDays + 10) * 86_400)
        let issues = PasswordAudit.scan([
            login("a", password: "Tr0ub4dor&3-correct-horse-battery", revision: old)
        ], now: now)
        XCTAssertEqual(kinds(issues, for: "a"), ["stale"])
    }

    func testRecentPasswordIsNotStale() {
        let recent = now.addingTimeInterval(-30 * 86_400)
        let issues = PasswordAudit.scan([
            login("a", password: "Tr0ub4dor&3-correct-horse-battery", revision: recent)
        ], now: now)
        XCTAssertEqual(kinds(issues, for: "a"), [])
    }

    /// No revision date means nothing is known about when it changed, which is not the same
    /// as knowing it is old.
    func testMissingRevisionDateIsNotStale() {
        let issues = PasswordAudit.scan([
            login("a", password: "Tr0ub4dor&3-correct-horse-battery", revision: nil)
        ], now: now)
        XCTAssertEqual(kinds(issues, for: "a"), [])
    }

    // MARK: Scope

    func testTrashedItemsAreIgnored() {
        let issues = PasswordAudit.scan([login("a", password: "abc", deleted: now)], now: now)
        XCTAssertTrue(issues.isEmpty)
    }

    /// Cards, notes and identities have no password to judge.
    func testNonLoginTypesAreIgnored() {
        let issues = PasswordAudit.scan([
            login("card", password: "abc", type: .card),
            login("note", password: "abc", type: .secureNote),
            login("ident", password: "abc", type: .identity),
        ], now: now)
        XCTAssertTrue(issues.isEmpty)
    }

    func testCleanVaultProducesNoFindings() {
        let recent = now.addingTimeInterval(-86_400)
        let issues = PasswordAudit.scan([
            login("a", password: "Tr0ub4dor&3-correct-horse", revision: recent),
            login("b", password: "C0rrect-Battery-Staple!9", revision: recent),
        ], now: now)
        XCTAssertTrue(issues.isEmpty, "unexpected findings: \(issues.map { $0.id })")
    }

    func testEmptyVaultProducesNoFindings() {
        XCTAssertTrue(PasswordAudit.scan([], now: now).isEmpty)
    }

    /// One item can carry more than one finding, and the ids must stay distinct so SwiftUI's
    /// ForEach does not collapse them into one row.
    func testIdsAreUniqueAcrossKinds() {
        let old = now.addingTimeInterval(-Double(PasswordAudit.staleAfterDays + 10) * 86_400)
        let issues = PasswordAudit.scan([
            login("a", password: "abc", revision: old),
            login("b", password: "abc", revision: old),
        ], now: now)
        XCTAssertEqual(Set(issues.map { $0.id }).count, issues.count)
        XCTAssertEqual(kinds(issues, for: "a"), ["reused", "stale", "weak"])
    }
}
