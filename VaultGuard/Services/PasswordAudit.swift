import Foundation

/// A single finding in the password health report.
struct PasswordIssue: Identifiable {
    enum Kind {
        /// `PasswordStrength` rates the password at the bottom of its scale.
        case weak
        /// The same password is stored on more than one item.
        case reused(count: Int)
        /// The item has no password at all, on a type that should have one.
        case empty
        /// The password has not changed in a long time.
        case stale(days: Int)
    }

    let id: String          // cipher id; an item appears once per kind
    let cipherId: String
    let cipherName: String
    let kind: Kind
}

/// Scans a decrypted vault for password hygiene problems.
///
/// Read-only and synchronous: it works on the ciphers already in memory, makes no network
/// calls and sends nothing anywhere. The comparison for reuse is done over hashes of the
/// passwords rather than the passwords themselves, so no plaintext is held in the grouping
/// structure any longer than the loop that builds it.
///
/// Deliberately *not* a breach check. Telling the user which of their passwords appeared in a
/// leak means asking a third party about them; that is a product decision with privacy
/// consequences, not a report you add quietly.
enum PasswordAudit {

    /// Items older than this are reported as stale. Three years is the point where a password
    /// predates most people's memory of setting it, rather than a security threshold — there
    /// is no evidence that rotating a strong unique password on a schedule helps.
    static let staleAfterDays = 1095

    /// Every finding, ordered: reuse first (it affects more than one account), then weak,
    /// then empty, then stale.
    static func scan(_ ciphers: [VaultCipher], now: Date = Date()) -> [PasswordIssue] {
        let candidates = ciphers.filter { $0.deletedDate == nil && $0.type == .login }

        var issues: [PasswordIssue] = []
        issues += reuseIssues(in: candidates)
        issues += weakIssues(in: candidates)
        issues += emptyIssues(in: candidates)
        issues += staleIssues(in: candidates, now: now)
        return issues
    }

    /// Passwords stored on more than one item. Grouped by hash: two items sharing a password
    /// is the finding, and the password itself is never needed to report it.
    private static func reuseIssues(in ciphers: [VaultCipher]) -> [PasswordIssue] {
        var byPassword: [Int: [VaultCipher]] = [:]
        for c in ciphers {
            guard let pw = c.login?.password, !pw.isEmpty else { continue }
            byPassword[pw.hashValue, default: []].append(c)
        }
        return byPassword.values
            .filter { $0.count > 1 }
            .flatMap { group in
                group.map {
                    PasswordIssue(id: "reused:" + $0.id, cipherId: $0.id, cipherName: $0.name,
                                  kind: .reused(count: group.count))
                }
            }
            .sorted { $0.cipherName.localizedCaseInsensitiveCompare($1.cipherName) == .orderedAscending }
    }

    private static func weakIssues(in ciphers: [VaultCipher]) -> [PasswordIssue] {
        ciphers.compactMap { c in
            guard let pw = c.login?.password, !pw.isEmpty else { return nil }
            guard PasswordStrength.evaluate(pw).score <= 1 else { return nil }
            return PasswordIssue(id: "weak:" + c.id, cipherId: c.id, cipherName: c.name, kind: .weak)
        }
    }

    /// A login with a username but no password is usually an import that lost something, not
    /// a deliberate blank.
    private static func emptyIssues(in ciphers: [VaultCipher]) -> [PasswordIssue] {
        ciphers.compactMap { c in
            let hasPassword = !(c.login?.password ?? "").isEmpty
            let hasUsername = !(c.login?.username ?? "").isEmpty
            guard !hasPassword, hasUsername else { return nil }
            return PasswordIssue(id: "empty:" + c.id, cipherId: c.id, cipherName: c.name, kind: .empty)
        }
    }

    /// `revisionDate` is the closest thing available to "when the password last changed" —
    /// any edit bumps it, so this under-reports rather than over-reports.
    private static func staleIssues(in ciphers: [VaultCipher], now: Date) -> [PasswordIssue] {
        ciphers.compactMap { c in
            guard let pw = c.login?.password, !pw.isEmpty, let changed = c.revisionDate else { return nil }
            let days = Calendar.current.dateComponents([.day], from: changed, to: now).day ?? 0
            guard days >= staleAfterDays else { return nil }
            return PasswordIssue(id: "stale:" + c.id, cipherId: c.id, cipherName: c.name,
                                 kind: .stale(days: days))
        }
    }
}
