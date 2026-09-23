import Foundation

/// Naming, ordering and rotation of the pre-save `.kdbx` snapshots.
///
/// Snapshots are named `<vault>_<yyyyMMdd_HHmmss>.kdbx.bak`. Everything here used to sort by the
/// whole file name, which orders by vault name first and time second. With more than one vault
/// that is not a time order at all:
///
/// * rotation kept "the last 10" alphabetically, so saving a vault whose name sorted late
///   deleted the *newest* snapshots of a vault whose name sorted early;
/// * the Settings list, described as newest first, was grouped by vault instead.
///
/// The snapshots are the recovery path for a save that went wrong, so losing the newest ones is
/// the failure that matters most. Rotation is now per vault and by timestamp.
///
/// Kept free of `AppState` so the rules can be unit-tested.
enum KeePassBackupPolicy {

    /// Snapshots kept for each vault. Per vault, so one frequently edited database cannot evict
    /// every copy of another.
    static let keepPerVault = 10

    static let suffix = ".kdbx.bak"

    /// `yyyyMMdd_HHmmss` — fixed width, which is what makes the name splittable.
    static let stampLength = 15

    struct Snapshot: Equatable {
        let url: URL
        /// The vault's file name without extension.
        let vault: String
        /// `yyyyMMdd_HHmmss`; lexical order is chronological order.
        let stamp: String
    }

    /// Split a snapshot file name into vault and timestamp. Nil for anything that is not one —
    /// the directory is ours, but a file that does not parse is never deleted on a guess.
    static func parse(_ url: URL) -> Snapshot? {
        let name = url.lastPathComponent
        guard name.hasSuffix(suffix) else { return nil }
        let stem = name.dropLast(suffix.count)                       // <vault>_<stamp>
        guard stem.count > stampLength + 1 else { return nil }

        let separator = stem.index(stem.endIndex, offsetBy: -(stampLength + 1))
        guard stem[separator] == "_" else { return nil }
        let stamp = String(stem[stem.index(after: separator)...])
        guard isStamp(stamp) else { return nil }

        let vault = String(stem[..<separator])
        guard !vault.isEmpty else { return nil }
        return Snapshot(url: url, vault: vault, stamp: stamp)
    }

    /// Every snapshot, newest first across all vaults. Files that do not parse are left out.
    static func newestFirst(_ urls: [URL]) -> [Snapshot] {
        urls.compactMap(parse).sorted { a, b in
            a.stamp != b.stamp ? a.stamp > b.stamp : a.vault < b.vault
        }
    }

    /// Snapshots to delete: for each vault, everything past its newest `keepPerVault`.
    /// Files that do not parse are never returned.
    static func filesToPrune(_ urls: [URL], keep: Int = keepPerVault) -> [URL] {
        let byVault = Dictionary(grouping: urls.compactMap(parse), by: \.vault)
        return byVault.values.flatMap { snapshots in
            snapshots.sorted { $0.stamp > $1.stamp }.dropFirst(max(0, keep)).map(\.url)
        }
    }

    /// `yyyyMMdd_HHmmss`: eight digits, an underscore, six digits.
    private static func isStamp(_ s: String) -> Bool {
        let chars = Array(s)
        guard chars.count == stampLength, chars[8] == "_" else { return false }
        return chars.enumerated().allSatisfy { i, c in i == 8 || c.isASCII && c.isNumber }
    }
}
