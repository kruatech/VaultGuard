import XCTest
import Foundation

/// Rotation of the pre-save `.kdbx` snapshots — the recovery path when a save goes wrong.
///
/// The rule this replaced sorted every snapshot by file name and kept the last ten, which
/// orders by vault name before time. The first test is that exact case, kept as a regression.
final class KeePassBackupPolicyTests: XCTestCase {

    private func url(_ name: String) -> URL {
        URL(fileURLWithPath: "/tmp/KeePassBackups").appendingPathComponent(name)
    }

    private func names(_ urls: [URL]) -> [String] { urls.map(\.lastPathComponent).sorted() }

    // MARK: The bug

    /// Five fresh snapshots of one vault, ten older ones of another whose name sorts later.
    /// Sorting by name deleted all five fresh ones — the newest copies of the first vault —
    /// while keeping stale copies of the second.
    func testNewestSnapshotsOfAnEarlySortingVaultSurvive() {
        let personal = (1...5).map { url(String(format: "Personal_202601%02d_120000.kdbx.bak", $0)) }
        let other = (1...10).map { url(String(format: "vaultguard-uitest_202512%02d_120000.kdbx.bak", $0)) }
        XCTAssertEqual(KeePassBackupPolicy.filesToPrune(personal + other), [],
                       "no vault is over its limit, so nothing should be deleted")
    }

    // MARK: Rotation

    func testOldestAreDroppedPastTheLimit() {
        let snaps = (1...12).map { url(String(format: "V_202601%02d_000000.kdbx.bak", $0)) }
        XCTAssertEqual(names(KeePassBackupPolicy.filesToPrune(snaps)),
                       ["V_20260101_000000.kdbx.bak", "V_20260102_000000.kdbx.bak"])
    }

    /// The limit is per vault: a busy database cannot evict every copy of a quiet one.
    func testLimitIsPerVault() {
        let busy = (1...15).map { url(String(format: "Busy_202601%02d_000000.kdbx.bak", $0)) }
        let quiet = [url("Quiet_20250101_000000.kdbx.bak")]
        let pruned = KeePassBackupPolicy.filesToPrune(busy + quiet)
        XCTAssertEqual(pruned.count, 5)
        XCTAssertFalse(pruned.contains(quiet[0]), "the only copy of the quiet vault was deleted")
    }

    func testAtTheLimitNothingIsDropped() {
        let snaps = (1...10).map { url(String(format: "V_202601%02d_000000.kdbx.bak", $0)) }
        XCTAssertTrue(KeePassBackupPolicy.filesToPrune(snaps).isEmpty)
    }

    /// Anything that does not parse is never deleted on a guess.
    func testUnrecognisedFilesAreNeverPruned() {
        let odd = [url("notes.txt"), url("V_2026010_1200000.kdbx.bak"), url("readme.kdbx.bak")]
        let snaps = (1...12).map { url(String(format: "V_202601%02d_000000.kdbx.bak", $0)) }
        let pruned = KeePassBackupPolicy.filesToPrune(snaps + odd)
        XCTAssertTrue(Set(pruned).isDisjoint(with: odd))
    }

    // MARK: Parsing

    /// A vault name may itself contain underscores and digits; the stamp is split off the end.
    func testVaultNameWithUnderscoresAndDigits() throws {
        let s = try XCTUnwrap(KeePassBackupPolicy.parse(url("My_Vault_2020_20260101_120000.kdbx.bak")))
        XCTAssertEqual(s.vault, "My_Vault_2020")
        XCTAssertEqual(s.stamp, "20260101_120000")
    }

    func testMalformedNamesAreRejected() {
        for name in ["_20260101_120000.kdbx.bak",         // no vault
                     "v_2026010_1200000.kdbx.bak",         // separator in the wrong place
                     "v_20260101_12000x.kdbx.bak",         // non-digit
                     "v_20260101_120000.kdbx",             // wrong suffix
                     "v.kdbx.bak"] {
            XCTAssertNil(KeePassBackupPolicy.parse(url(name)), name)
        }
    }

    // MARK: Ordering

    /// Newest first across vaults, by time — not grouped by vault name.
    func testNewestFirstIsByTimeAcrossVaults() {
        let ordered = KeePassBackupPolicy.newestFirst([
            url("B_20260101_000000.kdbx.bak"),
            url("A_20260103_000000.kdbx.bak"),
            url("C_20260102_000000.kdbx.bak"),
        ]).map(\.vault)
        XCTAssertEqual(ordered, ["A", "C", "B"])
    }
}
