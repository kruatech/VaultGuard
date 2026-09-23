import XCTest
import Foundation

/// The attachment preview lists a zip's contents. The archive is untrusted — in an organisation
/// vault anyone with access to an item can attach one — so the listing is tested for what a hostile
/// archive can do to it, not only for the happy path.
final class ZipListingTests: XCTestCase {

    /// A small archive: a folder, a file inside it, a file two levels down, a top-level file, and a
    /// file whose name uses a right-to-left override to disguise its extension.
    private let fixtureB64 =
        "UEsDBBQAAAAAACS8Nl0AAAAAAAAAAAAAAAAFAAAAZG9jcy9QSwMEFAAAAAAAJLw2XYamEDYFAAAABQAAAA8AAABkb2NzL3JlYWRt" +
        "ZS50eHRoZWxsb1BLAwQUAAAAAAAkvDZdXViTkwQAAAAEAAAAEQAAAGRvY3Mvc3ViL2RlZXAudHh0ZGVlcFBLAwQUAAAAAAAkvDZd" +
        "yh/ZHgMAAAADAAAABwAAAHRvcC50eHR0b3BQSwMEFAAACAAAJLw2XYMW3IwBAAAAAQAAABEAAABpbnZvaWNl4oCuZmRwLmV4ZXhQ" +
        "SwECFAMUAAAAAAAkvDZdAAAAAAAAAAAAAAAABQAAAAAAAAAAABAA/UEAAAAAZG9jcy9QSwECFAMUAAAAAAAkvDZdhqYQNgUAAAAF" +
        "AAAADwAAAAAAAAAAAAAAgAEjAAAAZG9jcy9yZWFkbWUudHh0UEsBAhQDFAAAAAAAJLw2XV1Yk5MEAAAABAAAABEAAAAAAAAAAAAA" +
        "AIABVQAAAGRvY3Mvc3ViL2RlZXAudHh0UEsBAhQDFAAAAAAAJLw2Xcof2R4DAAAAAwAAAAcAAAAAAAAAAAAAAIABiAAAAHRvcC50" +
        "eHRQSwECFAMUAAAIAAAkvDZdgxbcjAEAAAABAAAAEQAAAAAAAAAAAAAAgAGwAAAAaW52b2ljZeKArmZkcC5leGVQSwUGAAAAAAUA" +
        "BQAjAQAA4AAAAAAA"

    private var fixture: Data { Data(base64Encoded: fixtureB64)! }

    private func depth(_ nodes: [ZipNode]) -> Int {
        nodes.map { 1 + depth($0.children ?? []) }.max() ?? 0
    }

    // MARK: Reading the directory

    func testListsEveryEntry() throws {
        let paths = try XCTUnwrap(ZipDirectoryReader.entryPaths(from: fixture))
        XCTAssertEqual(paths.count, 5)
        XCTAssertTrue(paths.contains("docs/sub/deep.txt"))
    }

    func testNonArchiveInputIsRejected() {
        XCTAssertNil(ZipDirectoryReader.entryPaths(from: Data()))
        XCTAssertNil(ZipDirectoryReader.entryPaths(from: Data("not a zip at all, definitely not".utf8)))
    }

    /// A directory that claims to extend past the end of the data must be refused, not read.
    func testDirectoryPastTheEndIsRejected() {
        var bytes = [UInt8](fixture)
        // Find the end-of-central-directory record and push its offset field out of range.
        let sig: [UInt8] = [0x50, 0x4b, 0x05, 0x06]
        guard let eocd = (0...(bytes.count - 22)).reversed().first(where: { Array(bytes[$0..<$0 + 4]) == sig }) else {
            return XCTFail("fixture has no end-of-central-directory record")
        }
        for k in 0..<4 { bytes[eocd + 16 + k] = 0xFF }
        XCTAssertNil(ZipDirectoryReader.entryPaths(from: Data(bytes)))
    }

    // MARK: The tree

    func testFoldersComeBeforeFilesAndBothAreSorted() throws {
        let nodes = ZipNode.buildTree(from: try XCTUnwrap(ZipDirectoryReader.entryPaths(from: fixture)))
        XCTAssertEqual(nodes.first?.name, "docs")
        XCTAssertTrue(nodes.first?.isDirectory == true)
        let docs = try XCTUnwrap(nodes.first?.children)
        XCTAssertEqual(docs.map(\.name), ["sub", "readme.txt"])
    }

    /// One crafted name of `a/a/a/…` used to recurse once per component — some 32,000 levels for a
    /// 64 KB name — and overflow the stack on the main thread. The depth is now bounded, and
    /// nothing is dropped: the rest of the path is folded into the last node's name.
    func testPathologicallyDeepPathIsBounded() {
        let name = String(repeating: "a/", count: 30_000) + "leaf.txt"
        let nodes = ZipNode.buildTree(from: [name])
        XCTAssertEqual(depth(nodes), ZipNode.maxDepth)

        var node = nodes.first
        while let next = node?.children?.first { node = next }
        XCTAssertTrue(node?.name.hasSuffix("leaf.txt") == true, "the end of the path was lost")
    }

    func testOrdinaryDepthIsUntouched() {
        XCTAssertEqual(depth(ZipNode.buildTree(from: ["a/b/c/d.txt"])), 4)
    }

    // MARK: Names that lie

    /// `invoice<RLO>fdp.exe` renders as `invoiceexe.pdf`. The override is removed so the listing
    /// shows the real order of characters, and with it the real extension.
    func testRightToLeftOverrideIsRemoved() throws {
        let nodes = ZipNode.buildTree(from: try XCTUnwrap(ZipDirectoryReader.entryPaths(from: fixture)))
        let disguised = try XCTUnwrap(nodes.first { $0.name.hasPrefix("invoice") })
        XCTAssertEqual(disguised.name, "invoicefdp.exe")
        XCTAssertTrue(disguised.name.hasSuffix(".exe"))
    }

    func testEveryBidiControlIsRemoved() {
        let controls = ["\u{200E}", "\u{200F}", "\u{202A}", "\u{202B}", "\u{202C}", "\u{202D}", "\u{202E}",
                        "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}"]
        for c in controls {
            XCTAssertEqual(ZipNode.displayName("a\(c)b"), "ab", "U+\(String(c.unicodeScalars.first!.value, radix: 16, uppercase: true)) survived")
        }
    }

    /// Control characters are shown as a visible placeholder, not passed to the text renderer.
    func testControlCharactersAreMadeVisible() {
        XCTAssertEqual(ZipNode.displayName("a\u{0}b\u{1B}c\u{7F}"), "a\u{FFFD}b\u{FFFD}c\u{FFFD}")
    }

    /// Ordinary text in any script is left exactly as it is.
    func testOrdinaryNamesAreUnchanged() {
        for name in ["report.pdf", "Отчёт 2026.xlsx", "報告.txt", "a b-c_d (1).zip"] {
            XCTAssertEqual(ZipNode.displayName(name), name)
        }
    }
}
