import Foundation

// MARK: - Zip central-directory reader (names only; never extracts file data)

/// Reads the list of entry paths from a ZIP archive's central directory.
/// It only parses the directory (the archive's "table of contents") — it never
/// decompresses or extracts file contents, which keeps the operation cheap and safe.
/// The parser is defensive: it validates signatures and bounds and bails out on any
/// malformed field rather than trusting length values from the (possibly hostile) data.
///
/// Deliberately separate from `ZipArchive`, which extracts content for the 1Password importer
/// and refuses encrypted entries outright. A preview only lists names, and an encrypted archive's
/// names are still worth showing.
///
/// Reads through a `[UInt8]` copy rather than an unsafe pointer into the `Data`. Array subscripts
/// are bounds-checked in release builds and an unsafe buffer's are not; on input that may be
/// hostile, an out-of-range read should trap, not read past the buffer. The copy is made once per
/// preview, off the main thread.
enum ZipDirectoryReader {
    /// More entries than any real archive a person would preview; past this the input is treated
    /// as malformed.
    static let maxEntries = 100_000

    /// Returns entry paths (e.g. "folder/", "folder/file.txt") or nil if not a readable zip.
    static func entryPaths(from data: Data) -> [String]? {
        let bytes = [UInt8](data)
        let n = bytes.count
        guard n >= 22 else { return nil } // smallest possible EOCD record

        // Find End Of Central Directory record (signature 0x06054b50), scanning backwards.
        // The trailing comment can be up to 65535 bytes, so search that window.
        let eocdSig: [UInt8] = [0x50, 0x4b, 0x05, 0x06]
        var eocd = -1
        let minStart = max(0, n - (22 + 65535))
        var i = n - 22
        while i >= minStart {
            if bytes[i] == eocdSig[0], bytes[i+1] == eocdSig[1], bytes[i+2] == eocdSig[2], bytes[i+3] == eocdSig[3] {
                eocd = i; break
            }
            i -= 1
        }
        guard eocd >= 0, eocd + 22 <= n else { return nil }

        func u16(_ off: Int) -> Int { Int(bytes[off]) | (Int(bytes[off+1]) << 8) }
        func u32(_ off: Int) -> Int {
            Int(bytes[off]) | (Int(bytes[off+1]) << 8) | (Int(bytes[off+2]) << 16) | (Int(bytes[off+3]) << 24)
        }

        let totalEntries = u16(eocd + 10)
        let cdSize = u32(eocd + 12)
        let cdOffset = u32(eocd + 16)
        // ZIP64 or clearly invalid -> bail (we keep this reader simple and safe).
        guard cdOffset + cdSize <= n, totalEntries <= maxEntries else { return nil }

        var paths: [String] = []
        var p = cdOffset
        let cdEnd = cdOffset + cdSize
        let cenSig: [UInt8] = [0x50, 0x4b, 0x01, 0x02] // central directory file header
        var count = 0
        while p + 46 <= cdEnd, count < totalEntries {
            guard bytes[p] == cenSig[0], bytes[p+1] == cenSig[1], bytes[p+2] == cenSig[2], bytes[p+3] == cenSig[3] else {
                break
            }
            let nameLen = u16(p + 28)
            let extraLen = u16(p + 30)
            let commentLen = u16(p + 32)
            let nameStart = p + 46
            guard nameStart + nameLen <= cdEnd else { break }
            let nameBytes = Array(bytes[nameStart ..< nameStart + nameLen])
            if let name = String(bytes: nameBytes, encoding: .utf8) ?? String(bytes: nameBytes, encoding: .isoLatin1) {
                paths.append(name)
            }
            p = nameStart + nameLen + extraLen + commentLen
            count += 1
        }
        return paths
    }
}

// MARK: - Tree model

final class ZipNode: Identifiable {
    let id = UUID()
    let name: String
    let isDirectory: Bool
    var children: [ZipNode]?

    init(name: String, isDirectory: Bool, children: [ZipNode]? = nil) {
        self.name = name; self.isDirectory = isDirectory; self.children = children
    }

    /// Deepest folder level shown. Everything below is folded into one entry.
    ///
    /// Without a limit, tree building recursed once per path component. A single entry name may be
    /// up to 65,535 bytes, so a crafted archive with one name made of `a/a/a/…` meant some 32,000
    /// levels of recursion on the main thread — enough to overflow the stack and crash the app the
    /// moment the attachment was previewed. An attachment is not always the user's own: in an
    /// organisation vault anyone with access to the item can add one.
    static let maxDepth = 64

    /// Builds a Finder-like tree from flat zip paths.
    static func buildTree(from paths: [String]) -> [ZipNode] {
        // Intermediate mutable structure
        final class Builder { var dirs: [String: Builder] = [:]; var files: Set<String> = [] }
        let root = Builder()

        for raw in paths {
            let isDir = raw.hasSuffix("/")
            var comps = raw.split(separator: "/").map(String.init)
            guard !comps.isEmpty else { continue }
            if comps.count > maxDepth {
                // Keep the top of the path as folders and fold the rest into the final name, so
                // nothing is dropped from the listing — it is just not nested any further.
                let tail = comps.dropFirst(maxDepth - 1).joined(separator: "/")
                comps = Array(comps.prefix(maxDepth - 1)) + [tail]
            }
            var node = root
            for (idx, comp) in comps.enumerated() {
                let last = idx == comps.count - 1
                if last && !isDir {
                    node.files.insert(comp)
                } else {
                    if node.dirs[comp] == nil { node.dirs[comp] = Builder() }
                    node = node.dirs[comp]!
                }
            }
        }

        func convert(_ b: Builder) -> [ZipNode] {
            var out: [ZipNode] = []
            for key in b.dirs.keys.sorted() {
                out.append(ZipNode(name: displayName(key), isDirectory: true, children: convert(b.dirs[key]!)))
            }
            for f in b.files.sorted() {
                out.append(ZipNode(name: displayName(f), isDirectory: false))
            }
            return out
        }
        return convert(root)
    }

    /// An entry name made safe to show.
    ///
    /// Bidirectional-text controls are removed. With them an archive can name a file
    /// `invoice\u{202E}fdp.exe` and have it render as `invoiceexe.pdf` — a listing that lies about
    /// what the archive holds is worse than no listing. Other control characters are shown as a
    /// visible placeholder rather than passed to the text renderer.
    static func displayName(_ raw: String) -> String {
        var out = String.UnicodeScalarView()
        for scalar in raw.unicodeScalars {
            switch scalar.value {
            case 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069:
                continue                                   // bidi marks, embeddings, overrides, isolates
            case 0x00...0x1F, 0x7F:
                out.append("\u{FFFD}")                     // C0 controls and DEL
            default:
                out.append(scalar)
            }
        }
        return String(out)
    }
}
