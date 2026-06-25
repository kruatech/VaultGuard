import SwiftUI

// MARK: - Zip central-directory reader (names only; never extracts file data)

/// Reads the list of entry paths from a ZIP archive's central directory.
/// It only parses the directory (the archive's "table of contents") — it never
/// decompresses or extracts file contents, which keeps the operation cheap and safe.
/// The parser is defensive: it validates signatures and bounds and bails out on any
/// malformed field rather than trusting length values from the (possibly hostile) data.
enum ZipDirectoryReader {
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
        guard totalEntries >= 0, cdOffset >= 0, cdSize >= 0,
              cdOffset + cdSize <= n, totalEntries <= 100_000 else { return nil }

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
            guard nameLen >= 0, nameStart + nameLen <= cdEnd else { break }
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

    /// Builds a Finder-like tree from flat zip paths.
    static func buildTree(from paths: [String]) -> [ZipNode] {
        // Intermediate mutable structure
        final class Builder { var dirs: [String: Builder] = [:]; var files: Set<String> = [] }
        let root = Builder()

        for raw in paths {
            let isDir = raw.hasSuffix("/")
            let comps = raw.split(separator: "/").map(String.init)
            guard !comps.isEmpty else { continue }
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
                out.append(ZipNode(name: key, isDirectory: true, children: convert(b.dirs[key]!)))
            }
            for f in b.files.sorted() {
                out.append(ZipNode(name: f, isDirectory: false))
            }
            return out
        }
        return convert(root)
    }
}

// MARK: - UI

struct ZipPreviewView: View {
    let data: Data

    private var nodes: [ZipNode]? {
        guard let paths = ZipDirectoryReader.entryPaths(from: data) else { return nil }
        return ZipNode.buildTree(from: paths)
    }

    var body: some View {
        Group {
            if let nodes = nodes, !nodes.isEmpty {
                List {
                    OutlineGroup(nodes, children: \.children) { node in
                        HStack(spacing: 8) {
                            Image(systemName: node.isDirectory ? "folder.fill" : "doc")
                                .font(.system(size: 13))
                                .foregroundColor(node.isDirectory ? .accentColor : .secondary)
                            Text(node.name).font(.system(size: 12))
                        }
                    }
                }
                .listStyle(.sidebar)
            } else {
                VStack(spacing: 10) {
                    Image(systemName: "doc.zipper").font(.system(size: 48, weight: .ultraLight)).foregroundColor(.secondary)
                    Text("misc.cannotOpenFile".localized).font(.system(size: 14)).foregroundColor(.secondary)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .background(Color(NSColor.controlBackgroundColor))
    }
}
