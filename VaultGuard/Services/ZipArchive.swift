import Foundation
import Compression

/// Read-only ZIP reader: enough to pull named entries out of an archive, nothing more.
///
/// Written rather than taken from a package because the app needs exactly one thing from ZIP
/// — reading `export.data` out of a `.1pux` — and a password manager is a bad place to add a
/// dependency that parses untrusted input for a single call site. Everything here is bounds
/// checked and refuses rather than guesses.
///
/// Not supported, on purpose: ZIP64, encrypted entries, split archives, and any compression
/// method beyond stored and deflate. Each is reported as its own error rather than silently
/// producing wrong bytes.
enum ZipArchive {

    enum ZipError: LocalizedError {
        case notAZipArchive
        case unsupportedZip64
        case encryptedEntry
        case unsupportedCompression(UInt16)
        case corrupted
        case entryTooLarge
        case entryNotFound(String)

        var errorDescription: String? {
            switch self {
            case .notAZipArchive:            return "Not a ZIP archive"
            case .unsupportedZip64:          return "ZIP64 archives are not supported"
            case .encryptedEntry:            return "The archive is password-protected"
            case .unsupportedCompression(let m): return "Unsupported ZIP compression method \(m)"
            case .corrupted:                 return "The archive is damaged"
            case .entryTooLarge:             return "An entry in the archive is too large"
            case .entryNotFound(let name):   return "\(name) is missing from the archive"
            }
        }
    }

    /// Ceiling on a single decompressed entry, for the same reason `KDBXReader` caps gunzip:
    /// the size comes from the archive's own headers, so a crafted file could otherwise ask
    /// for gigabytes before anything is validated.
    static let maxEntrySize = 256 * 1024 * 1024

    private static let eocdSignature: UInt32 = 0x0605_4b50
    private static let centralSignature: UInt32 = 0x0201_4b50
    private static let localSignature: UInt32 = 0x0403_4b50

    /// Names of every file in the archive, in central-directory order.
    static func entryNames(in data: Data) throws -> [String] {
        try centralEntries(in: data).map { $0.name }
    }

    /// Contents of one entry by exact name.
    static func extract(_ name: String, from data: Data) throws -> Data {
        guard let entry = try centralEntries(in: data).first(where: { $0.name == name }) else {
            throw ZipError.entryNotFound(name)
        }
        return try read(entry, from: data)
    }

    /// Contents of the first entry whose name matches `predicate`. Used where the path inside
    /// the archive varies (some exporters nest everything under a folder).
    static func extractFirst(from data: Data, where predicate: (String) -> Bool) throws -> Data? {
        guard let entry = try centralEntries(in: data).first(where: { predicate($0.name) }) else {
            return nil
        }
        return try read(entry, from: data)
    }

    // MARK: - Central directory

    private struct Entry {
        let name: String
        let method: UInt16
        let flags: UInt16
        let compressedSize: Int
        let uncompressedSize: Int
        let localHeaderOffset: Int
    }

    private static func centralEntries(in data: Data) throws -> [Entry] {
        let bytes = [UInt8](data)
        guard bytes.count >= 22 else { throw ZipError.notAZipArchive }

        // The end-of-central-directory record sits last, but a trailing comment of up to 64 KB
        // may follow it, so it has to be searched for backwards.
        var eocd = -1
        let lowest = max(0, bytes.count - 22 - 0xFFFF)
        var i = bytes.count - 22
        while i >= lowest {
            if le32(bytes, i) == eocdSignature { eocd = i; break }
            i -= 1
        }
        guard eocd >= 0 else { throw ZipError.notAZipArchive }

        let count = Int(le16(bytes, eocd + 10))
        let directorySize = Int(le32(bytes, eocd + 12))
        let directoryOffset = Int(le32(bytes, eocd + 16))
        // 0xFFFF / 0xFFFFFFFF in these fields is ZIP64's escape value: the real numbers live
        // in a record this reader does not parse, so it says so instead of reading garbage.
        guard count != 0xFFFF, directorySize != 0xFFFF_FFFF, directoryOffset != 0xFFFF_FFFF else {
            throw ZipError.unsupportedZip64
        }
        guard directoryOffset >= 0, directoryOffset + directorySize <= bytes.count else {
            throw ZipError.corrupted
        }

        var entries: [Entry] = []
        var p = directoryOffset
        for _ in 0..<count {
            guard p + 46 <= bytes.count, le32(bytes, p) == centralSignature else {
                throw ZipError.corrupted
            }
            let flags = le16(bytes, p + 8)
            let method = le16(bytes, p + 10)
            let compressed = Int(le32(bytes, p + 20))
            let uncompressed = Int(le32(bytes, p + 24))
            let nameLength = Int(le16(bytes, p + 28))
            let extraLength = Int(le16(bytes, p + 30))
            let commentLength = Int(le16(bytes, p + 32))
            let localOffset = Int(le32(bytes, p + 42))

            guard p + 46 + nameLength <= bytes.count else { throw ZipError.corrupted }
            // Bit 0 of the general-purpose flags marks an encrypted entry.
            guard flags & 0x0001 == 0 else { throw ZipError.encryptedEntry }
            guard compressed != 0xFFFF_FFFF, uncompressed != 0xFFFF_FFFF,
                  localOffset != 0xFFFF_FFFF else { throw ZipError.unsupportedZip64 }

            // Bit 11 says the name is UTF-8; otherwise it is CP437. ASCII names — which is
            // everything this reader is asked for — decode the same either way, so a name
            // that is not valid UTF-8 is simply skipped rather than mangled.
            let nameBytes = Array(bytes[(p + 46)..<(p + 46 + nameLength)])
            if let name = String(bytes: nameBytes, encoding: .utf8) {
                entries.append(Entry(name: name, method: method, flags: flags,
                                     compressedSize: compressed, uncompressedSize: uncompressed,
                                     localHeaderOffset: localOffset))
            }
            p += 46 + nameLength + extraLength + commentLength
        }
        return entries
    }

    // MARK: - Entry data

    private static func read(_ entry: Entry, from data: Data) throws -> Data {
        let bytes = [UInt8](data)
        let header = entry.localHeaderOffset
        guard header >= 0, header + 30 <= bytes.count, le32(bytes, header) == localSignature else {
            throw ZipError.corrupted
        }
        // The local header repeats the name and extra-field lengths, and they are allowed to
        // differ from the central directory's, so the data offset must come from here.
        let nameLength = Int(le16(bytes, header + 26))
        let extraLength = Int(le16(bytes, header + 28))
        let start = header + 30 + nameLength + extraLength
        guard start >= 0, start + entry.compressedSize <= bytes.count else { throw ZipError.corrupted }
        guard entry.uncompressedSize <= maxEntrySize else { throw ZipError.entryTooLarge }

        let payload = Data(bytes[start..<(start + entry.compressedSize)])
        switch entry.method {
        case 0:
            return payload
        case 8:
            return try inflate(payload, expecting: entry.uncompressedSize)
        default:
            throw ZipError.unsupportedCompression(entry.method)
        }
    }

    /// Raw DEFLATE, the same primitive `KDBXReader.gunzip` uses. ZIP stores the uncompressed
    /// size up front, so the output buffer is sized exactly and a short result is an error
    /// rather than something to paper over.
    private static func inflate(_ payload: Data, expecting size: Int) throws -> Data {
        if size == 0 { return Data() }
        var destination = Data(count: size)
        let produced: Int = destination.withUnsafeMutableBytes { dst in
            payload.withUnsafeBytes { src in
                compression_decode_buffer(
                    dst.bindMemory(to: UInt8.self).baseAddress!, size,
                    src.bindMemory(to: UInt8.self).baseAddress!, payload.count,
                    nil, COMPRESSION_ZLIB)
            }
        }
        guard produced == size else { throw ZipError.corrupted }
        return destination
    }

    // MARK: - Little-endian reads

    private static func le16(_ b: [UInt8], _ i: Int) -> UInt16 {
        guard i >= 0, i + 2 <= b.count else { return 0 }
        return UInt16(b[i]) | (UInt16(b[i + 1]) << 8)
    }

    private static func le32(_ b: [UInt8], _ i: Int) -> UInt32 {
        guard i >= 0, i + 4 <= b.count else { return 0 }
        return UInt32(b[i]) | (UInt32(b[i + 1]) << 8) | (UInt32(b[i + 2]) << 16) | (UInt32(b[i + 3]) << 24)
    }
}
