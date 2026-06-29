import Foundation
import CryptoKit
import Compression

// MARK: - KDBX container reader
//
// Reads a KDBX 3.1 or KDBX 4 database and returns the decrypted, decompressed XML payload
// plus the inner random-stream parameters used to resolve Protected values. The full KDBX 4
// chain (composite key → KDF → master/HMAC keys → header & block HMAC → outer decrypt →
// gunzip → inner header) is validated end-to-end against a real KeePassXC file in
// VaultGuardTests/KDBXReaderTests.swift; the KDBX 3.1 path (uint16 header sizes, AES-KDF
// fields in the header, StreamStartBytes wrong-password check, SHA-256 hashed-block payload,
// no inner header) is covered by VaultGuardTests/KDBXv3Tests.swift.

enum KDBXError: LocalizedError {
    case notKDBX
    case unsupportedVersion(major: Int, minor: Int)
    case truncated
    case headerCorrupted
    case wrongCredentials          // header HMAC mismatch: bad password / key file
    case badBlockHMAC
    case unsupportedCipher(String)
    case unsupportedKDF(String)
    case missingHeaderField(UInt8)
    case decompressFailed
    case badInnerStream
    case randomGenerationFailed

    var errorDescription: String? {
        switch self {
        case .notKDBX: return "Not a KDBX file"
        case .unsupportedVersion(let a, let b): return "Unsupported KDBX version \(a).\(b)"
        case .truncated: return "File is truncated or malformed"
        case .headerCorrupted: return "KDBX header is corrupted"
        case .wrongCredentials: return "Wrong password or key file"
        case .badBlockHMAC: return "Data integrity check failed (block HMAC)"
        case .unsupportedCipher(let u): return "Unsupported cipher (\(u))"
        case .unsupportedKDF(let u): return "Unsupported KDF (\(u))"
        case .missingHeaderField(let id): return "Missing KDBX header field \(id)"
        case .decompressFailed: return "Failed to decompress the database"
        case .badInnerStream: return "Unsupported inner random stream"
        case .randomGenerationFailed: return "Secure random generation failed"
        }
    }
}

struct KDBXDatabase {
    let xml: Data
    let innerStreamID: UInt32   // 2 = Salsa20, 3 = ChaCha20
    let innerStreamKey: Data
    let binaries: [Data]        // inner-header binaries (attachments), in order
    let profile: KDBXProfile    // on-disk format profile, for lossless write-back
}

/// On-disk format profile of a KDBX file: container version, outer cipher, compression and
/// KDF type+cost. Captured on read so the writer reproduces it instead of normalizing every
/// save to one fixed profile. Salt/seed/IV are NOT part of this (always regenerated on write).
struct KDBXProfile {
    enum Cipher { case aesCBC, chacha20 }
    enum KDF {
        case aesKdf(rounds: UInt64)
        case argon2d(memoryKiB: UInt64, iterations: UInt64, parallelism: UInt32)
        case argon2id(memoryKiB: UInt64, iterations: UInt64, parallelism: UInt32)
    }
    var versionMajor: UInt16
    var versionMinor: UInt16
    var cipher: Cipher
    var compression: UInt32     // 0 none, 1 gzip (preserved by the writer)
    var kdf: KDF

    static let `default` = KDBXProfile(versionMajor: 4, versionMinor: 1, cipher: .aesCBC,
                                       compression: 0,
                                       kdf: .argon2d(memoryKiB: 16 * 1024, iterations: 4, parallelism: 2))
    static let lightArgon2d = KDBXProfile(versionMajor: 4, versionMinor: 1, cipher: .aesCBC,
                                          compression: 0,
                                          kdf: .argon2d(memoryKiB: 1024, iterations: 2, parallelism: 1))
}

private enum KDBXUUID {
    static let aesCBC      = "31c1f2e6bf714350be5805216afc5aff"
    static let chacha20    = "d6038a2b8b6f4cb5a524339a31dbb59a"
    static let kdfAES      = "c9d9f39a628a4460bf740d08c18a4fea"
    static let kdfArgon2d  = "ef636ddf8c29444b91f7a9a403e30a0c"
    static let kdfArgon2id = "9e298b1956db4773b23dfc3ec6f0a1e6"
}

enum KDBXReader {

    // MARK: Public entry

    /// Decrypt and decompress a KDBX 3.1 or 4 file. Throws `.wrongCredentials` when the
    /// password / key file is wrong.
    static func unlock(data: Data, password: String?, keyfile: Data? = nil) throws -> KDBXDatabase {
        try unlock(data: data, passwordSHA256: hashedPasswordComponent(password), keyfile: keyfile)
    }

    /// Same as `unlock(data:password:keyfile:)` but takes the pre-hashed password component —
    /// SHA-256 of the UTF-8 password — instead of the raw password. Per the KDBX format the
    /// composite key is SHA256(SHA256(password) ‖ keyfileKey), so this component is sufficient
    /// to open the database and cannot be reversed back to the password. Biometric unlock
    /// stores exactly this value (never the raw master password).
    static func unlock(data: Data, passwordSHA256: Data?, keyfile: Data? = nil) throws -> KDBXDatabase {
        let bytes = [UInt8](data)
        var c = Cursor(bytes)

        guard try c.uint(4) == 0x9AA2_D903, try c.uint(4) == 0xB54B_FB67 else { throw KDBXError.notKDBX }
        let minor = Int(try c.uint(2))
        let major = Int(try c.uint(2))
        switch major {
        case 4: return try unlockV4(bytes, passwordSHA256: passwordSHA256, keyfile: keyfile)
        case 3: return try unlockV3(bytes, passwordSHA256: passwordSHA256, keyfile: keyfile)
        default: throw KDBXError.unsupportedVersion(major: major, minor: minor)
        }
    }

    /// SHA-256 of the UTF-8 password — the password's contribution to the KDBX composite key.
    static func hashedPasswordComponent(_ password: String?) -> Data? {
        password.map { Data(SHA256.hash(data: Data($0.utf8))) }
    }

    // MARK: KDBX 4

    private static func unlockV4(_ bytes: [UInt8], passwordSHA256: Data?, keyfile: Data?) throws -> KDBXDatabase {
        var c = Cursor(bytes)
        _ = try c.bytes(12)   // magic + version (already validated)

        // Outer header: [id:u8][size:u32][data]; terminated by id == 0.
        var fields: [UInt8: [UInt8]] = [:]
        while true {
            let id = try c.u8()
            let size = Int(try c.uint(4))
            let fdata = try c.bytes(size)
            fields[id] = fdata
            if id == 0 { break }
        }
        let headerEnd = c.offset
        let headerData = Data(bytes[0..<headerEnd])

        guard let cipherRaw = fields[2] else { throw KDBXError.missingHeaderField(2) }
        guard let compRaw = fields[3] else { throw KDBXError.missingHeaderField(3) }
        guard let masterSeedRaw = fields[4] else { throw KDBXError.missingHeaderField(4) }
        guard let encIVRaw = fields[7] else { throw KDBXError.missingHeaderField(7) }
        guard let kdfRaw = fields[11] else { throw KDBXError.missingHeaderField(11) }

        let cipher = hex(cipherRaw)
        let compression = le32(compRaw)
        let masterSeed = Data(masterSeedRaw)
        let encIV = Data(encIVRaw)

        let cipherKind: KDBXProfile.Cipher
        switch cipher {
        case KDBXUUID.aesCBC:   cipherKind = .aesCBC
        case KDBXUUID.chacha20: cipherKind = .chacha20
        default: throw KDBXError.unsupportedCipher(cipher)
        }
        let minorV = UInt16(bytes[8]) | (UInt16(bytes[9]) << 8)
        let majorV = UInt16(bytes[10]) | (UInt16(bytes[11]) << 8)
        let profile = KDBXProfile(versionMajor: majorV, versionMinor: minorV, cipher: cipherKind,
                                  compression: compression, kdf: try kdfSpec(from: kdfRaw))

        // Key schedule.
        let composite = compositeKey(passwordSHA256: passwordSHA256, keyfile: keyfile)
        let transformed = try transformKey(composite: composite, kdfParams: kdfRaw)
        let masterKey = Data(SHA256.hash(data: masterSeed + transformed))
        let hmacBase = Data(SHA512.hash(data: masterSeed + transformed + Data([0x01])))

        // Header integrity: [SHA256(header)][HMAC-SHA256(header)].
        let storedSHA = Data(try c.bytes(32))
        let storedHMAC = Data(try c.bytes(32))
        guard Data(SHA256.hash(data: headerData)) == storedSHA else { throw KDBXError.headerCorrupted }
        let headerKey = blockKey(0xFFFF_FFFF_FFFF_FFFF, base: hmacBase)
        guard ctEqual(hmac256(key: headerKey, msg: headerData), storedHMAC) else {
            throw KDBXError.wrongCredentials
        }

        // HMAC'd blocks → concatenated ciphertext.
        var ciphertext = Data()
        var idx: UInt64 = 0
        while true {
            let blockHMAC = Data(try c.bytes(32))
            let blockSize = Int(try c.uint(4))
            let blockData = Data(try c.bytes(blockSize))
            var msg = le64Data(idx)
            msg.append(le32Data(UInt32(blockSize)))
            msg.append(blockData)
            guard ctEqual(hmac256(key: blockKey(idx, base: hmacBase), msg: msg), blockHMAC) else {
                throw KDBXError.badBlockHMAC
            }
            if blockSize == 0 { break }
            ciphertext.append(blockData)
            idx &+= 1
        }

        // Outer decrypt.
        let plain: Data
        switch cipher {
        case KDBXUUID.aesCBC:
            plain = try KeePassKDF.aesCbcDecrypt(ciphertext, key: masterKey, iv: encIV)
        case KDBXUUID.chacha20:
            guard var cc = ChaCha20Cipher(key: masterKey, nonce: encIV, counter: 0) else {
                throw KDBXError.unsupportedCipher(cipher)
            }
            plain = cc.process(ciphertext)
        default:
            throw KDBXError.unsupportedCipher(cipher)
        }

        // Decompress if gzip.
        let payload = (compression == 1) ? try gunzip(plain) : plain

        // Inner header (TLV u32) then XML.
        let payloadBytes = [UInt8](payload)
        var ic = Cursor(payloadBytes)
        var innerStreamID: UInt32 = 0
        var innerStreamKey = Data()
        var binaries: [Data] = []
        while true {
            let id = try ic.u8()
            let size = Int(try ic.uint(4))
            let d = try ic.bytes(size)
            switch id {
            case 0: // end
                let xml = Data(payloadBytes[ic.offset...])
                guard innerStreamID == 2 || innerStreamID == 3 else { throw KDBXError.badInnerStream }
                return KDBXDatabase(xml: xml, innerStreamID: innerStreamID,
                                    innerStreamKey: innerStreamKey, binaries: binaries, profile: profile)
            case 1: innerStreamID = le32(d)
            case 2: innerStreamKey = Data(d)
            case 3: binaries.append(Data(d))  // full inner-binary item: [flags:1][data:N], kept verbatim for lossless write-back
            default: break
            }
        }
    }

    // MARK: KDBX 3.1
    //
    // Differences from v4: uint16 header field sizes; AES-KDF parameters live in the header
    // (TransformSeed/TransformRounds); no header HMAC; the payload starts with
    // StreamStartBytes (verified against the header — this is the wrong-password check) then a
    // SHA-256 hashed-block stream; no inner header (XML follows directly); the inner stream is
    // always Salsa20 with the ProtectedStreamKey header field.

    private static func unlockV3(_ bytes: [UInt8], passwordSHA256: Data?, keyfile: Data?) throws -> KDBXDatabase {
        var c = Cursor(bytes)
        _ = try c.bytes(12)

        // Header: [id:u8][size:u16][data]; terminated by id == 0.
        var fields: [UInt8: [UInt8]] = [:]
        while true {
            let id = try c.u8()
            let size = Int(try c.uint(2))
            let fdata = try c.bytes(size)
            fields[id] = fdata
            if id == 0 { break }
        }
        let headerEnd = c.offset

        guard let cipherRaw = fields[2], let compRaw = fields[3], let masterSeedRaw = fields[4],
              let transformSeedRaw = fields[5], let roundsRaw = fields[6], let encIVRaw = fields[7],
              let protKeyRaw = fields[8], let startBytesRaw = fields[9], let innerIDRaw = fields[10]
        else { throw KDBXError.headerCorrupted }

        let cipher = hex(cipherRaw)
        guard cipher == KDBXUUID.aesCBC else { throw KDBXError.unsupportedCipher(cipher) }

        let composite = compositeKey(passwordSHA256: passwordSHA256, keyfile: keyfile)
        let transformed = try KeePassKDF.aesKdfTransform(
            compositeKey: composite, seed: Data(transformSeedRaw), rounds: le64(roundsRaw))
        let masterKey = Data(SHA256.hash(data: Data(masterSeedRaw) + transformed))

        // Outer decrypt (no PKCS#7 strip: the hashed-block terminator ends the data; the rest
        // is padding we ignore).
        let ciphertext = Data(bytes[headerEnd...])
        let plain = try KeePassKDF.aesCbcDecrypt(ciphertext, key: masterKey, iv: Data(encIVRaw), padding: false)

        // StreamStartBytes verification = wrong-password check.
        guard plain.count >= 32, Data(plain.prefix(32)) == Data(startBytesRaw) else {
            throw KDBXError.wrongCredentials
        }
        let payload = try readHashedBlocks(Array(plain.dropFirst(32)))

        let xml = (le32(compRaw) == 1) ? try gunzip(payload) : payload
        let innerID = le32(innerIDRaw)
        guard innerID == 2 || innerID == 3 else { throw KDBXError.badInnerStream }
        let minorV3 = UInt16(bytes[8]) | (UInt16(bytes[9]) << 8)
        let profileV3 = KDBXProfile(versionMajor: 3, versionMinor: minorV3, cipher: .aesCBC,
                                    compression: le32(compRaw), kdf: .aesKdf(rounds: le64(roundsRaw)))
        return KDBXDatabase(xml: xml, innerStreamID: innerID,
                            innerStreamKey: Data(protKeyRaw), binaries: [], profile: profileV3)
    }

    /// KDBX 3.1 hashed-block stream: repeated [index:u32][SHA256:32][size:u32][data];
    /// terminated by a zero-size block. Each block's SHA-256 must match.
    private static func readHashedBlocks(_ b: [UInt8]) throws -> Data {
        var c = Cursor(b)
        var out = Data()
        while true {
            _ = try c.uint(4)                    // block index (unused)
            let hash = Data(try c.bytes(32))
            let size = Int(try c.uint(4))
            if size == 0 { break }
            let data = Data(try c.bytes(size))
            guard Data(SHA256.hash(data: data)) == hash else { throw KDBXError.badBlockHMAC }
            out.append(data)
        }
        return out
    }



    /// KeePass composite key: SHA256 over the concatenation of each credential's 32-byte
    /// hash. Password contributes SHA256(utf8). Key-file contributes `keyfileKey`.
    static func compositeKey(password: String?, keyfile: Data?) -> Data {
        compositeKey(passwordSHA256: hashedPasswordComponent(password), keyfile: keyfile)
    }

    /// Composite key from the pre-hashed password component (see `hashedPasswordComponent`).
    static func compositeKey(passwordSHA256: Data?, keyfile: Data?) -> Data {
        var parts = Data()
        if let passwordSHA256 { parts.append(passwordSHA256) }
        if let keyfile { parts.append(keyfileKey(keyfile)) }
        return Data(SHA256.hash(data: parts))
    }

    /// Resolve a key-file to its 32-byte key. Order per KeePass: 32 raw bytes → used as-is;
    /// 64 hex chars → decoded; XML key-file `<Data>` (v1 base64, or v2 hex with a verified
    /// 4-byte hash) → decoded; otherwise SHA256(file).
    static func keyfileKey(_ data: Data) -> Data {
        if data.count == 32 { return data }
        if data.count == 64, let h = hexDecode(data) { return h }
        if let k = xmlKeyfileData(data) { return k }
        return Data(SHA256.hash(data: data))
    }

    private static func xmlKeyfileData(_ data: Data) -> Data? {
        guard let s = String(data: data, encoding: .utf8), s.contains("<KeyFile"),
              let open = s.range(of: "<Data[^>]*>", options: .regularExpression),
              let close = s.range(of: "</Data>", range: open.upperBound..<s.endIndex) else { return nil }
        let tag = String(s[open])                                   // e.g. <Data Hash="A1B2C3D4">
        let inner = String(s[open.upperBound..<close.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)

        // Key-file v2: <Data Hash="..."> with hex content; verify the 4-byte integrity hash.
        if let hr = tag.range(of: "Hash=\"[0-9A-Fa-f]+\"", options: .regularExpression) {
            let expected = tag[hr].dropFirst(6).dropLast().lowercased()    // hex inside the quotes
            let hexBody = inner.filter { !$0.isWhitespace }
            guard let key = hexDecode(Data(hexBody.utf8)) else { return nil }
            let digest = hex(Array(Data(SHA256.hash(data: key)).prefix(4)))
            guard digest == expected else { return nil }                   // corrupted key file
            return key
        }
        // Key-file v1: base64.
        return Data(base64Encoded: inner)
    }

    // MARK: KDF dispatch

    /// Extract the KDF type + cost (no salt) for the profile. Mirrors `transformKey` parsing.
    private static func kdfSpec(from kdfParams: [UInt8]) throws -> KDBXProfile.KDF {
        let vd = try parseVariantDictionary(kdfParams)
        guard let uuid = vd["$UUID"] else { throw KDBXError.unsupportedKDF("missing $UUID") }
        switch hex(uuid) {
        case KDBXUUID.kdfAES:
            guard let r = vd["R"] else { throw KDBXError.unsupportedKDF("AES params") }
            return .aesKdf(rounds: le64(r))
        case KDBXUUID.kdfArgon2d:
            guard let i = vd["I"], let m = vd["M"], let p = vd["P"] else { throw KDBXError.unsupportedKDF("Argon2 params") }
            return .argon2d(memoryKiB: le64(m) / 1024, iterations: le64(i), parallelism: le32(p))
        case KDBXUUID.kdfArgon2id:
            guard let i = vd["I"], let m = vd["M"], let p = vd["P"] else { throw KDBXError.unsupportedKDF("Argon2 params") }
            return .argon2id(memoryKiB: le64(m) / 1024, iterations: le64(i), parallelism: le32(p))
        default:
            throw KDBXError.unsupportedKDF(hex(uuid))
        }
    }

    private static func transformKey(composite: Data, kdfParams: [UInt8]) throws -> Data {
        let vd = try parseVariantDictionary(kdfParams)
        guard let uuid = vd["$UUID"] else { throw KDBXError.unsupportedKDF("missing $UUID") }
        let kdf = hex(uuid)
        switch kdf {
        case KDBXUUID.kdfAES:
            guard let s = vd["S"], let r = vd["R"] else { throw KDBXError.unsupportedKDF("AES params") }
            return try KeePassKDF.aesKdfTransform(compositeKey: composite, seed: Data(s), rounds: le64(r))
        case KDBXUUID.kdfArgon2d, KDBXUUID.kdfArgon2id:
            guard let s = vd["S"], let i = vd["I"], let m = vd["M"],
                  let p = vd["P"], let v = vd["V"] else { throw KDBXError.unsupportedKDF("Argon2 params") }
            let variant: KeePassKDF.Argon2Variant = (kdf == KDBXUUID.kdfArgon2d) ? .d : .id
            return try KeePassKDF.argon2(
                compositeKey: composite, salt: Data(s), variant: variant,
                iterations: le64(i), memoryBytes: le64(m), parallelism: le32(p), version: le32(v))
        default:
            throw KDBXError.unsupportedKDF(kdf)
        }
    }

    // MARK: VariantDictionary

    private static func parseVariantDictionary(_ raw: [UInt8]) throws -> [String: [UInt8]] {
        var c = Cursor(raw)
        let version = try c.uint(2)
        // The high byte is the critical (major) version; KeePass refuses anything above 1.
        guard (version >> 8) <= 0x01 else { throw KDBXError.unsupportedKDF("VariantDictionary version") }
        var d: [String: [UInt8]] = [:]
        while true {
            let t = try c.u8()
            if t == 0 { break }
            let kl = Int(try c.uint(4)); let kb = try c.bytes(kl)
            let vl = Int(try c.uint(4)); let vb = try c.bytes(vl)
            d[String(decoding: kb, as: UTF8.self)] = vb
        }
        return d
    }

    // MARK: Key derivation helpers

    private static func blockKey(_ idx: UInt64, base: Data) -> Data {
        Data(SHA512.hash(data: le64Data(idx) + base))
    }
    private static func hmac256(key: Data, msg: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: key)))
    }
    private static func ctEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[a.index(a.startIndex, offsetBy: i)] ^ b[b.index(b.startIndex, offsetBy: i)] }
        return diff == 0
    }

    // MARK: gzip

    private static func gunzip(_ data: Data) throws -> Data {
        let b = [UInt8](data)
        guard b.count > 18, b[0] == 0x1f, b[1] == 0x8b, b[2] == 0x08 else { throw KDBXError.decompressFailed }
        let flg = b[3]
        var idx = 10
        if flg & 0x04 != 0 {                       // FEXTRA
            guard idx + 2 <= b.count else { throw KDBXError.decompressFailed }
            let xlen = Int(b[idx]) | (Int(b[idx + 1]) << 8); idx += 2 + xlen
        }
        if flg & 0x08 != 0 { while idx < b.count, b[idx] != 0 { idx += 1 }; idx += 1 }   // FNAME
        if flg & 0x10 != 0 { while idx < b.count, b[idx] != 0 { idx += 1 }; idx += 1 }   // FCOMMENT
        if flg & 0x02 != 0 { idx += 2 }                                                  // FHCRC
        guard idx <= b.count - 8 else { throw KDBXError.decompressFailed }
        let deflate = Data(b[idx..<(b.count - 8)])
        let isize = Int(b[b.count - 4]) | (Int(b[b.count - 3]) << 8)
            | (Int(b[b.count - 2]) << 16) | (Int(b[b.count - 1]) << 24)
        let dstCap = isize > 0 ? isize : max(deflate.count * 8, 1 << 16)
        let srcLen = deflate.count
        var dst = Data(count: dstCap)
        let n = dst.withUnsafeMutableBytes { (dstRaw: UnsafeMutableRawBufferPointer) -> Int in
            deflate.withUnsafeBytes { (srcRaw: UnsafeRawBufferPointer) -> Int in
                compression_decode_buffer(
                    dstRaw.bindMemory(to: UInt8.self).baseAddress!, dstCap,
                    srcRaw.bindMemory(to: UInt8.self).baseAddress!, srcLen,
                    nil, COMPRESSION_ZLIB)
            }
        }
        guard n > 0 else { throw KDBXError.decompressFailed }
        let result = Data(dst.prefix(n))
        // Integrity: gzip footer = CRC32 (4) + ISIZE (4), both little-endian.
        let crcStored = UInt32(b[b.count - 8]) | (UInt32(b[b.count - 7]) << 8)
            | (UInt32(b[b.count - 6]) << 16) | (UInt32(b[b.count - 5]) << 24)
        guard result.count == (isize & 0xFFFF_FFFF), crc32(result) == crcStored else {
            throw KDBXError.decompressFailed
        }
        return result
    }

    /// CRC-32/ISO-HDLC (gzip CRC): reflected, poly 0xEDB88320, init/xorout 0xFFFFFFFF.
    private static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 { crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB8_8320 : (crc >> 1) }
        }
        return crc ^ 0xFFFF_FFFF
    }

    // MARK: byte / int helpers

    private static func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
    private static func le32(_ b: [UInt8]) -> UInt32 {
        var v: UInt32 = 0; for i in 0..<min(4, b.count) { v |= UInt32(b[i]) << (8 * i) }; return v
    }
    private static func le64(_ b: [UInt8]) -> UInt64 {
        var v: UInt64 = 0; for i in 0..<min(8, b.count) { v |= UInt64(b[i]) << (8 * i) }; return v
    }
    private static func le32Data(_ v: UInt32) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }
    private static func le64Data(_ v: UInt64) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }

    private static func hexDecode(_ d: Data) -> Data? {
        guard let s = String(data: d, encoding: .utf8), s.count % 2 == 0 else { return nil }
        var out = Data(); var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            guard let byte = UInt8(s[i..<j], radix: 16) else { return nil }
            out.append(byte); i = j
        }
        return out
    }

    // MARK: Cursor

    private struct Cursor {
        let b: [UInt8]
        var i = 0
        init(_ b: [UInt8]) { self.b = b }
        var offset: Int { i }
        mutating func u8() throws -> UInt8 {
            guard i < b.count else { throw KDBXError.truncated }
            defer { i += 1 }; return b[i]
        }
        mutating func uint(_ n: Int) throws -> UInt64 {
            guard i + n <= b.count else { throw KDBXError.truncated }
            var v: UInt64 = 0; for k in 0..<n { v |= UInt64(b[i + k]) << (8 * k) }
            i += n; return v
        }
        mutating func bytes(_ n: Int) throws -> [UInt8] {
            guard n >= 0, i + n <= b.count else { throw KDBXError.truncated }
            let s = Array(b[i..<i + n]); i += n; return s
        }
    }
}

// MARK: - Protected value stream
//
// Resolves `<Value Protected="True">` fields. The inner random stream produces a single
// keystream consumed across all protected values in document order, so call `decrypt(_:)`
// for each protected base64 value in the order they appear in the XML.

final class KDBXProtectedStream {
    private enum Stream { case salsa(Salsa20Cipher); case chacha(ChaCha20Cipher) }
    private var stream: Stream

    /// - streamID: 2 = Salsa20 (key = SHA256(innerKey), fixed IV); 3 = ChaCha20
    ///   (key/nonce = SHA512(innerKey)[0..32] / [32..44]).
    init?(streamID: UInt32, key: Data) {
        switch streamID {
        case 2:
            let k = Data(SHA256.hash(data: key))
            let iv = Data([0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a])
            guard let c = Salsa20Cipher(key: k, nonce: iv) else { return nil }
            stream = .salsa(c)
        case 3:
            let h = Data(SHA512.hash(data: key))
            guard let c = ChaCha20Cipher(key: Data(h.prefix(32)), nonce: Data(h.subdata(in: 32..<44))) else { return nil }
            stream = .chacha(c)
        default:
            return nil
        }
    }

    /// Decrypt one protected value (base64). Advances the shared keystream by its length.
    func decrypt(_ base64Value: String) -> String? {
        guard let data = Data(base64Encoded: base64Value) else { return nil }
        let out: Data
        switch stream {
        case .salsa(var c): out = c.process(data); stream = .salsa(c)
        case .chacha(var c): out = c.process(data); stream = .chacha(c)
        }
        return String(data: out, encoding: .utf8)
    }

    /// Encrypt one protected value (plaintext → base64). XOR is symmetric, so the same stream
    /// type encrypts; advances the shared keystream by the plaintext length. Used by the writer.
    func encrypt(_ plaintext: String) -> String {
        let data = Data(plaintext.utf8)
        let out: Data
        switch stream {
        case .salsa(var c): out = c.process(data); stream = .salsa(c)
        case .chacha(var c): out = c.process(data); stream = .chacha(c)
        }
        return out.base64EncodedString()
    }
}
