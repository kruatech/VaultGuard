import Foundation
import CryptoKit
import Security
import Compression

// MARK: - KDBX 4 writer
//
// Inverse of `KDBXReader` for the write path. Produces a valid KDBX 4 file:
// AES-256-CBC or ChaCha20 outer, AES-KDF/Argon2d/Argon2id, ChaCha20 inner stream. The on-disk
// profile (cipher / KDF / version / compression) is preserved from the source file; gzip is
// applied on write when the original used it. Validated by round-trip (`KDBXReader.unlock`
// reads it back) and a Python mirror that real KeePass tooling reads.
//
// The XML is edited as an `XMLDocument` so escaping/serialization are correct. Protected
// values are re-encrypted with a fresh inner-stream key, in document order (XPath returns
// nodes in document order, matching the reader's SAX order).

enum KDBXEditor {
    /// Decrypt all Protected values inline, returning an editable `XMLDocument` whose
    /// Protected values hold plaintext. Order matches the reader (document order).
    static func makeEditable(xml: Data, stream: KDBXProtectedStream) throws -> XMLDocument {
        let doc = try XMLDocument(data: xml, options: [.nodePreserveWhitespace])
        for node in try doc.nodes(forXPath: "//Value[@Protected='True']") {
            guard let el = node as? XMLElement else { continue }
            el.stringValue = stream.decrypt(el.stringValue ?? "") ?? ""
        }
        return doc
    }

    /// Features present in the document that the current writer would NOT preserve on save.
    /// Used as a destructive-save guard. Binary attachments are now passed through losslessly
    /// (`KDBXWriter` re-emits inner-header binaries), so there are no known lossy features at
    /// the moment. The hook is kept so any future unsupported case can be surfaced here.
    /// Returns human-readable tags; empty means the save is lossless.
    static func lossyFeatures(in doc: XMLDocument) -> [String] {
        []
    }
}

enum KDBXWriter {

    private static let aesCBCUUID   = Data([0x31,0xc1,0xf2,0xe6,0xbf,0x71,0x43,0x50,0xbe,0x58,0x05,0x21,0x6a,0xfc,0x5a,0xff])
    private static let chacha20UUID = Data([0xd6,0x03,0x8a,0x2b,0x8b,0x6f,0x4c,0xb5,0xa5,0x24,0x33,0x9a,0x31,0xdb,0xb5,0x9a])
    private static let argon2dUUID  = Data([0xef,0x63,0x6d,0xdf,0x8c,0x29,0x44,0x4b,0x91,0xf7,0xa9,0xa4,0x03,0xe3,0x0a,0x0c])
    private static let argon2idUUID = Data([0x9e,0x29,0x8b,0x19,0x56,0xdb,0x47,0x73,0xb2,0x3d,0xfc,0x3e,0xc6,0xf0,0xa1,0xe6])
    private static let aesKdfUUID   = Data([0xc9,0xd9,0xf3,0x9a,0x62,0x8a,0x44,0x60,0xbf,0x74,0x0d,0x08,0xc1,0x8a,0x4f,0xea])

    /// Build a KDBX file from a plaintext `XMLDocument` (Protected values hold plaintext).
    /// `binaries` are inner-header binary items (attachments), full `[flags:1][data:N]` payloads,
    /// re-emitted in index order so `<Binary Ref="N"/>` stay valid (lossless passthrough).
    /// `profile` reproduces the original file's version / outer cipher / KDF / compression
    /// (gzip is re-applied on write when the source file used it). KDBX 3 is upgraded to 4.1
    /// (no v3 writer), preserving its AES-KDF + cipher.
    static func build(plaintextXML: XMLDocument, password: String?, keyfile: Data? = nil,
                      profile: KDBXProfile = .default, binaries: [Data] = []) throws -> Data {
        try build(plaintextXML: plaintextXML,
                  passwordSHA256: KDBXReader.hashedPasswordComponent(password),
                  keyfile: keyfile, profile: profile, binaries: binaries)
    }

    /// Same as `build(plaintextXML:password:…)` but takes the pre-hashed password component
    /// (SHA-256 of the UTF-8 password) — the form biometric unlock stores, sufficient to
    /// derive the composite key without ever holding the raw master password.
    static func build(plaintextXML: XMLDocument, passwordSHA256: Data?, keyfile: Data? = nil,
                      profile: KDBXProfile = .default, binaries: [Data] = []) throws -> Data {
        // 1. Fresh inner stream (ChaCha20) and re-encrypt protected values in document order.
        let innerKey = try randomBytes(64)
        guard let stream = KDBXProtectedStream(streamID: 3, key: innerKey) else {
            throw KDBXError.badInnerStream
        }
        // Work on a copy so the caller's editable document keeps plaintext Protected values.
        let work = (plaintextXML.copy() as? XMLDocument) ?? plaintextXML
        for node in try work.nodes(forXPath: "//Value[@Protected='True']") {
            guard let el = node as? XMLElement else { continue }
            el.stringValue = stream.encrypt(el.stringValue ?? "")
        }
        let xmlData = work.xmlData

        // 2. Inner header (TLV u32) + XML, gzip-compressed when the profile says so.
        var inner = Data()
        inner.append(innerTLV(1, le32Data(3)))            // InnerRandomStreamID = ChaCha20
        inner.append(innerTLV(2, innerKey))               // InnerRandomStreamKey
        for item in binaries { inner.append(innerTLV(3, item)) }  // attachments, index order
        inner.append(innerTLV(0, Data()))                 // end
        let rawPayload = inner + xmlData
        let payload = (profile.compression == 1) ? try Self.gzip(rawPayload) : rawPayload

        // 3. Key schedule with the profile's KDF (fresh salt/seed each save).
        let masterSeed = try randomBytes(32)
        let composite = KDBXReader.compositeKey(passwordSHA256: passwordSHA256, keyfile: keyfile)
        let transformed: Data
        let kdfVD: Data
        switch profile.kdf {
        case .aesKdf(let rounds):
            let seed = try randomBytes(32)
            transformed = try KeePassKDF.aesKdfTransform(compositeKey: composite, seed: seed, rounds: rounds)
            kdfVD = aesKdfVariantDictionary(seed: seed, rounds: rounds)
        case .argon2d(let m, let i, let p):
            let salt = try randomBytes(32)
            transformed = try KeePassKDF.argon2(compositeKey: composite, salt: salt, variant: .d,
                                                iterations: i, memoryBytes: m * 1024, parallelism: p, version: 19)
            kdfVD = argon2VariantDictionary(uuid: argon2dUUID, salt: salt, memoryKiB: m, iterations: i, parallelism: p)
        case .argon2id(let m, let i, let p):
            let salt = try randomBytes(32)
            transformed = try KeePassKDF.argon2(compositeKey: composite, salt: salt, variant: .id,
                                                iterations: i, memoryBytes: m * 1024, parallelism: p, version: 19)
            kdfVD = argon2VariantDictionary(uuid: argon2idUUID, salt: salt, memoryKiB: m, iterations: i, parallelism: p)
        }
        let masterKey = Data(SHA256.hash(data: masterSeed + transformed))
        let hmacBase = Data(SHA512.hash(data: masterSeed + transformed + Data([0x01])))

        // 4. Outer cipher + version (KDBX 3 upgraded to 4.1).
        let cipherUUID = (profile.cipher == .aesCBC) ? aesCBCUUID : chacha20UUID
        let encIV = try randomBytes(profile.cipher == .aesCBC ? 16 : 12)
        let major = max(profile.versionMajor, 4)
        let minor = profile.versionMajor >= 4 ? profile.versionMinor : 1

        var header = Data()
        header.append(le32Data(0x9AA2_D903))
        header.append(le32Data(0xB54B_FB67))
        header.append(le16Data(minor))
        header.append(le16Data(major))
        header.append(headerTLV(2, cipherUUID))
        header.append(headerTLV(3, le32Data(profile.compression)))  // 0 none / 1 gzip (preserved)
        header.append(headerTLV(4, masterSeed))
        header.append(headerTLV(7, encIV))
        header.append(headerTLV(11, kdfVD))
        header.append(headerTLV(0, Data([0x0d,0x0a,0x0d,0x0a])))

        let headerSHA = Data(SHA256.hash(data: header))
        let headerHMAC = hmac256(key: blockKey(0xFFFF_FFFF_FFFF_FFFF, base: hmacBase), msg: header)

        // 5. Encrypt the payload with the chosen cipher.
        let ciphertext: Data
        switch profile.cipher {
        case .aesCBC:
            ciphertext = try KeePassKDF.aesCbcEncrypt(payload, key: masterKey, iv: encIV)
        case .chacha20:
            guard var cc = ChaCha20Cipher(key: masterKey, nonce: encIV, counter: 0) else {
                throw KDBXError.unsupportedCipher("chacha20")
            }
            ciphertext = cc.process(payload)
        }

        // 6. HMAC blocks: one data block + zero-size terminator.
        var out = header + headerSHA + headerHMAC
        out.append(hmacBlock(index: 0, data: ciphertext, base: hmacBase))
        out.append(hmacBlock(index: 1, data: Data(), base: hmacBase))
        return out
    }

    // MARK: encoders

    private static func argon2VariantDictionary(uuid: Data, salt: Data, memoryKiB: UInt64,
                                                iterations: UInt64, parallelism: UInt32) -> Data {
        var d = le16Data(0x0100)
        func entry(_ type: UInt8, _ key: String, _ value: Data) {
            let kb = Data(key.utf8)
            d.append(type)
            d.append(le32Data(UInt32(kb.count))); d.append(kb)
            d.append(le32Data(UInt32(value.count))); d.append(value)
        }
        entry(0x42, "$UUID", uuid)
        entry(0x42, "S", salt)
        entry(0x05, "I", le64Data(iterations))
        entry(0x05, "M", le64Data(memoryKiB * 1024))
        entry(0x04, "P", le32Data(parallelism))
        entry(0x04, "V", le32Data(19))
        d.append(0x00)
        return d
    }

    private static func aesKdfVariantDictionary(seed: Data, rounds: UInt64) -> Data {
        var d = le16Data(0x0100)
        func entry(_ type: UInt8, _ key: String, _ value: Data) {
            let kb = Data(key.utf8)
            d.append(type)
            d.append(le32Data(UInt32(kb.count))); d.append(kb)
            d.append(le32Data(UInt32(value.count))); d.append(value)
        }
        entry(0x42, "$UUID", aesKdfUUID)
        entry(0x42, "S", seed)
        entry(0x05, "R", le64Data(rounds))
        d.append(0x00)
        return d
    }

    private static func headerTLV(_ id: UInt8, _ data: Data) -> Data {
        var t = Data([id]); t.append(le32Data(UInt32(data.count))); t.append(data); return t
    }
    private static func innerTLV(_ id: UInt8, _ data: Data) -> Data {
        var t = Data([id]); t.append(le32Data(UInt32(data.count))); t.append(data); return t
    }

    private static func hmacBlock(index: UInt64, data: Data, base: Data) -> Data {
        var msg = le64Data(index); msg.append(le32Data(UInt32(data.count))); msg.append(data)
        var block = hmac256(key: blockKey(index, base: base), msg: msg)
        block.append(le32Data(UInt32(data.count))); block.append(data)
        return block
    }

    private static func blockKey(_ idx: UInt64, base: Data) -> Data {
        Data(SHA512.hash(data: le64Data(idx) + base))
    }
    private static func hmac256(key: Data, msg: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: key)))
    }

    private static func le16Data(_ v: UInt16) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }
    private static func le32Data(_ v: UInt32) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }
    private static func le64Data(_ v: UInt64) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }

    /// Build a minimal, empty KeePass document (`Meta` + one empty `Root` group named after the
    /// database). Combine with `build(plaintextXML:password:…)` to create a brand-new `.kdbx`.
    /// XML escaping of `name` is handled by `XMLElement`.
    static func emptyDatabase(name: String) throws -> XMLDocument {
        let meta = XMLElement(name: "Meta")
        meta.addChild(XMLElement(name: "Generator", stringValue: "VaultGuard"))
        meta.addChild(XMLElement(name: "DatabaseName", stringValue: name))
        meta.addChild(XMLElement(name: "RecycleBinEnabled", stringValue: "True"))
        meta.addChild(XMLElement(name: "RecycleBinUUID", stringValue: Data(count: 16).base64EncodedString()))
        meta.addChild(XMLElement(name: "HistoryMaxItems", stringValue: "10"))

        let group = XMLElement(name: "Group")
        group.addChild(XMLElement(name: "UUID", stringValue: try randomBytes(16).base64EncodedString()))
        group.addChild(XMLElement(name: "Name", stringValue: name))

        let root = XMLElement(name: "Root")
        root.addChild(group)

        let keePassFile = XMLElement(name: "KeePassFile")
        keePassFile.addChild(meta)
        keePassFile.addChild(root)

        let doc = XMLDocument(rootElement: keePassFile)
        doc.version = "1.0"
        doc.characterEncoding = "utf-8"
        return doc
    }

    /// Cryptographically secure random bytes. Fails hard: if the system CSPRNG is
    /// unavailable we refuse to produce key material rather than fall back to a weak source.
    private static func randomBytes(_ n: Int) throws -> Data {
        var d = Data(count: n)
        let ok = d.withUnsafeMutableBytes { ptr -> Int32 in
            SecRandomCopyBytes(kSecRandomDefault, n, ptr.baseAddress!)
        }
        guard ok == errSecSuccess else { throw KDBXError.randomGenerationFailed }
        return d
    }

    // MARK: gzip (RFC 1952)

    /// Wrap data in a GZip stream: 10-byte header (FLG=0) + raw DEFLATE + CRC32 + ISIZE.
    /// The raw DEFLATE body matches what `KDBXReader.gunzip` inflates (Apple COMPRESSION_ZLIB).
    private static func gzip(_ data: Data) throws -> Data {
        let srcLen = data.count
        let cap = max(srcLen + srcLen / 2 + 128, 256)   // deflate can briefly exceed input on tiny/random data
        var deflated = Data(count: cap)
        let n = deflated.withUnsafeMutableBytes { (dst: UnsafeMutableRawBufferPointer) -> Int in
            data.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> Int in
                compression_encode_buffer(
                    dst.bindMemory(to: UInt8.self).baseAddress!, cap,
                    src.bindMemory(to: UInt8.self).baseAddress!, srcLen,
                    nil, COMPRESSION_ZLIB)
            }
        }
        guard n > 0 else { throw KDBXError.decompressFailed }
        var out = Data([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff])
        out.append(deflated.prefix(n))
        out.append(le32Data(crc32(data)))
        out.append(le32Data(UInt32(truncatingIfNeeded: srcLen)))
        return out
    }

    /// CRC-32/ISO-HDLC (the gzip CRC): reflected, poly 0xEDB88320, init/xorout 0xFFFFFFFF.
    private static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB8_8320 : (crc >> 1)
            }
        }
        return crc ^ 0xFFFF_FFFF
    }
}
