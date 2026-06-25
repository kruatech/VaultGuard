import Foundation
import CommonCrypto
import CryptoKit
import Argon2Swift
import Security

// MARK: - Encryption Types

enum EncType: Int {
    case aesCbc256_B64 = 0
    case aesCbc128_HmacSha256_B64 = 1
    case aesCbc256_HmacSha256_B64 = 2
    case rsa2048_OaepSha256_B64 = 3
    case rsa2048_OaepSha1_B64 = 4
    case rsa2048_OaepSha256_HmacSha256_B64 = 5
    case rsa2048_OaepSha1_HmacSha256_B64 = 6
}

struct EncString {
    let type: EncType
    let iv: Data?
    let ct: Data
    let mac: Data?

    init(type: EncType, iv: Data?, ct: Data, mac: Data?) {
        self.type = type; self.iv = iv; self.ct = ct; self.mac = mac
    }

    /// Strict parser. Only the canonical `<type>.<b64>|<b64>|<b64>` form is accepted.
    /// Ambiguous / headerless / wrong-arity inputs are rejected (return nil) instead of
    /// being coerced into a weaker type — this closes EncString downgrade/parsing attacks.
    init?(string: String) {
        guard !string.isEmpty else { return nil }

        let parts = string.split(separator: ".", maxSplits: 1)
        guard parts.count == 2,
              let typeInt = Int(parts[0]),
              let encType = EncType(rawValue: typeInt) else {
            return nil
        }

        let dataParts = String(parts[1]).split(separator: "|").map(String.init)

        switch encType {
        case .aesCbc256_B64:
            // Unauthenticated AES-CBC. Parsed for completeness but rejected at decrypt time.
            guard dataParts.count == 2,
                  let iv = Data(base64Encoded: dataParts[0]),
                  let ct = Data(base64Encoded: dataParts[1]) else { return nil }
            self.init(type: encType, iv: iv, ct: ct, mac: nil)

        case .aesCbc256_HmacSha256_B64, .aesCbc128_HmacSha256_B64:
            guard dataParts.count == 3,
                  let iv = Data(base64Encoded: dataParts[0]),
                  let ct = Data(base64Encoded: dataParts[1]),
                  let mac = Data(base64Encoded: dataParts[2]) else { return nil }
            self.init(type: encType, iv: iv, ct: ct, mac: mac)

        case .rsa2048_OaepSha256_B64, .rsa2048_OaepSha1_B64:
            guard dataParts.count == 1,
                  let ct = Data(base64Encoded: dataParts[0]) else { return nil }
            self.init(type: encType, iv: nil, ct: ct, mac: nil)

        case .rsa2048_OaepSha256_HmacSha256_B64, .rsa2048_OaepSha1_HmacSha256_B64:
            guard dataParts.count == 2,
                  let ct = Data(base64Encoded: dataParts[0]),
                  let mac = Data(base64Encoded: dataParts[1]) else { return nil }
            self.init(type: encType, iv: nil, ct: ct, mac: mac)
        }
    }

    func serialize() -> String {
        var parts: [String] = []
        if let iv = iv { parts.append(iv.base64EncodedString()) }
        parts.append(ct.base64EncodedString())
        if let mac = mac { parts.append(mac.base64EncodedString()) }
        return "\(type.rawValue).\(parts.joined(separator: "|"))"
    }
}

// MARK: - Symmetric Key Pair

/// Holds the encryption + MAC sub-keys. Backed by `SecureBytes` so the key
/// material is zeroed when the key object is released (e.g. on `clearKeys()`).
final class SymmetricCryptoKey {
    private let enc: SecureBytes
    private let mac: SecureBytes

    /// True when a real (non-placeholder) MAC key is present.
    let hasMacKey: Bool

    init(key: Data) {
        if key.count == 64 {
            enc = SecureBytes(data: key.prefix(32))
            mac = SecureBytes(data: key.suffix(32))
            hasMacKey = true
        } else if key.count == 32 {
            enc = SecureBytes(data: CryptoService.hkdfExpand(prk: key, info: Data("enc".utf8), length: 32))
            mac = SecureBytes(data: CryptoService.hkdfExpand(prk: key, info: Data("mac".utf8), length: 32))
            hasMacKey = true
        } else {
            enc = SecureBytes(data: key.prefix(32))
            mac = SecureBytes(count: 32)
            hasMacKey = false
        }
    }

    func withEncKey<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try enc.withUnsafeBytes(body)
    }

    func withMacKey<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try mac.withUnsafeBytes(body)
    }
}

enum KdfType: Int { case pbkdf2 = 0; case argon2id = 1 }

// MARK: - Crypto Service

/// `@unchecked Sendable`: decryption only *reads* key material, and within a sync
/// the key-setup + decrypt run sequentially inside a single background task, so the
/// instance is never mutated concurrently. (Avoid calling `clearKeys()`/`setEncryptionKey`
/// from another thread while a background decrypt is in flight.)
final class CryptoService: @unchecked Sendable {
    // Secure storage for secrets — guaranteed zeroing on clear/dealloc
    private var masterKey: SecureBytes?
    private var masterPasswordHash: SecureString?
    private var encKey: SymmetricCryptoKey?
    /// Raw user (vault) key bytes — the material `encKey` was built from. Retained so it
    /// can be exported once for biometric-unlock storage and restored later without the
    /// master password. Zeroed by `clearKeys()`.
    private var userKey: SecureBytes?
    private var rsaPrivateKey: SecKey?
    private var orgKeys: [String: SymmetricCryptoKey] = [:]

    var hasKeys: Bool { encKey != nil }
    var passwordHash: String? { masterPasswordHash?.string }
    var organizationCount: Int { orgKeys.count }

    // MARK: - Key Derivation

    func deriveKeys(
        password: String, email: String, kdf: Int, kdfIterations: Int,
        kdfMemory: Int?, kdfParallelism: Int?
    ) throws {
        let salt = Data(email.lowercased().utf8)
        let passwordData = Data(password.utf8)

        guard let kdfType = KdfType(rawValue: kdf) else { throw CryptoError.unsupportedKdf(kdf) }

        let mk: Data
        switch kdfType {
        case .pbkdf2:
            mk = pbkdf2(password: passwordData, salt: salt, iterations: kdfIterations, keyLength: 32)
        case .argon2id:
            guard let memory = kdfMemory, let parallelism = kdfParallelism else { throw CryptoError.missingKdfParams }
            let argonSalt = Data(SHA256.hash(data: salt))
            mk = try deriveArgon2id(password: passwordData, salt: argonSalt,
                                     iterations: kdfIterations, memoryMiB: memory, parallelism: parallelism)
        }

        masterKey = SecureBytes(data: mk)
        // Bitwarden server-side master-password hash: PBKDF2(masterKey, password, 1 iter).
        let hash = pbkdf2(password: mk, salt: passwordData, iterations: 1, keyLength: 32)
        masterPasswordHash = SecureString(hash.base64EncodedString())
    }

    func setEncryptionKey(from encryptedKey: String) throws {
        guard let mk = masterKey else { throw CryptoError.noMasterKey }
        let stretchedKey = SymmetricCryptoKey(key: mk.data)
        let decrypted = try decryptData(encryptedKey, key: stretchedKey)
        userKey = SecureBytes(data: decrypted)
        encKey = SymmetricCryptoKey(key: decrypted)
    }

    // MARK: - Biometric unlock (store the key, not the master password)

    /// Raw user-key bytes for biometric-unlock storage. Valid only after a successful
    /// `setEncryptionKey(from:)` or `restoreSession(userKey:passwordHash:)`. Returns a
    /// copy; the caller must hand it straight to protected storage and not retain it.
    func exportUserKey() -> Data? { userKey?.data }

    /// Restore a session for biometric unlock without the master password: install the
    /// user key directly (so the vault decrypts) and the master-password hash (needed by
    /// the reprompt check and by server re-login). `masterKey` is intentionally NOT set —
    /// biometric unlock never re-derives from the password.
    func restoreSession(userKey rawUserKey: Data, passwordHash: String) {
        userKey = SecureBytes(data: rawUserKey)
        encKey = SymmetricCryptoKey(key: rawUserKey)
        masterPasswordHash = SecureString(passwordHash)
    }

    // MARK: - RSA Private Key

    func setPrivateKey(from encryptedPrivateKey: String?) {
        guard let encPK = encryptedPrivateKey, !encPK.isEmpty else { return }
        guard let key = encKey else { return }
        do {
            let pkData = try decryptData(encPK, key: key)
            rsaPrivateKey = try importRSAPrivateKey(pkData)
        } catch {
            Log.crypto("RSA private key import failed")
        }
    }

    // MARK: - Organization Keys

    func setOrganizationKeys(_ orgs: [SyncOrganization]) {
        orgKeys.removeAll()
        guard rsaPrivateKey != nil else { return }

        for org in orgs {
            guard let orgId = org.id, let orgKeyStr = org.key, !orgKeyStr.isEmpty else { continue }
            do {
                let decryptedKey = try decryptRSA(orgKeyStr)
                orgKeys[orgId] = SymmetricCryptoKey(key: decryptedKey)
            } catch {
                Log.crypto("Org key decrypt failed")
            }
        }
    }

    func hasOrgKey(for orgId: String?) -> Bool {
        guard let orgId else { return false }
        return orgKeys[orgId] != nil
    }

    // MARK: - Decrypt

    func decrypt(_ encryptedString: String?, orgId: String? = nil) -> String? {
        guard let encryptedString, !encryptedString.isEmpty else { return nil }

        if let orgId, let orgKey = orgKeys[orgId] {
            if let data = try? decryptData(encryptedString, key: orgKey) {
                return String(data: data, encoding: .utf8)
            }
        }

        guard let key = encKey else { return nil }
        guard let data = try? decryptData(encryptedString, key: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Decrypt an EncString to raw bytes using the org key (if `orgId` is given and known)
    /// or the user key. Unlike `decrypt(_:orgId:)` this does NOT UTF-8-decode the result,
    /// so it is safe for binary key material.
    func decryptToData(_ encryptedString: String?, orgId: String? = nil) -> Data? {
        guard let encryptedString, !encryptedString.isEmpty else { return nil }
        if let orgId, let orgKey = orgKeys[orgId],
           let data = try? decryptData(encryptedString, key: orgKey) {
            return data
        }
        guard let key = encKey else { return nil }
        return try? decryptData(encryptedString, key: key)
    }

    /// Build a per-cipher `SymmetricCryptoKey` from its wrapped key string.
    /// Used for Bitwarden "Cipher Key Encryption": newer items carry their own key,
    /// wrapped by the user/org key, and all of the item's fields are encrypted with it.
    func cipherKey(from encryptedKey: String?, orgId: String? = nil) -> SymmetricCryptoKey? {
        guard let raw = decryptToData(encryptedKey, orgId: orgId) else { return nil }
        return SymmetricCryptoKey(key: raw)
    }

    /// Decrypt a field with an explicit key (e.g. a per-cipher key).
    func decrypt(_ encryptedString: String?, with key: SymmetricCryptoKey) -> String? {
        guard let encryptedString, !encryptedString.isEmpty else { return nil }
        guard let data = try? decryptData(encryptedString, key: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func decryptData(_ encryptedString: String, key: SymmetricCryptoKey) throws -> Data {
        guard let enc = EncString(string: encryptedString) else { throw CryptoError.invalidEncString }
        return try decryptEncString(enc, key: key)
    }

    /// Strict symmetric decrypt. MAC is mandatory for authenticated AES-CBC types;
    /// unauthenticated AES-CBC (type 0) is rejected outright.
    private func decryptEncString(_ enc: EncString, key: SymmetricCryptoKey) throws -> Data {
        switch enc.type {
        case .aesCbc256_HmacSha256_B64, .aesCbc128_HmacSha256_B64:
            guard let iv = enc.iv, let mac = enc.mac else { throw CryptoError.invalidEncString }
            var macInput = Data(); macInput.append(iv); macInput.append(enc.ct)
            let computed = hmacSha256(data: macInput, key: key)
            guard constantTimeEqual(computed, mac) else { throw CryptoError.macMismatch }
            return try aesCbcDecrypt(data: enc.ct, key: key, iv: iv)

        case .aesCbc256_B64:
            throw CryptoError.unauthenticatedNotAllowed

        default:
            // RSA types must go through decryptRSA, never the symmetric path.
            throw CryptoError.unsupportedEncType(enc.type.rawValue)
        }
    }

    // MARK: - RSA Decryption

    private func decryptRSA(_ encryptedString: String) throws -> Data {
        guard let pk = rsaPrivateKey else { throw CryptoError.noMasterKey }
        guard let enc = EncString(string: encryptedString) else { throw CryptoError.invalidEncString }

        let algorithm: SecKeyAlgorithm
        switch enc.type {
        case .rsa2048_OaepSha256_B64, .rsa2048_OaepSha256_HmacSha256_B64:
            algorithm = .rsaEncryptionOAEPSHA256
        case .rsa2048_OaepSha1_B64, .rsa2048_OaepSha1_HmacSha256_B64:
            algorithm = .rsaEncryptionOAEPSHA1
        default:
            throw CryptoError.unsupportedEncType(enc.type.rawValue)
        }

        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(pk, algorithm, enc.ct as CFData, &error) else {
            let cfError = error?.takeRetainedValue()
            throw CryptoError.rsaDecryptionFailed(cfError?.localizedDescription ?? "RSA decryption failed")
        }
        return decrypted as Data
    }

    private func importRSAPrivateKey(_ data: Data) throws -> SecKey {
        // Bitwarden private keys are PKCS#8. Try the stripped PKCS#1 form first so the raw
        // attempt (which fails with errSecParam -50 and logs system noise) is skipped for
        // them. If the data isn't PKCS#8, stripPKCS8Header returns nil and we fall back to raw.
        if let stripped = stripPKCS8Header(data), let key = createSecKey(from: stripped) { return key }
        if let key = createSecKey(from: data) { return key }
        throw CryptoError.rsaDecryptionFailed("Cannot import RSA private key")
    }

    private func createSecKey(from data: Data) -> SecKey? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]
        var error: Unmanaged<CFError>?
        return SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error)
    }

    private func stripPKCS8Header(_ keyData: Data) -> Data? {
        guard keyData.count > 26 else { return nil }
        var idx = 0
        guard keyData[idx] == 0x30 else { return nil }
        idx += 1
        idx += asn1LengthSize(keyData, at: idx)
        guard idx < keyData.count, keyData[idx] == 0x02 else { return nil }
        idx += 1
        let vLen = asn1Length(keyData, at: &idx)
        idx += vLen
        guard idx < keyData.count, keyData[idx] == 0x30 else { return nil }
        idx += 1
        let aLen = asn1Length(keyData, at: &idx)
        idx += aLen
        guard idx < keyData.count, keyData[idx] == 0x04 else { return nil }
        idx += 1
        _ = asn1Length(keyData, at: &idx)
        guard idx < keyData.count else { return nil }
        return Data(keyData[idx...])
    }

    private func asn1LengthSize(_ data: Data, at index: Int) -> Int {
        guard index < data.count else { return 1 }
        if data[index] < 0x80 { return 1 }
        return 1 + Int(data[index] & 0x7f)
    }

    private func asn1Length(_ data: Data, at index: inout Int) -> Int {
        guard index < data.count else { return 0 }
        let first = data[index]
        if first < 0x80 { index += 1; return Int(first) }
        let numBytes = Int(first & 0x7f)
        index += 1
        var length = 0
        for i in 0..<numBytes {
            guard index + i < data.count else { break }
            length = (length << 8) | Int(data[index + i])
        }
        index += numBytes
        return length
    }

    // MARK: - Decrypt Attachment Data

    func decryptAttachmentData(_ encryptedData: Data, attachmentKeyString: String?, orgId: String? = nil) throws -> Data {
        let baseKey: SymmetricCryptoKey
        if let orgId, let orgKey = orgKeys[orgId] { baseKey = orgKey }
        else if let key = encKey { baseKey = key }
        else { throw CryptoError.noMasterKey }

        let fileKey: SymmetricCryptoKey
        if let keyString = attachmentKeyString, !keyString.isEmpty {
            let rawKeyData = try decryptData(keyString, key: baseKey)
            fileKey = SymmetricCryptoKey(key: rawKeyData)
        } else {
            fileKey = baseKey
        }
        return try decryptRawBuffer(encryptedData, key: fileKey)
    }

    /// Strict attachment buffer decrypt.
    /// Canonical Bitwarden layout: `[encType:1][iv:16][mac:32][ciphertext...]`.
    /// MAC is verified before decryption; a mismatch (or an unauthenticated type)
    /// throws instead of silently returning tampered plaintext.
    func decryptRawBuffer(_ data: Data, key: SymmetricCryptoKey) throws -> Data {
        guard data.count > 49 else { throw CryptoError.invalidEncString }
        let start = data.startIndex
        let typeByte = Int(data[start])
        guard let type = EncType(rawValue: typeByte) else { throw CryptoError.unsupportedEncType(typeByte) }

        switch type {
        case .aesCbc256_HmacSha256_B64, .aesCbc128_HmacSha256_B64:
            let iv = Data(data[(start + 1)..<(start + 17)])
            let mac = Data(data[(start + 17)..<(start + 49)])
            let ct = Data(data[(start + 49)...])
            var macInput = Data(); macInput.append(iv); macInput.append(ct)
            let computed = hmacSha256(data: macInput, key: key)
            guard constantTimeEqual(computed, mac) else { throw CryptoError.macMismatch }
            return try aesCbcDecrypt(data: ct, key: key, iv: iv)

        case .aesCbc256_B64:
            throw CryptoError.unauthenticatedNotAllowed

        default:
            throw CryptoError.unsupportedEncType(typeByte)
        }
    }

    // MARK: - Encrypt

    func encrypt(_ plaintext: String?, orgId: String? = nil) -> String? {
        guard let plaintext, !plaintext.isEmpty else { return nil }
        let key: SymmetricCryptoKey
        if let orgId, let orgKey = orgKeys[orgId] { key = orgKey }
        else if let ek = encKey { key = ek }
        else { return nil }
        guard let data = plaintext.data(using: .utf8) else { return nil }
        return try? encryptData(data, key: key)
    }

    func encryptData(_ data: Data, key: SymmetricCryptoKey) throws -> String {
        let iv = try randomBytes(16)
        let ct = try aesCbcEncrypt(data: data, key: key, iv: iv)
        var macData = Data(); macData.append(iv); macData.append(ct)
        let mac = hmacSha256(data: macData, key: key)
        return EncString(type: .aesCbc256_HmacSha256_B64, iv: iv, ct: ct, mac: mac).serialize()
    }

    // MARK: - Attachment Encryption

    /// Encrypt a file for upload as a Bitwarden attachment.
    /// Returns the encrypted buffer (`[type][iv][mac][ciphertext]`) and the
    /// attachment key — a fresh random file key, itself encrypted with the
    /// cipher/organization key — for the server's `key` field.
    func encryptAttachment(_ data: Data, orgId: String? = nil) throws -> (data: Data, key: String) {
        let baseKey: SymmetricCryptoKey
        if let orgId, let orgKey = orgKeys[orgId] { baseKey = orgKey }
        else if let ek = encKey { baseKey = ek }
        else { throw CryptoError.noMasterKey }

        let attachmentKeyRaw = try randomBytes(64)
        let fileKey = SymmetricCryptoKey(key: attachmentKeyRaw)
        let encryptedData = try encryptBuffer(data, key: fileKey)
        let encryptedKey = try encryptData(attachmentKeyRaw, key: baseKey)
        return (encryptedData, encryptedKey)
    }

    /// Authenticated AES-CBC into the raw attachment buffer layout
    /// `[encType:1][iv:16][mac:32][ciphertext]` — the inverse of `decryptRawBuffer`.
    func encryptBuffer(_ data: Data, key: SymmetricCryptoKey) throws -> Data {
        let iv = try randomBytes(16)
        let ct = try aesCbcEncrypt(data: data, key: key, iv: iv)
        var macInput = Data(); macInput.append(iv); macInput.append(ct)
        let mac = hmacSha256(data: macInput, key: key)

        var out = Data()
        out.reserveCapacity(1 + iv.count + mac.count + ct.count)
        out.append(UInt8(EncType.aesCbc256_HmacSha256_B64.rawValue))
        out.append(iv); out.append(mac); out.append(ct)
        return out
    }

    /// Securely clear all keys from memory. Dropping the `SymmetricCryptoKey`
    /// references triggers `SecureBytes.deinit`, which zeroes the key material.
    func clearKeys() {
        masterKey?.wipe()
        masterKey = nil
        masterPasswordHash?.wipe()
        masterPasswordHash = nil
        userKey?.wipe()
        userKey = nil
        encKey = nil
        rsaPrivateKey = nil
        orgKeys.removeAll()
    }

    // MARK: - Low-level Crypto

    private func deriveArgon2id(password: Data, salt: Data, iterations: Int, memoryMiB: Int, parallelism: Int) throws -> Data {
        let saltObj = Salt(bytes: salt)
        let result = try Argon2Swift.hashPasswordBytes(
            password: password, salt: saltObj, iterations: iterations,
            memory: memoryMiB * 1024, parallelism: parallelism, type: .id
        )
        return result.hashData()
    }

    private func pbkdf2(password: Data, salt: Data, iterations: Int, keyLength: Int) -> Data {
        var derivedKey = Data(count: keyLength)
        derivedKey.withUnsafeMutableBytes { dk in
            password.withUnsafeBytes { pw in
                salt.withUnsafeBytes { s in
                    _ = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                        pw.baseAddress?.assumingMemoryBound(to: Int8.self), password.count,
                        s.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations),
                        dk.baseAddress?.assumingMemoryBound(to: UInt8.self), keyLength)
                }
            }
        }
        return derivedKey
    }

    static func hkdfExpand(prk: Data, info: Data, length: Int) -> Data {
        let key = SymmetricKey(data: prk)
        var okm = Data(); var t = Data(); var i: UInt8 = 1
        while okm.count < length {
            var input = t; input.append(info); input.append(i)
            t = Data(HMAC<SHA256>.authenticationCode(for: input, using: key))
            okm.append(t); i += 1
        }
        return okm.prefix(length)
    }

    private func hmacSha256(data: Data, key: SymmetricCryptoKey) -> Data {
        key.withMacKey { mk in
            Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: mk)))
        }
    }

    private func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }

    private func randomBytes(_ count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw CryptoError.randomFailed }
        return data
    }

    private func aesCbcDecrypt(data: Data, key: SymmetricCryptoKey, iv: Data) throws -> Data {
        let bufSize = data.count + kCCBlockSizeAES128
        var buf = Data(count: bufSize); var outLen = 0
        let status = key.withEncKey { k in
            buf.withUnsafeMutableBytes { b in
                data.withUnsafeBytes { d in iv.withUnsafeBytes { i in
                    CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                            k.baseAddress, k.count, i.baseAddress, d.baseAddress, data.count,
                            b.baseAddress, bufSize, &outLen)
                }}
            }
        }
        guard status == kCCSuccess else { throw CryptoError.decryptionFailed(status) }
        return buf.prefix(outLen)
    }

    private func aesCbcEncrypt(data: Data, key: SymmetricCryptoKey, iv: Data) throws -> Data {
        let bufSize = data.count + kCCBlockSizeAES128 + 16
        var buf = Data(count: bufSize); var outLen = 0
        let status = key.withEncKey { k in
            buf.withUnsafeMutableBytes { b in
                data.withUnsafeBytes { d in iv.withUnsafeBytes { i in
                    CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                            k.baseAddress, k.count, i.baseAddress, d.baseAddress, data.count,
                            b.baseAddress, bufSize, &outLen)
                }}
            }
        }
        guard status == kCCSuccess else { throw CryptoError.encryptionFailed(status) }
        return buf.prefix(outLen)
    }

    // MARK: - Password Generator

    /// Cryptographically secure index in `0..<upperBound` using rejection sampling
    /// to eliminate modulo bias.
    private static func secureRandomIndex(_ upperBound: Int) -> Int {
        precondition(upperBound > 0)
        let n = UInt32(upperBound)
        let limit = UInt32.max - (UInt32.max % n)
        while true {
            var bytes = [UInt8](repeating: 0, count: 4)
            guard SecRandomCopyBytes(kSecRandomDefault, 4, &bytes) == errSecSuccess else { continue }
            let r = UInt32(bytes[0]) | (UInt32(bytes[1]) << 8) | (UInt32(bytes[2]) << 16) | (UInt32(bytes[3]) << 24)
            if r < limit { return Int(r % n) }
        }
    }

    static func generatePassword(length: Int = 20, uppercase: Bool = true, lowercase: Bool = true, digits: Bool = true, symbols: Bool = true, excludeAmbiguous: Bool = false) -> String {
        let ambiguous = Set<Character>("O0oIl1|`'\"")
        func cls(_ s: String) -> [Character] {
            let a = Array(s)
            return excludeAmbiguous ? a.filter { !ambiguous.contains($0) } : a
        }
        var classes: [[Character]] = []
        if uppercase { classes.append(cls("ABCDEFGHIJKLMNOPQRSTUVWXYZ")) }
        if lowercase { classes.append(cls("abcdefghijklmnopqrstuvwxyz")) }
        if digits { classes.append(cls("0123456789")) }
        if symbols { classes.append(cls("!@#$%^&*()_+-=")) }
        classes = classes.filter { !$0.isEmpty }
        if classes.isEmpty { classes.append(Array("abcdefghijklmnopqrstuvwxyz")) }

        let all = classes.flatMap { $0 }
        let targetLen = max(1, length)

        var chars: [Character] = []
        chars.reserveCapacity(targetLen)

        // Guarantee at least one character from each selected class (when length allows).
        if targetLen >= classes.count {
            for c in classes { chars.append(c[secureRandomIndex(c.count)]) }
        }
        while chars.count < targetLen {
            chars.append(all[secureRandomIndex(all.count)])
        }

        // Fisher–Yates shuffle so the seeded class characters aren't always first.
        if chars.count > 1 {
            for i in stride(from: chars.count - 1, to: 0, by: -1) {
                chars.swapAt(i, secureRandomIndex(i + 1))
            }
        }

        return String(chars)
    }

    /// Generate a password from a saved template.
    static func generate(from t: PasswordTemplate) -> String {
        let s = t.sanitized()
        return generatePassword(length: s.length, uppercase: s.uppercase, lowercase: s.lowercase,
                                digits: s.digits, symbols: s.symbols, excludeAmbiguous: s.excludeAmbiguous)
    }
}

/// A named password-generation preset.
struct PasswordTemplate: Identifiable, Codable, Equatable {
    var id: String = UUID().uuidString
    var name: String
    var length: Int
    var uppercase: Bool
    var lowercase: Bool
    var digits: Bool
    var symbols: Bool
    var excludeAmbiguous: Bool
    /// Localization key for built-in templates; nil for user (custom) templates.
    var builtinKey: String? = nil
    /// SF Symbol name; custom templates fall back to "key".
    var icon: String? = nil

    static let minLength = 6
    static let maxLength = 128

    /// Built-in templates are read-only (cannot be edited, deleted or reordered).
    var isBuiltin: Bool { builtinKey != nil }
    /// Display name: localized built-in key when present, otherwise the user-set name.
    var displayName: String { builtinKey?.localized ?? name }
    var iconName: String { icon ?? "key" }

    /// Clamp length to [6, 128] and ensure at least one character class is enabled.
    func sanitized() -> PasswordTemplate {
        var t = self
        t.length = Swift.max(Self.minLength, Swift.min(t.length, Self.maxLength))
        if !(t.uppercase || t.lowercase || t.digits || t.symbols) { t.lowercase = true }
        return t
    }

    /// True when generation settings match (ignores id / name / icon).
    func sameSettings(as o: PasswordTemplate) -> Bool {
        length == o.length && uppercase == o.uppercase && lowercase == o.lowercase
            && digits == o.digits && symbols == o.symbols && excludeAmbiguous == o.excludeAmbiguous
    }

    /// Short human summary, e.g. "16 · A-Z a-z 0-9 !@#".
    var summary: String {
        var parts: [String] = []
        if uppercase { parts.append("A-Z") }
        if lowercase { parts.append("a-z") }
        if digits { parts.append("0-9") }
        if symbols { parts.append("!@#") }
        var s = "\(length) · " + parts.joined(separator: " ")
        if excludeAmbiguous { s += " · " + L10n.Generator.noSimilarShort.localized }
        return s
    }

    /// Read-only built-in presets (fixed order, stable IDs, localized names).
    static var builtins: [PasswordTemplate] {
        [
            PasswordTemplate(id: "standard", name: "", length: 16, uppercase: true, lowercase: true, digits: true, symbols: true, excludeAmbiguous: false, builtinKey: L10n.Generator.starterStandard, icon: "star"),
            PasswordTemplate(id: "strong_30", name: "", length: 30, uppercase: true, lowercase: true, digits: true, symbols: true, excludeAmbiguous: true, builtinKey: L10n.Generator.starterStrong30, icon: "lock.shield"),
            PasswordTemplate(id: "letters_digits_12", name: "", length: 12, uppercase: true, lowercase: true, digits: true, symbols: false, excludeAmbiguous: true, builtinKey: L10n.Generator.starterAlnum12, icon: "number"),
            PasswordTemplate(id: "pin_6", name: "", length: 6, uppercase: false, lowercase: false, digits: true, symbols: false, excludeAmbiguous: false, builtinKey: L10n.Generator.starterPin6, icon: "lock"),
        ]
    }
}

// MARK: - Errors

enum CryptoError: LocalizedError {
    case noMasterKey, invalidEncString, macMismatch, missingIV
    case decryptionFailed(CCCryptorStatus), encryptionFailed(CCCryptorStatus)
    case randomFailed, unsupportedKdf(Int), missingKdfParams
    case rsaDecryptionFailed(String)
    case unauthenticatedNotAllowed
    case unsupportedEncType(Int)

    var errorDescription: String? {
        switch self {
        case .noMasterKey: return "Master key not set"
        case .invalidEncString: return "Invalid encrypted string format"
        case .macMismatch: return "Data integrity check failed (MAC)"
        case .missingIV: return "Missing initialization vector"
        case .decryptionFailed(let s): return "Decryption error: \(s)"
        case .encryptionFailed(let s): return "Encryption error: \(s)"
        case .randomFailed: return "Random data generation error"
        case .unsupportedKdf(let t): return "Unsupported KDF type: \(t)"
        case .missingKdfParams: return "Missing KDF parameters"
        case .rsaDecryptionFailed(let msg): return "RSA error: \(msg)"
        case .unauthenticatedNotAllowed: return "Unauthenticated encryption (no MAC) is not allowed"
        case .unsupportedEncType(let t): return "Unsupported encryption type: \(t)"
        }
    }
}
