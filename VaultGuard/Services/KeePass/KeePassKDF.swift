import Foundation
import CommonCrypto
import CryptoKit
import Argon2Swift

// MARK: - KeePass key derivation
//
// KDBX поддерживает два KDF:
// - AES-KDF (KDBX 3.1): `rounds` раз прогнать 32-байтный составной ключ через AES-256-ECB
//   с ключом = transform seed, затем SHA-256.
// - Argon2 (KDBX 4): Argon2d/Argon2id. Используется уже имеющийся `Argon2Swift`
//   (проверено по исходнику ревизии: есть параметры `type` и `version`). Параметр KDBX `M`
//   задаётся в БАЙТАХ и здесь конвертируется в KiB для библиотеки.
//
// Ограничение: Argon2Swift не пробрасывает Argon2 secret (K) / associated data (A).
// Стандартные файлы KeePass/KeePassXC их не используют; при непустых K/A бросаем ошибку.
//
// Корректность проверяется в `VaultGuardTests/KeePassCryptoTests.swift`.

enum KeePassKDFError: LocalizedError {
    case aesFailed(Int32)
    case argon2(String)
    case unsupportedArgon2SecretOrAD
    case badInputLength

    var errorDescription: String? {
        switch self {
        case .aesFailed(let s): return "AES-KDF failed (status \(s))"
        case .argon2(let m): return "Argon2 failed: \(m)"
        case .unsupportedArgon2SecretOrAD: return "Argon2 secret/associated data is not supported"
        case .badInputLength: return "Invalid key/seed length for KDF"
        }
    }
}

enum KeePassKDF {

    enum Argon2Variant { case d, id }

    /// KDBX 3.1 AES-KDF transform. Returns the 32-byte transformed key
    /// (`SHA256` of the composite key after `rounds` AES-256-ECB iterations under `seed`).
    static func aesKdfTransform(compositeKey: Data, seed: Data, rounds: UInt64) throws -> Data {
        guard compositeKey.count == 32, seed.count == 32 else { throw KeePassKDFError.badInputLength }
        var data = compositeKey
        // ECB processes each 16-byte half independently, matching KDBX's per-half transform.
        var i: UInt64 = 0
        while i < rounds {
            data = try aesEcbEncrypt(data, key: seed)
            i &+= 1
        }
        return Data(SHA256.hash(data: data))
    }

    /// AES-256-ECB, no padding. `data.count` must be a multiple of 16.
    static func aesEcbEncrypt(_ data: Data, key: Data) throws -> Data {
        guard data.count % kCCBlockSizeAES128 == 0, key.count == kCCKeySizeAES256 else {
            throw KeePassKDFError.badInputLength
        }
        let cap = data.count
        var out = Data(count: cap)
        var outLen = 0
        let status = key.withUnsafeBytes { k in
            data.withUnsafeBytes { d in
                out.withUnsafeMutableBytes { o in
                    CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionECBMode),
                            k.baseAddress, k.count, nil,
                            d.baseAddress, cap,
                            o.baseAddress, cap, &outLen)
                }
            }
        }
        guard status == kCCSuccess else { throw KeePassKDFError.aesFailed(status) }
        return out.prefix(outLen)
    }

    /// AES-256-CBC encrypt with PKCS#7 padding (KDBX 4 outer cipher, write path).
    static func aesCbcEncrypt(_ data: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == kCCKeySizeAES256, iv.count == kCCBlockSizeAES128 else {
            throw KeePassKDFError.badInputLength
        }
        let cap = data.count + kCCBlockSizeAES128
        let dataLen = data.count
        var out = Data(count: cap)
        var outLen = 0
        let status = key.withUnsafeBytes { k in
            iv.withUnsafeBytes { ivp in
                data.withUnsafeBytes { d in
                    out.withUnsafeMutableBytes { o in
                        CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
                                CCOptions(kCCOptionPKCS7Padding),
                                k.baseAddress, k.count, ivp.baseAddress,
                                d.baseAddress, dataLen,
                                o.baseAddress, cap, &outLen)
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw KeePassKDFError.aesFailed(status) }
        return out.prefix(outLen)
    }

    /// AES-256-CBC decrypt. With `padding` true (default) PKCS#7 padding is removed (KDBX 4
    /// outer cipher). With `padding` false the raw blocks are returned (KDBX 3.1, where the
    /// hashed-block terminator delimits the data and trailing padding is ignored). `iv` is 16
    /// bytes.
    static func aesCbcDecrypt(_ data: Data, key: Data, iv: Data, padding: Bool = true) throws -> Data {
        guard key.count == kCCKeySizeAES256, iv.count == kCCBlockSizeAES128 else {
            throw KeePassKDFError.badInputLength
        }
        let cap = data.count + kCCBlockSizeAES128
        let dataLen = data.count
        var out = Data(count: cap)
        var outLen = 0
        let options = padding ? CCOptions(kCCOptionPKCS7Padding) : CCOptions(0)
        let status = key.withUnsafeBytes { k in
            iv.withUnsafeBytes { ivp in
                data.withUnsafeBytes { d in
                    out.withUnsafeMutableBytes { o in
                        CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES),
                                options,
                                k.baseAddress, k.count, ivp.baseAddress,
                                d.baseAddress, dataLen,
                                o.baseAddress, cap, &outLen)
                    }
                }
            }
        }
        guard status == kCCSuccess else { throw KeePassKDFError.aesFailed(status) }
        return out.prefix(outLen)
    }

    /// KDBX 4 Argon2 KDF. `memoryBytes` is the KDBX `M` parameter in BYTES; `version` is the
    /// KDBX `V` parameter (0x10 → V10, otherwise V13). Returns a 32-byte derived key.
    static func argon2(compositeKey: Data, salt: Data, variant: Argon2Variant,
                       iterations: UInt64, memoryBytes: UInt64, parallelism: UInt32,
                       version: UInt32, secret: Data = Data(), associatedData: Data = Data()) throws -> Data {
        guard secret.isEmpty, associatedData.isEmpty else {
            throw KeePassKDFError.unsupportedArgon2SecretOrAD
        }
        let type: Argon2Type = (variant == .d) ? .d : .id
        let ver: Argon2Version = (version == 0x10) ? .V10 : .V13
        let memKiB = Int(memoryBytes / 1024)
        do {
            let res = try Argon2Swift.hashPasswordBytes(
                password: compositeKey,
                salt: Salt(bytes: salt),
                iterations: Int(iterations),
                memory: memKiB,
                parallelism: Int(parallelism),
                length: 32,
                type: type,
                version: ver)
            return res.hashData()
        } catch {
            throw KeePassKDFError.argon2(String(describing: error))
        }
    }
}
