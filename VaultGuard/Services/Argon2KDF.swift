import Foundation
import CArgon2

/// Argon2 key derivation over the vendored reference implementation.
///
/// Both callers — `KeePassKDF` for KDBX 4 and `CryptoService` for Bitwarden's Argon2id KDF —
/// need exactly one thing: raw derived bytes from a password and a salt. This is that one
/// function, and nothing else of the library is exposed.
///
/// It calls `argon2_hash` the same way the removed `Argon2Swift` wrapper did, so the output is
/// byte-for-byte what it was: same `m_cost` unit (KiB), same `t_cost`, lanes equal to threads.
/// The one difference is that no encoded `$argon2id$…` string is requested. That string is
/// produced after the raw hash is computed and does not affect it; asking for it only meant
/// allocating and copying a second buffer nobody read.
enum Argon2KDF {

    enum Variant {
        case d
        case id

        fileprivate var cValue: argon2_type {
            switch self {
            case .d:  return Argon2_d
            case .id: return Argon2_id
            }
        }
    }

    /// Argon2 algorithm version. KeePass files record which one they were written with; new
    /// derivations use 1.3.
    enum Version: UInt32 {
        case v10 = 0x10
        case v13 = 0x13
    }

    enum KDFError: LocalizedError {
        case parameterOutOfRange(String)
        case failed(code: Int32, message: String)

        var errorDescription: String? {
            switch self {
            case .parameterOutOfRange(let what): return "Argon2 parameter out of range: \(what)"
            case .failed(_, let message):        return "Argon2 failed: \(message)"
            }
        }
    }

    /// Derive `length` bytes.
    ///
    /// - Parameters:
    ///   - memoryKiB: memory cost in KiB — the library's unit. KDBX stores bytes and Bitwarden
    ///     stores MiB, so each caller converts at its own boundary rather than this function
    ///     guessing.
    static func hash(password: Data, salt: Data, iterations: UInt32, memoryKiB: UInt32,
                     parallelism: UInt32, length: Int = 32,
                     variant: Variant, version: Version = .v13) throws -> Data {
        // The C API takes 32-bit sizes internally; reject rather than truncate.
        guard length > 0, length <= Int(UInt32.max) else {
            throw KDFError.parameterOutOfRange("length \(length)")
        }
        guard iterations > 0 else { throw KDFError.parameterOutOfRange("iterations 0") }
        guard parallelism > 0 else { throw KDFError.parameterOutOfRange("parallelism 0") }

        var output = Data(count: length)
        let code: Int32 = output.withUnsafeMutableBytes { out in
            password.withUnsafeBytes { pwd in
                salt.withUnsafeBytes { slt in
                    argon2_hash(iterations, memoryKiB, parallelism,
                                pwd.baseAddress, password.count,
                                slt.baseAddress, salt.count,
                                out.baseAddress, length,
                                nil, 0,                       // no encoded string
                                variant.cValue, version.rawValue)
                }
            }
        }
        guard code == ARGON2_OK.rawValue else {
            // Do not hand back a buffer the library may have left half-written.
            output.resetBytes(in: 0..<output.count)
            throw KDFError.failed(code: code, message: String(cString: argon2_error_message(code)))
        }
        return output
    }
}
