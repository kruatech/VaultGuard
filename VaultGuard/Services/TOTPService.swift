import Foundation
import CryptoKit

/// TOTP/HOTP generator with full `otpauth://` and `steam://` support.
///
/// Accepts either a raw Base32 secret or a full otpauth URI and honours the
/// `algorithm` (SHA1/256/512), `digits`, and `period` parameters, plus Steam Guard.
final class TOTPService {
    static let shared = TOTPService()

    private enum Algorithm { case sha1, sha256, sha512, steam }

    private struct OTPConfig {
        let key: Data
        let digits: Int
        let period: Int
        let algorithm: Algorithm
    }

    // MARK: - Public API

    func generateCode(secret: String) -> String? {
        guard let cfg = parse(secret) else { return nil }
        let counter = UInt64(Date().timeIntervalSince1970) / UInt64(cfg.period)
        return code(cfg: cfg, counter: counter)
    }

    func formattedCode(secret: String) -> String? {
        guard let code = generateCode(secret: secret) else { return nil }
        guard code.count == 6 else { return code } // group only the common 6-digit case
        let idx = code.index(code.startIndex, offsetBy: 3)
        return "\(code[..<idx]) \(code[idx...])"
    }

    func period(for secret: String) -> Int { parse(secret)?.period ?? 30 }

    func secondsRemaining(for secret: String) -> Int {
        let p = period(for: secret)
        return p - (Int(Date().timeIntervalSince1970) % p)
    }

    func progress(for secret: String) -> Double {
        let p = period(for: secret)
        return Double(secondsRemaining(for: secret)) / Double(p)
    }

    // MARK: - Parsing

    private func parse(_ raw: String) -> OTPConfig? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)

        // steam://<base32>
        if trimmed.lowercased().hasPrefix("steam://") {
            let secret = String(trimmed.dropFirst("steam://".count))
            guard let key = base32Decode(secret) else { return nil }
            return OTPConfig(key: key, digits: 5, period: 30, algorithm: .steam)
        }

        // otpauth://totp/label?secret=...&algorithm=...&digits=...&period=...
        if trimmed.lowercased().hasPrefix("otpauth://"),
           let comps = URLComponents(string: trimmed) {
            let items = comps.queryItems ?? []
            func q(_ name: String) -> String? { items.first { $0.name.lowercased() == name }?.value }

            guard let secretParam = q("secret"), let key = base32Decode(secretParam) else { return nil }
            let rawDigits = q("digits").flatMap(Int.init) ?? 6
            guard (5...10).contains(rawDigits) else { return nil }
            let digits = rawDigits
            let period = q("period").flatMap(Int.init) ?? 30
            var algo: Algorithm = .sha1
            switch (q("algorithm") ?? "SHA1").uppercased() {
            case "SHA256": algo = .sha256
            case "SHA512": algo = .sha512
            default: algo = .sha1
            }
            if comps.host?.lowercased() == "steam" || (q("encoder")?.lowercased() == "steam") {
                algo = .steam
            }
            return OTPConfig(key: key, digits: algo == .steam ? 5 : digits,
                             period: max(1, period), algorithm: algo)
        }

        // Raw Base32 secret (possibly spaced).
        guard let key = base32Decode(trimmed) else { return nil }
        return OTPConfig(key: key, digits: 6, period: 30, algorithm: .sha1)
    }

    // MARK: - HOTP core

    private func code(cfg: OTPConfig, counter: UInt64) -> String {
        var counterBE = counter.bigEndian
        let counterData = Data(bytes: &counterBE, count: 8)
        let hmac = hmac(cfg.algorithm, key: cfg.key, data: counterData)

        let offset = Int(hmac[hmac.count - 1] & 0x0f)
        let binary = (UInt32(hmac[offset]) & 0x7f) << 24
            | UInt32(hmac[offset + 1]) << 16
            | UInt32(hmac[offset + 2]) << 8
            | UInt32(hmac[offset + 3])

        if cfg.algorithm == .steam { return steamEncode(binary) }

        // Modulo in UInt64: 10^10 exceeds UInt32.max, so a Double->UInt32 conversion
        // would trap at runtime for digits == 10 (a crafted/odd otpauth URI in a vault
        // item must never crash the app).
        let modulus = (0..<cfg.digits).reduce(UInt64(1)) { m, _ in m * 10 }
        let otp = UInt64(binary) % modulus
        return String(format: "%0\(cfg.digits)d", otp)
    }

    private func hmac(_ algorithm: Algorithm, key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        switch algorithm {
        case .sha256:
            return Data(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))
        case .sha512:
            return Data(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
        case .sha1, .steam:
            return Data(HMAC<Insecure.SHA1>.authenticationCode(for: data, using: symmetricKey))
        }
    }

    private func steamEncode(_ value: UInt32) -> String {
        let alphabet = Array("23456789BCDFGHJKMNPQRTVWXY")
        var v = value
        var result = ""
        for _ in 0..<5 {
            result.append(alphabet[Int(v % UInt32(alphabet.count))])
            v /= UInt32(alphabet.count)
        }
        return result
    }

    // MARK: - Base32

    private func base32Decode(_ input: String) -> Data? {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        let cleaned = input.uppercased().replacingOccurrences(of: " ", with: "")
        var bits = ""
        for char in cleaned {
            if char == "=" { continue }
            guard let index = alphabet.firstIndex(of: char) else { return nil }
            let value = alphabet.distance(from: alphabet.startIndex, to: index)
            bits += String(value, radix: 2).leftPadded(to: 5)
        }

        var bytes = Data()
        var i = 0
        while i + 8 <= bits.count {
            let startIdx = bits.index(bits.startIndex, offsetBy: i)
            let endIdx = bits.index(startIdx, offsetBy: 8)
            if let byte = UInt8(String(bits[startIdx..<endIdx]), radix: 2) { bytes.append(byte) }
            i += 8
        }
        return bytes.isEmpty ? nil : bytes
    }
}

private extension String {
    func leftPadded(to length: Int, with char: Character = "0") -> String {
        count >= length ? self : String(repeating: char, count: length - count) + self
    }
}
