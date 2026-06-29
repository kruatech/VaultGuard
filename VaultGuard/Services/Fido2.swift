import Foundation
import CryptoKit
import Security

/// WebAuthn / FIDO2 crypto core for passkeys. Pure byte construction + P-256 (ES256) signing,
/// independent of the AutoFill extension wiring. Validated against the WebAuthn spec byte formats
/// (COSE_Key, authenticatorData, attestationObject, assertion signature).
enum Fido2 {

    // MARK: - Minimal CBOR (canonical, only what passkeys need)

    enum CBOR {
        /// Major-type-0 unsigned integer header/value.
        static func uint(_ v: UInt64) -> [UInt8] {
            if v < 24 { return [UInt8(v)] }
            if v <= 0xff { return [0x18, UInt8(v)] }
            if v <= 0xffff { return [0x19, UInt8(v >> 8), UInt8(v & 0xff)] }
            if v <= 0xffff_ffff {
                return [0x1a, UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
            }
            var b: [UInt8] = [0x1b]
            for shift in stride(from: 56, through: 0, by: -8) { b.append(UInt8((v >> UInt64(shift)) & 0xff)) }
            return b
        }
        /// Major-type-1 negative integer (value = -1 - n).
        static func negInt(_ v: Int) -> [UInt8] {
            var b = uint(UInt64(-1 - v)); b[0] |= 0x20; return b
        }
        static func bytes(_ d: Data) -> [UInt8] {
            var h = uint(UInt64(d.count)); h[0] |= 0x40; return h + [UInt8](d)
        }
        static func text(_ s: String) -> [UInt8] {
            let u = Array(s.utf8); var h = uint(UInt64(u.count)); h[0] |= 0x60; return h + u
        }
        static func mapHeader(_ count: Int) -> [UInt8] {
            var h = uint(UInt64(count)); h[0] |= 0xa0; return h
        }
    }

    // MARK: - Authenticator flags

    struct Flags {
        static let userPresent: UInt8 = 0x01
        static let userVerified: UInt8 = 0x04
        static let attestedCredentialData: UInt8 = 0x40
    }

    // MARK: - COSE key

    /// COSE_Key for an EC2 / P-256 / ES256 public key: {1:2, 3:-7, -1:1, -2:x, -3:y} (canonical).
    static func coseKey(x: Data, y: Data) -> Data {
        var b: [UInt8] = []
        b += CBOR.mapHeader(5)
        b += CBOR.uint(1);   b += CBOR.uint(2)      // kty: EC2
        b += CBOR.uint(3);   b += CBOR.negInt(-7)   // alg: ES256
        b += CBOR.negInt(-1); b += CBOR.uint(1)     // crv: P-256
        b += CBOR.negInt(-2); b += CBOR.bytes(x)    // x coordinate
        b += CBOR.negInt(-3); b += CBOR.bytes(y)    // y coordinate
        return Data(b)
    }

    // MARK: - Authenticator data

    /// attestedCredentialData = aaguid(16) || credIdLen(2 BE) || credId || cosePublicKey.
    static func attestedCredentialData(aaguid: Data, credentialId: Data, coseKey: Data) -> Data {
        var d = Data()
        d.append(aaguid)
        d.append(UInt8((credentialId.count >> 8) & 0xff))
        d.append(UInt8(credentialId.count & 0xff))
        d.append(credentialId)
        d.append(coseKey)
        return d
    }

    /// authenticatorData = SHA256(rpId)(32) || flags(1) || signCount(4 BE) || [attestedCredentialData].
    static func authenticatorData(rpId: String, flags: UInt8, signCount: UInt32, attestedCredentialData: Data?) -> Data {
        var d = Data()
        d.append(Data(SHA256.hash(data: Data(rpId.utf8))))
        d.append(flags)
        d.append(UInt8((signCount >> 24) & 0xff))
        d.append(UInt8((signCount >> 16) & 0xff))
        d.append(UInt8((signCount >> 8) & 0xff))
        d.append(UInt8(signCount & 0xff))
        if let acd = attestedCredentialData { d.append(acd) }
        return d
    }

    /// attestationObject for the "none" attestation format: {fmt:"none", attStmt:{}, authData:…}.
    static func attestationObject(authData: Data) -> Data {
        var b: [UInt8] = []
        b += CBOR.mapHeader(3)
        b += CBOR.text("fmt");      b += CBOR.text("none")
        b += CBOR.text("attStmt");  b += CBOR.mapHeader(0)
        b += CBOR.text("authData"); b += CBOR.bytes(authData)
        return Data(b)
    }

    // MARK: - Keys & signing

    /// Split a P-256 public key into its 32-byte X and Y coordinates (from the X9.63 form).
    static func coordinates(_ key: P256.Signing.PublicKey) -> (x: Data, y: Data) {
        let raw = key.x963Representation   // 0x04 || X(32) || Y(32)
        return (raw.subdata(in: 1..<33), raw.subdata(in: 33..<65))
    }

    /// ES256 assertion signature over (authenticatorData || clientDataHash), DER-encoded.
    static func assertionSignature(privateKey: P256.Signing.PrivateKey,
                                   authenticatorData: Data, clientDataHash: Data) throws -> Data {
        let signature = try privateKey.signature(for: authenticatorData + clientDataHash)
        return signature.derRepresentation
    }

    // MARK: - Stored credential

    /// A passkey stored in the vault. `privateKey` is the P-256 raw scalar (32 bytes).
    struct Credential: Codable {
        var credentialId: Data
        var rpId: String
        var userHandle: Data
        var userName: String
        var privateKey: Data
        var counter: UInt32
    }

    /// Thrown when the system CSPRNG fails; never fall back to a predictable credential id.
    enum Fido2Error: Error { case randomGenerationFailed }

    /// Generate a new discoverable passkey credential for an RP.
    /// Throws if the system CSPRNG is unavailable — an all-zero credential id must never
    /// be produced (consistent with the fail-hard random policy elsewhere in the project).
    static func createCredential(rpId: String, userHandle: Data, userName: String) throws -> (credential: Credential, key: P256.Signing.PrivateKey) {
        let key = P256.Signing.PrivateKey()
        var credId = Data(count: 32)
        let status = credId.withUnsafeMutableBytes { buf -> Int32 in
            guard let base = buf.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, 32, base)
        }
        guard status == errSecSuccess else { throw Fido2Error.randomGenerationFailed }
        let cred = Credential(credentialId: credId, rpId: rpId, userHandle: userHandle,
                              userName: userName, privateKey: key.rawRepresentation, counter: 0)
        return (cred, key)
    }
}
