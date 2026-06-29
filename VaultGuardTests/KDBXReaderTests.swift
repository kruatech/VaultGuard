import XCTest
import Foundation
import CryptoKit

/// End-to-end test of the KDBX 4 container reader against a real KeePassXC file
/// (AES-256-CBC outer, gzip, Argon2d). Diagnostic-grade: every step has a message so a
/// failure names exactly where the byte-level divergence is.
final class KDBXReaderTests: XCTestCase {

    private let fixtureB64 =
        "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"

    private var fixture: Data { Data(base64Encoded: fixtureB64)! }

    private func hexData(_ s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex { let j = s.index(i, offsetBy: 2); d.append(UInt8(s[i..<j], radix: 16)!); i = j }
        return d
    }
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    private func sha256Hex(_ d: Data) -> String { hex(Data(SHA256.hash(data: d))) }

    // Ground truth (pykeepass / pycryptodome / argon2-cffi)
    private let saltHex = "7839e86543e0449b3d6cc46b95b4bbab7d519c7eb01d9cf59d64d82f6ab1a15f"
    private let compositeHex = "1bbfc37c1ad8e131b25747e9c1e0ccdffeeb1e946f1e8949d40717834cde2dc4"
    private let transformedHex = "2135906ee68b36aa473638bb441355cff065f194924a67261e4fcdb1402e5759"
    private let xmlSha = "ff0a9187d297bf13864da096bda36e0b82a16f3ce38e1cd151a11535563b920c"

    // MARK: composite key (fast)

    func testCompositeKey() {
        XCTAssertEqual(hex(KDBXReader.compositeKey(password: "test-password", keyfile: nil)), compositeHex)
    }

    // MARK: isolate Argon2 with the fixture's exact params (heavy)

    func testArgon2FixtureParams() throws {
        let composite = hexData(compositeHex)
        let out = try KeePassKDF.argon2(compositeKey: composite, salt: hexData(saltHex), variant: .d,
                                        iterations: 14, memoryBytes: 67_108_864, parallelism: 2, version: 19)
        XCTAssertEqual(hex(out), transformedHex, "Argon2 transformed-key mismatch (KDF/params bug)")
    }

    // MARK: full unlock, surfacing the exact failure point (heavy)

    func testUnlockDiagnostic() throws {
        let db: KDBXDatabase
        do {
            db = try KDBXReader.unlock(data: fixture, password: "test-password")
        } catch {
            XCTFail("unlock threw: \(error)")
            return
        }
        XCTAssertEqual(db.innerStreamID, 3, "innerStreamID")
        XCTAssertEqual(db.innerStreamKey.count, 64, "innerStreamKey length")
        XCTAssertEqual(sha256Hex(db.xml), xmlSha, "decrypted XML sha256")

        let stream = try XCTUnwrap(KDBXProtectedStream(streamID: db.innerStreamID, key: db.innerStreamKey))
        XCTAssertEqual(stream.decrypt("sreEu4J52/pmtCU="), "S3cr3t!Pass", "protected value #1")
        XCTAssertEqual(stream.decrypt("Cau+CETusA=="), "hunter2", "protected value #2")
    }

    // MARK: wrong password (heavy)

    func testWrongPasswordThrows() {
        XCTAssertThrowsError(try KDBXReader.unlock(data: fixture, password: "nope")) { error in
            guard case KDBXError.wrongCredentials = error else {
                return XCTFail("expected wrongCredentials, got \(error)")
            }
        }
    }
}
