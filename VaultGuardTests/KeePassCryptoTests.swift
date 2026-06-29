import XCTest
import Foundation

/// Reference-vector tests for the KeePass crypto primitives. The expected values were
/// generated with pycryptodome (ChaCha20 / Salsa20 / AES-256-ECB) and argon2-cffi
/// (Argon2 v0x13), so a transcription bug in the Swift implementations fails here.
final class KeePassCryptoTests: XCTestCase {

    // MARK: helpers
    private func data(hex s: String) -> Data {
        var d = Data(); var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            d.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return d
    }
    private func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    private let key32 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

    // MARK: ChaCha20 (RFC 8439)

    func testChaCha20KeystreamBlock0() {
        var c = ChaCha20Cipher(key: data(hex: key32), nonce: data(hex: "000000090000004a00000000"), counter: 0)!
        let ks = c.process(Data(count: 64))
        XCTAssertEqual(hex(ks),
            "8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582" +
            "cd9833367d0a54d57d3c9e998f490ee69ca34c1ff9e939a75584c52d690a35d4")
    }

    func testChaCha20KeystreamBlock1() {
        var c = ChaCha20Cipher(key: data(hex: key32), nonce: data(hex: "000000090000004a00000000"), counter: 1)!
        let ks = c.process(Data(count: 64))
        XCTAssertEqual(hex(ks),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e" +
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
    }

    func testChaCha20EncryptAcrossBlocks() {
        // 80-byte plaintext spanning two keystream blocks, starting at counter 0.
        let pt = Data((0..<80).map { UInt8($0) })
        var c = ChaCha20Cipher(key: data(hex: key32), nonce: data(hex: "000000090000004a00000000"), counter: 0)!
        let ct = c.process(pt)
        XCTAssertEqual(hex(ct),
            "8add93fe9bf1f6f21306a75bf318d838f41fefb112d944d09bbe581b4c210b9d" +
            "edb91115592f72f25515b4b2a36420c9ac927e2ccddc0f906dbdff1655370beb" +
            "50b0a5a7957e1f5218469754ef6d3f8b")
        // round-trip
        var d = ChaCha20Cipher(key: data(hex: key32), nonce: data(hex: "000000090000004a00000000"), counter: 0)!
        XCTAssertEqual(d.process(ct), pt)
    }

    // MARK: Salsa20/20

    func testSalsa20KeystreamBlock0() {
        var s = Salsa20Cipher(key: data(hex: key32), nonce: data(hex: "0001020304050607"), counter: 0)!
        let ks = s.process(Data(count: 64))
        XCTAssertEqual(hex(ks),
            "2ead0f5f185729ced672b3a928e454f72fdb44a87b9cd8d219e4ec14aef9c6bc" +
            "77bf057f5659d7753848f8d3fe769ca5fdd8057d46326990e5f136e2fcb7bb7c")
    }

    func testSalsa20KeePassStyle() {
        // key = SHA256("protected-stream-key-example"); KeePass fixed IV E830094B97205D2A.
        let key = data(hex: "070374343b1b43defb385a34d21a45f6e062df87b5c268abd49857696d565702")
        var s = Salsa20Cipher(key: key, nonce: data(hex: "e830094b97205d2a"), counter: 0)!
        let ks = s.process(Data(count: 32))
        XCTAssertEqual(hex(ks), "eb8ab8cf869875f4c389326b6aed4d9ec0e224066924fc6be1f2a41cee6325dd")
    }

    // MARK: AES-256-ECB

    func testAesEcb() throws {
        let ct = try KeePassKDF.aesEcbEncrypt(data(hex: "000102030405060708090a0b0c0d0e0f"),
                                              key: data(hex: key32))
        XCTAssertEqual(hex(ct), "5a6e045708fb7196f02e553d02c3a692")
    }

    // MARK: AES-KDF (KDBX 3.1)

    func testAesKdfTransform() throws {
        let composite = data(hex: "ad1e26066637d18f500318563e09c716fe3b0f6cf646ce32fb4c79f995aa15f5")
        let seed = data(hex: String(repeating: "11", count: 32))
        let out = try KeePassKDF.aesKdfTransform(compositeKey: composite, seed: seed, rounds: 600)
        XCTAssertEqual(hex(out), "902141f6ae3f211bdae57fbb6abf2011607867138afe86ec9ea9a74c6ccbd8c9")
    }

    // MARK: Argon2 (KDBX 4), version 0x13

    func testArgon2d() throws {
        let pwd = data(hex: "ad1e26066637d18f500318563e09c716fe3b0f6cf646ce32fb4c79f995aa15f5")
        let salt = data(hex: "736f6d6573616c742d31366279746573")  // "somesalt-16bytes"
        let out = try KeePassKDF.argon2(compositeKey: pwd, salt: salt, variant: .d,
                                        iterations: 3, memoryBytes: 64 * 1024, parallelism: 1, version: 0x13)
        XCTAssertEqual(hex(out), "5059dba89bb2a2de5bd33e20e80fa28ddeb295cd3399fe4813e02029291d7501")
    }

    func testArgon2id() throws {
        let pwd = data(hex: "ad1e26066637d18f500318563e09c716fe3b0f6cf646ce32fb4c79f995aa15f5")
        let salt = data(hex: "736f6d6573616c742d31366279746573")
        let out = try KeePassKDF.argon2(compositeKey: pwd, salt: salt, variant: .id,
                                        iterations: 3, memoryBytes: 64 * 1024, parallelism: 1, version: 0x13)
        XCTAssertEqual(hex(out), "d0406d407c2064b9758e4735127e0af25f6613ee99e8e0d1b2f194366ac76e6b")
    }

    func testArgon2RejectsSecret() {
        let pwd = Data(count: 32)
        XCTAssertThrowsError(try KeePassKDF.argon2(compositeKey: pwd, salt: Data(count: 16), variant: .d,
                                                   iterations: 1, memoryBytes: 8 * 1024, parallelism: 1,
                                                   version: 0x13, secret: Data([1, 2, 3])))
    }
}
