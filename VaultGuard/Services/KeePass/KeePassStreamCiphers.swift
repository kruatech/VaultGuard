import Foundation

// MARK: - KeePass stream ciphers
//
// Чистые Swift-реализации ChaCha20 и Salsa20: в проекте их нет, а CryptoKit даёт лишь
// AEAD ChaCha20Poly1305, не «сырой» поток. Используются ТОЛЬКО на KeePass-пути:
//
// - `ChaCha20Cipher` — RFC 8439 (12-байтный nonce, 32-битный блочный счётчик). Inner
//   random-stream KDBX 4 и опциональный outer-cipher KDBX 4.
// - `Salsa20Cipher` — Salsa20/20 (256-бит ключ, 64-бит nonce, 64-бит счётчик). Inner
//   random-stream KDBX 3.1 (KeePass использует фиксированный IV E830094B97205D2A).
//
// ВАЖНО: гамма НЕПРЕРЫВНА между вызовами process(_:). KeePass inner-stream расходует один
// общий keystream на все Protected-значения подряд, поэтому остаток последнего 64-байтного
// блока буферизуется и используется следующим вызовом (а не начинается заново с границы
// блока). Проверено в KeePassCryptoTests (одиночные вызовы) и в KDBXReaderTests
// (последовательные значения).

@inline(__always) private func rotl32(_ x: UInt32, _ n: UInt32) -> UInt32 {
    (x << n) | (x >> (32 &- n))
}

@inline(__always) private func load32LE(_ p: UnsafePointer<UInt8>, _ i: Int) -> UInt32 {
    UInt32(p[i]) | (UInt32(p[i + 1]) << 8) | (UInt32(p[i + 2]) << 16) | (UInt32(p[i + 3]) << 24)
}

@inline(__always) private func serializeLE(_ blk: [UInt32]) -> [UInt8] {
    var ks = [UInt8](repeating: 0, count: 64)
    for i in 0..<16 {
        ks[i * 4]     = UInt8(blk[i] & 0xff)
        ks[i * 4 + 1] = UInt8((blk[i] >> 8) & 0xff)
        ks[i * 4 + 2] = UInt8((blk[i] >> 16) & 0xff)
        ks[i * 4 + 3] = UInt8((blk[i] >> 24) & 0xff)
    }
    return ks
}

// MARK: ChaCha20 (RFC 8439)

struct ChaCha20Cipher {
    private var state: [UInt32]   // 16 words; word 12 is the 32-bit block counter
    private var ksBuf: [UInt8] = []
    private var ksPos: Int = 0

    /// - Parameters: key 32 bytes; nonce 12 bytes; counter — initial 32-bit block counter.
    init?(key: Data, nonce: Data, counter: UInt32 = 0) {
        guard key.count == 32, nonce.count == 12 else { return nil }
        var s = [UInt32](repeating: 0, count: 16)
        s[0] = 0x6170_7865; s[1] = 0x3320_646e; s[2] = 0x7962_2d32; s[3] = 0x6b20_6574
        key.withUnsafeBytes { raw in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!
            for i in 0..<8 { s[4 + i] = load32LE(p, i * 4) }
        }
        s[12] = counter
        nonce.withUnsafeBytes { raw in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!
            s[13] = load32LE(p, 0); s[14] = load32LE(p, 4); s[15] = load32LE(p, 8)
        }
        state = s
    }

    private static func block(_ s: [UInt32]) -> [UInt32] {
        var x = s
        @inline(__always) func qr(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            x[a] = x[a] &+ x[b]; x[d] ^= x[a]; x[d] = rotl32(x[d], 16)
            x[c] = x[c] &+ x[d]; x[b] ^= x[c]; x[b] = rotl32(x[b], 12)
            x[a] = x[a] &+ x[b]; x[d] ^= x[a]; x[d] = rotl32(x[d], 8)
            x[c] = x[c] &+ x[d]; x[b] ^= x[c]; x[b] = rotl32(x[b], 7)
        }
        for _ in 0..<10 {
            qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
            qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
        }
        for i in 0..<16 { x[i] = x[i] &+ s[i] }
        return x
    }

    private mutating func refill() {
        ksBuf = serializeLE(Self.block(state))
        // RFC 8439 uses a 32-bit block counter: the keystream is 2^32 * 64 B = 256 GiB before
        // the counter wraps and the stream would repeat. A KDBX payload can never approach
        // that, but keep this in mind if the cipher is ever reused for arbitrary-size data.
        state[12] = state[12] &+ 1
        ksPos = 0
    }

    /// XOR the (continuous) keystream over `data`. Leftover keystream is kept for the next call.
    mutating func process(_ data: Data) -> Data {
        let inp = [UInt8](data)
        guard !inp.isEmpty else { return Data() }
        var out = [UInt8](repeating: 0, count: inp.count)
        for i in 0..<inp.count {
            if ksPos == ksBuf.count { refill() }
            out[i] = inp[i] ^ ksBuf[ksPos]
            ksPos += 1
        }
        return Data(out)
    }
}

// MARK: Salsa20/20

struct Salsa20Cipher {
    private var state: [UInt32]   // words 8 (low) and 9 (high) form the 64-bit counter
    private var ksBuf: [UInt8] = []
    private var ksPos: Int = 0

    /// - Parameters: key 32 bytes; nonce 8 bytes; counter — initial 64-bit block counter.
    init?(key: Data, nonce: Data, counter: UInt64 = 0) {
        guard key.count == 32, nonce.count == 8 else { return nil }
        var s = [UInt32](repeating: 0, count: 16)
        s[0] = 0x6170_7865; s[5] = 0x3320_646e; s[10] = 0x7962_2d32; s[15] = 0x6b20_6574
        key.withUnsafeBytes { raw in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!
            s[1] = load32LE(p, 0);  s[2] = load32LE(p, 4);  s[3] = load32LE(p, 8);  s[4] = load32LE(p, 12)
            s[11] = load32LE(p, 16); s[12] = load32LE(p, 20); s[13] = load32LE(p, 24); s[14] = load32LE(p, 28)
        }
        nonce.withUnsafeBytes { raw in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!
            s[6] = load32LE(p, 0); s[7] = load32LE(p, 4)
        }
        s[8] = UInt32(counter & 0xffff_ffff)
        s[9] = UInt32((counter >> 32) & 0xffff_ffff)
        state = s
    }

    private static func block(_ s: [UInt32]) -> [UInt32] {
        var x = s
        @inline(__always) func qr(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            x[b] ^= rotl32(x[a] &+ x[d], 7)
            x[c] ^= rotl32(x[b] &+ x[a], 9)
            x[d] ^= rotl32(x[c] &+ x[b], 13)
            x[a] ^= rotl32(x[d] &+ x[c], 18)
        }
        for _ in 0..<10 {
            qr(0, 4, 8, 12); qr(5, 9, 13, 1); qr(10, 14, 2, 6); qr(15, 3, 7, 11)   // column
            qr(0, 1, 2, 3); qr(5, 6, 7, 4); qr(10, 11, 8, 9); qr(15, 12, 13, 14)   // row
        }
        for i in 0..<16 { x[i] = x[i] &+ s[i] }
        return x
    }

    private mutating func refill() {
        ksBuf = serializeLE(Self.block(state))
        state[8] = state[8] &+ 1
        if state[8] == 0 { state[9] = state[9] &+ 1 }
        ksPos = 0
    }

    /// XOR the (continuous) keystream over `data`. Leftover keystream is kept for the next call.
    mutating func process(_ data: Data) -> Data {
        let inp = [UInt8](data)
        guard !inp.isEmpty else { return Data() }
        var out = [UInt8](repeating: 0, count: inp.count)
        for i in 0..<inp.count {
            if ksPos == ksBuf.count { refill() }
            out[i] = inp[i] ^ ksBuf[ksPos]
            ksPos += 1
        }
        return Data(out)
    }
}
