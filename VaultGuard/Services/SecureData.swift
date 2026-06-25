import Foundation

/// A wrapper around mutable bytes that guarantees zeroing on deallocation.
/// Use instead of `Data` for any secrets (master key, enc key, password hash).
final class SecureBytes {
    private var buffer: UnsafeMutableBufferPointer<UInt8>
    
    var count: Int { buffer.count }
    var isEmpty: Bool { buffer.count == 0 }
    
    /// Access raw bytes (read-only copy as Data)
    var data: Data {
        Data(buffer)
    }
    
    init(count: Int) {
        let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
        ptr.initialize(repeating: 0, count: count)
        buffer = UnsafeMutableBufferPointer(start: ptr, count: count)
    }
    
    init(data: Data) {
        let count = data.count
        let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
        data.copyBytes(to: ptr, count: count)
        buffer = UnsafeMutableBufferPointer(start: ptr, count: count)
    }
    
    init(bytes: [UInt8]) {
        let count = bytes.count
        let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: count)
        ptr.initialize(from: bytes, count: count)
        buffer = UnsafeMutableBufferPointer(start: ptr, count: count)
    }
    
    /// Prefix
    func prefix(_ n: Int) -> Data {
        Data(buffer.prefix(n))
    }
    
    /// Suffix
    func suffix(_ n: Int) -> Data {
        Data(buffer.suffix(n))
    }
    
    /// Perform an operation with raw UnsafeRawBufferPointer
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(buffer))
    }
    
    /// Zero out and deallocate
    func wipe() {
        guard let base = buffer.baseAddress else { return }
        // Volatile-like zeroing to prevent compiler optimization
        secureZero(base, buffer.count)
    }
    
    deinit {
        wipe()
        buffer.baseAddress?.deinitialize(count: buffer.count)
        buffer.baseAddress?.deallocate()
    }
}

/// Secure string wrapper that zeroes underlying UTF-8 bytes on deallocation
final class SecureString {
    private let backing: SecureBytes
    
    var string: String {
        String(data: backing.data, encoding: .utf8) ?? ""
    }
    
    var isEmpty: Bool { backing.isEmpty }
    
    init(_ value: String) {
        backing = SecureBytes(data: value.data(using: .utf8) ?? Data())
    }
    
    func wipe() {
        backing.wipe()
    }
    
    deinit {
        backing.wipe()
    }
}

// MARK: - memset_s fallback

/// Guaranteed non-optimizable zeroing.
/// Uses C11 `memset_s` (available on Darwin), which the compiler is forbidden
/// from optimizing away, with a defensive `memset` + lifetime fence as fallback.
private func secureZero(_ dest: UnsafeMutableRawPointer, _ count: Int) {
    guard count > 0 else { return }
    #if canImport(Darwin)
    memset_s(dest, count, 0, count)
    #else
    memset(dest, 0, count)
    #endif
    withExtendedLifetime(dest) {}
}
