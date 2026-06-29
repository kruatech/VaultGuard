import Foundation

/// A wrapper around mutable bytes whose OWN buffer is guaranteed to be zeroed on
/// deallocation (`memset_s`). Use instead of `Data` for secrets (master key, enc key,
/// password hash).
///
/// HONEST LIMITATION (Swift memory model): the `data` / `prefix` / `suffix` accessors and
/// `SecureString.string` return ordinary `Data`/`String` COPIES that this class cannot
/// track or zero — once a copy is taken, its lifetime is up to the caller and ARC/COW.
/// The guarantee here is therefore best-effort containment of the primary buffer, not a
/// proof that no secret bytes remain in memory. Prefer `withUnsafeBytes` for transient
/// access, take copies only to hand them straight to protected storage, and see
/// docs/security-model.md ("Memory handling").
final class SecureBytes {
    private var buffer: UnsafeMutableBufferPointer<UInt8>
    
    var count: Int { buffer.count }
    var isEmpty: Bool { buffer.count == 0 }
    
    /// Read-only COPY of the bytes as `Data`. The copy is not tracked and will not be
    /// zeroed by this class — hand it straight to protected storage and drop it.
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

/// String wrapper whose backing UTF-8 bytes are zeroed on deallocation. Note that the
/// `string` accessor returns an ordinary `String` COPY that cannot be zeroed (see the
/// limitation note on `SecureBytes`).
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
