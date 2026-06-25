import Foundation
import CryptoKit
import Security

/// Encrypted on-disk cache of the last successful vault sync.
///
/// Enables fast startup and offline read access. The raw sync payload is sealed with
/// AES-GCM under a random 32-byte key kept in the Keychain, so the file on disk is opaque
/// at rest. The cipher fields inside remain Bitwarden-encrypted as well, so the cache never
/// exposes plaintext vault data even if the GCM key leaks.
///
/// Each account gets its own cache file (`vault-<accountId>.cache`) sealed with its own
/// per-account key, so accounts never share offline data. Create one with `forAccount(_:)`.
///
final class VaultCache {
    static func forAccount(_ id: String) -> VaultCache { VaultCache(accountId: id) }

    private let keychain = KeychainService.shared
    private let accountId: String

    init(accountId: String) { self.accountId = accountId }

    private var fileName: String { "vault-\(accountId).cache" }

    private var fileURL: URL? {
        guard let dir = Self.cacheDirectory() else { return nil }
        return dir.appendingPathComponent(fileName)
    }

    /// Resolves the cache directory. Strict: requires the shared App Group container so the
    /// AutoFill extension can read the same cache. Returns `nil` when the group isn't usable
    /// (the cache is simply not used — no silent sandbox fallback). Builds compiled with
    /// `DEBUG_APPGROUP_FALLBACK` fall back to the local sandbox with a logged fault.
    private static func cacheDirectory() -> URL? {
        let appDirName = "VaultGuard"
        if let shared = SharedConfig.appGroupContainerURL {
            let dir = shared.appendingPathComponent(appDirName, isDirectory: true)
            if (try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)) != nil {
                return dir
            }
        }
        #if DEBUG_APPGROUP_FALLBACK
        Log.fault("App Group container unavailable — using local sandbox (DEBUG_APPGROUP_FALLBACK)")
        if let base = try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true) {
            let dir = base.appendingPathComponent(appDirName, isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            return dir
        }
        #endif
        return nil
    }

    func save(_ data: Data) {
        guard let url = fileURL, let key = cacheKey() else { return }
        do {
            let sealed = try AES.GCM.seal(data, using: key)
            guard let combined = sealed.combined else { return }
            // .completeFileProtection is iOS-only; on macOS it can fail the write.
            // The payload is already sealed with AES-GCM, so atomic write is enough.
            try combined.write(to: url, options: [.atomic])
        } catch {
            Log.app("vault cache write failed")
        }
    }

    func load() -> Data? {
        guard let url = fileURL,
              FileManager.default.fileExists(atPath: url.path),
              let key = existingCacheKey(),
              let blob = try? Data(contentsOf: url) else { return nil }
        do {
            let box = try AES.GCM.SealedBox(combined: blob)
            return try AES.GCM.open(box, using: key)
        } catch {
            Log.app("vault cache read failed")
            return nil
        }
    }

    func clear() {
        if let url = fileURL { try? FileManager.default.removeItem(at: url) }
        try? setStoredCacheKey(nil)
    }

    // MARK: - Key management

    /// Base64 cache key for this account.
    private func storedCacheKey() -> String? { keychain.account(accountId).cacheKey }

    private func setStoredCacheKey(_ value: String?) throws {
        try keychain.account(accountId).setCacheKey(value)
    }

    private func cacheKey() -> SymmetricKey? {
        if let existing = existingCacheKey() { return existing }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &bytes) == errSecSuccess else { return nil }
        let data = Data(bytes)
        // The cache is an optimization; if its key can't be persisted, skip caching rather
        // than failing the operation that triggered it.
        do { try setStoredCacheKey(data.base64EncodedString()) }
        catch { Log.fault("vault cache key store failed"); return nil }
        return SymmetricKey(data: data)
    }

    private func existingCacheKey() -> SymmetricKey? {
        guard let b64 = storedCacheKey(), let data = Data(base64Encoded: b64) else { return nil }
        return SymmetricKey(data: data)
    }
}
