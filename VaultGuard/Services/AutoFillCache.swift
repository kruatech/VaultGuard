import Foundation
import CryptoKit

/// Minimal credential record shared with the AutoFill extension. Holds only what the
/// extension needs to offer a credential — never tokens, keys, or other session data.
struct AutoFillRecord: Codable {
    let id: String
    let name: String
    let user: String
    let password: String
    let uris: [String]
}

/// Per-account AutoFill cache, deliberately separate from the main app's `VaultCache`.
///
/// Stores an already-decrypted, minimal credential list in the App Group container, sealed
/// with a key DERIVED from the shared vault key payload (which carries a TTL). The extension
/// never reads the main app's `cacheKey`, `encryptedKey`, tokens, or any session secret: when
/// the shared vault key is gone (lock / logout / account removal / local vault close / TTL
/// expiry) the derivation input is gone, so this cache can no longer be opened.
///
/// Derivation is purpose- and scope-separated: HKDF-SHA256 over the shared secret with
/// `info = "VaultGuard AutoFill Cache v1|<accountId>|<kind>"`, so a secret for one
/// account / vault-kind can never open another's cache.
enum AutoFillCache {
    private static let infoPrefix = "VaultGuard AutoFill Cache v1"
    private static let salt = "VaultGuard AutoFill Cache salt v1"

    private static func fileURL(accountId: String) -> URL? {
        guard let dir = directory() else { return nil }
        return dir.appendingPathComponent("autofill-\(accountId).cache")
    }

    /// AutoFill cache directory inside the shared App Group container. No sandbox fallback:
    /// if the group isn't usable the cache simply isn't available.
    private static func directory() -> URL? {
        guard let shared = SharedConfig.appGroupContainerURL else { return nil }
        let dir = shared.appendingPathComponent("VaultGuard", isDirectory: true)
        guard (try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)) != nil else { return nil }
        return dir
    }

    /// HKDF-SHA256 cache key bound to the account id and vault kind, so a secret can never be
    /// reused across accounts or across vault types.
    private static func deriveKey(secret: Data, accountId: String, kind: String) -> SymmetricKey {
        let info = "\(infoPrefix)|\(accountId)|\(kind)"
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: secret),
            salt: Data(salt.utf8),
            info: Data(info.utf8),
            outputByteCount: 32)
    }

    /// Seal and write the records. Returns false on any failure; never leaves partial/plaintext.
    @discardableResult
    static func save(_ records: [AutoFillRecord], secret: Data, accountId: String, kind: String) -> Bool {
        guard let url = fileURL(accountId: accountId) else { return false }
        do {
            let plaintext = try JSONEncoder().encode(records)
            let key = deriveKey(secret: secret, accountId: accountId, kind: kind)
            guard let sealed = try AES.GCM.seal(plaintext, using: key).combined else { return false }
            try sealed.write(to: url, options: [.atomic])
            return true
        } catch {
            Log.fault("autofill cache write failed")
            return false
        }
    }

    /// Outcome of an open attempt, so the extension can map precise locked/empty/error states.
    enum OpenResult {
        case records([AutoFillRecord])
        case missing      // no cache file on disk
        case corrupted    // file present but cannot be opened/decoded (already invalidated)
    }

    /// Open the cache for an account. A wrong/rotated secret, tampering, or corruption all
    /// invalidate the file and return `.corrupted` (fail closed, never silently downgrade).
    static func open(secret: Data, accountId: String, kind: String) -> OpenResult {
        guard let url = fileURL(accountId: accountId),
              FileManager.default.fileExists(atPath: url.path),
              let blob = try? Data(contentsOf: url) else { return .missing }
        let key = deriveKey(secret: secret, accountId: accountId, kind: kind)
        do {
            let box = try AES.GCM.SealedBox(combined: blob)
            let opened = try AES.GCM.open(box, using: key)
            return .records(try JSONDecoder().decode([AutoFillRecord].self, from: opened))
        } catch {
            clear(accountId: accountId)
            return .corrupted
        }
    }

    static func clear(accountId: String) {
        guard let url = fileURL(accountId: accountId) else { return }
        try? FileManager.default.removeItem(at: url)
    }
}
