import Foundation
import Security
import LocalAuthentication

/// Low-level Keychain store.
///
/// Storage is split into two namespaces:
/// - **Global** items (`deviceIdentifier`, the account index, the active-account
///   pointer) are shared across all accounts and live under fixed keychain accounts.
/// - **Per-account** secrets (tokens, encrypted key, cache key, KDF params,
///   server/email, and biometric-unlock key material) live under keys suffixed with
///   the owning `accountId`, so several signed-in accounts never collide. The master
///   password itself is never stored; the legacy `masterPassword` key is kept only so
///   old builds can be wiped safely.
///
/// Per-account secrets are reached through `account(_:)`, which returns a thin scoped
/// view (`KeychainAccountStore`). Biometric helpers and global values stay on the
/// service itself.
final class KeychainService {
    static let shared = KeychainService()

    private let serviceName = "com.vaultguard.macos"

    // MARK: - Key namespaces

    /// Fixed, account-independent keychain accounts.
    private enum GlobalKey {
        static let deviceIdentifier = "deviceIdentifier"
        static let accountIndex = "accountIndex"      // JSON blob owned by AccountManager
        static let activeAccountId = "activeAccountId"
    }

    /// Per-account secret fields. The real keychain account is `"<rawValue>.<accountId>"`.
    fileprivate enum AccountField: String, CaseIterable {
        case masterPassword, serverURL, email
        case accessToken, refreshToken, encryptedKey
        case kdfIterations, kdfType, kdfMemory, kdfParallelism
        case cacheKey
    }

    // MARK: - Touch ID / Biometric

    var isBiometricAvailable: Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    var biometricType: String {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return L10n.Biometric.password.localized
        }
        switch context.biometryType {
        case .touchID: return "Touch ID"
        case .faceID: return "Face ID"
        case .opticID: return "Optic ID"
        default: return L10n.Biometric.generic.localized
        }
    }

    func authenticateWithBiometric(reason: String = L10n.Biometric.unlockReason.localized) async throws -> Bool {
        let context = LAContext()
        context.localizedFallbackTitle = L10n.Biometric.enterPassword.localized
        do {
            return try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
        } catch let e as LAError {
            // Map the system LAError (localized in the OS language) to our own
            // app-language message, so the error follows the app's selected language.
            throw BiometricError.from(e)
        }
    }

    // MARK: - Per-account scoped store

    /// A thin, value-typed view of one account's secrets. Cheap to create; all access
    /// goes straight to the Keychain under namespaced keys.
    func account(_ accountId: String) -> KeychainAccountStore {
        KeychainAccountStore(accountId: accountId, service: self)
    }

    // MARK: - Per-account biometric unlock (stores the vault key, never the master password)

    /// Persist the biometric-unlock secret for an account: the raw user (vault) key plus the
    /// master-password hash, sealed behind a biometric access control. The OS releases it only
    /// after a successful biometric check bound to the item itself, so the app never holds the
    /// master password. Also clears any legacy raw master-password item for this account.
    func saveBiometricUnlock(userKey: Data, passwordHash: String, accountId: String) throws {
        let payload = BiometricUnlockPayload(userKey: userKey.base64EncodedString(), passwordHash: passwordHash)
        let data = try JSONEncoder().encode(payload)
        let access = try makeBiometricAccessControl()
        try saveProtected(key: biometricKey(accountId), data: data, accessControl: access)
        // Plaintext presence marker (no secret): lets the unlock gate check availability
        // without triggering a biometric prompt, since probing the protected item itself
        // is unreliable on macOS. Essential — if it can't be written, biometric isn't usable.
        try save(key: biometricMarker(accountId), value: "1")
        attempt("clear legacy master password") { try deleteItem(key: accountKey(.masterPassword, accountId)) }
    }

    /// Read the biometric-unlock secret, prompting Touch ID / Face ID via the item's access
    /// control. Returns nil when nothing is stored.
    func getBiometricUnlock(accountId: String,
                            reason: String = L10n.Biometric.unlockReason.localized)
        async throws -> (userKey: Data, passwordHash: String)?
    {
        guard hasBiometricUnlock(accountId: accountId) else { return nil }
        let context = LAContext()
        context.localizedFallbackTitle = L10n.Biometric.enterPassword.localized
        let access = try makeBiometricAccessControl()
        do {
            // Pre-authenticate the access control so the keychain read below doesn't re-prompt.
            _ = try await context.evaluateAccessControl(access, operation: .useItem, localizedReason: reason)
        } catch let e as LAError {
            throw BiometricError.from(e)
        }
        guard let data = try loadProtected(key: biometricKey(accountId), context: context) else { return nil }
        let payload = try JSONDecoder().decode(BiometricUnlockPayload.self, from: data)
        guard let key = Data(base64Encoded: payload.userKey) else { throw KeychainError.loadFailed(errSecDecode) }
        return (key, payload.passwordHash)
    }

    func hasBiometricUnlock(accountId: String) -> Bool {
        existsWithoutUI(biometricMarker(accountId))
    }

    /// Forget the biometric-unlock secret for this account (and any legacy raw master
    /// password). Attempts every deletion; throws if any genuinely failed so callers can
    /// surface an incomplete wipe (errSecItemNotFound counts as success).
    func clearBiometricUnlock(accountId: String) throws {
        var firstError: Error?
        func del(_ what: String, _ op: () throws -> Void) {
            do { try op() } catch { logKeychainFault(what, error); firstError = firstError ?? error }
        }
        del("delete biometric secret") { try deleteProtected(key: biometricKey(accountId)) }
        del("delete biometric marker") { try deleteItem(key: biometricMarker(accountId)) }
        del("delete legacy master password") { try deleteItem(key: accountKey(.masterPassword, accountId)) }
        if let firstError { throw firstError }
    }

    // MARK: - Shared vault key (AutoFill, Variant B)

    /// Publish the account's vault key for the AutoFill extension while the vault is unlocked.
    /// Stored WhenUnlockedThisDeviceOnly with no biometric control, in the shared keychain
    /// access group (the single entitled group is the default), so the extension can read it
    /// without a prompt. Removed on lock/logout via `clearSharedVaultKey`.
    func shareVaultKey(_ userKey: Data, accountId: String) {
        attempt("share vault key") { try save(key: sharedVaultKeyName(accountId), value: userKey.base64EncodedString()) }
    }

    /// Read the shared vault key, if the main app currently has the account unlocked.
    func sharedVaultKey(accountId: String) -> Data? {
        guard let b64 = try? load(key: sharedVaultKeyName(accountId)),
              let data = Data(base64Encoded: b64) else { return nil }
        return data
    }

    func clearSharedVaultKey(accountId: String) throws {
        try deleteItem(key: sharedVaultKeyName(accountId))
    }

    private func sharedVaultKeyName(_ accountId: String) -> String { "sharedVaultKey.\(accountId)" }

    // MARK: - Global values

    var deviceIdentifier: String? {
        get { try? load(key: GlobalKey.deviceIdentifier) }
        set { setOrDelete(key: GlobalKey.deviceIdentifier, value: newValue) }
    }

    /// JSON-encoded account index, owned and (de)serialized by `AccountManager`.
    var accountIndexJSON: String? {
        get { try? load(key: GlobalKey.accountIndex) }
        set { setOrDelete(key: GlobalKey.accountIndex, value: newValue) }
    }

    /// Identifier of the account that should be unlocked on launch / after switch.
    var activeAccountId: String? {
        get { try? load(key: GlobalKey.activeAccountId) }
        set { setOrDelete(key: GlobalKey.activeAccountId, value: newValue) }
    }

    // MARK: - Per-account teardown

    /// Wipe every secret belonging to one account (used by "log out this account"):
    /// per-field secrets, the biometric-unlock secret + marker, and the shared vault key.
    /// Attempts all; throws if any genuinely failed so logout can report an incomplete wipe.
    func clearAccount(_ accountId: String) throws {
        var firstError: Error?
        func del(_ what: String, _ op: () throws -> Void) {
            do { try op() } catch { logKeychainFault(what, error); firstError = firstError ?? error }
        }
        for field in AccountField.allCases {
            del("delete \(field.rawValue)") { try deleteItem(key: accountKey(field, accountId)) }
        }
        del("delete biometric secret") { try deleteProtected(key: biometricKey(accountId)) }
        del("delete biometric marker") { try deleteItem(key: biometricMarker(accountId)) }
        del("delete shared vault key") { try deleteItem(key: sharedVaultKeyName(accountId)) }
        if let firstError { throw firstError }
    }

    /// Wipe all listed accounts and the global index + active pointer.
    /// `deviceIdentifier` is intentionally preserved so the device keeps a stable id.
    func clearAllAccounts(_ accountIds: [String]) throws {
        var firstError: Error?
        for id in accountIds {
            do { try clearAccount(id) } catch { firstError = firstError ?? error }
        }
        func del(_ what: String, _ op: () throws -> Void) {
            do { try op() } catch { logKeychainFault(what, error); firstError = firstError ?? error }
        }
        del("delete account index") { try deleteItem(key: GlobalKey.accountIndex) }
        del("delete active account id") { try deleteItem(key: GlobalKey.activeAccountId) }
        if let firstError { throw firstError }
    }

    // MARK: - Field helpers (fileprivate, used by KeychainAccountStore)

    fileprivate func accountKey(_ field: AccountField, _ accountId: String) -> String {
        "\(field.rawValue).\(accountId)"
    }

    fileprivate func loadField(_ field: AccountField, _ accountId: String) -> String? {
        try? load(key: accountKey(field, accountId))
    }

    /// Throwing per-account field write used by the store's critical setters. A genuine
    /// failure propagates so the caller (login/session establishment) can fail in a
    /// controlled way instead of silently looking successful.
    fileprivate func writeField(_ field: AccountField, _ accountId: String, _ value: String?) throws {
        if let value { try save(key: accountKey(field, accountId), value: value) }
        else { try deleteItem(key: accountKey(field, accountId)) }
    }

    fileprivate func intField(_ field: AccountField, _ accountId: String) -> Int? {
        loadField(field, accountId).flatMap(Int.init)
    }

    // MARK: - Helpers

    private func intValue(for key: String) -> Int? {
        guard let str = try? load(key: key) else { return nil }
        return Int(str)
    }

    private func setOrDelete(key: String, value: String?) {
        if let value {
            try? save(key: key, value: value)
        } else {
            try? deleteItem(key: key)
        }
    }

    /// Log a non-sensitive Keychain failure (operation label + OSStatus only).
    private func logKeychainFault(_ what: String, _ error: Error) {
        let status = (error as? KeychainError).map { String($0.status) } ?? "?"
        Log.fault("keychain \(what) failed: status \(status)")
    }

    /// Run a best-effort Keychain operation whose failure must not be silent but also must
    /// not propagate (optional/convenience writes). Logs a fault and asserts in Debug.
    @discardableResult
    private func attempt(_ what: String, _ op: () throws -> Void) -> Bool {
        do { try op(); return true }
        catch {
            logKeychainFault(what, error)
            assertionFailure("keychain \(what) failed: \(error)")
            return false
        }
    }

    /// Existence probe that never triggers an authentication UI prompt.
    private func existsWithoutUI(_ key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: false,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip,
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    // MARK: - Biometric unlock storage (data-protection keychain + access control)

    /// Namespaced keychain account for an account's biometric-unlock secret.
    private func biometricKey(_ accountId: String) -> String { "biometricUnlock.\(accountId)" }

    /// Namespaced plaintext marker recording that biometric unlock is configured.
    private func biometricMarker(_ accountId: String) -> String { "biometricUnlockSet.\(accountId)" }

    /// Access control requiring the current biometric set, device-only. Re-enrolling or
    /// changing the biometric set invalidates the stored secret.
    private func makeBiometricAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet],
            &error
        ) else {
            throw KeychainError.saveFailed(errSecParam)
        }
        return access
    }

    /// Add an item to the data-protection keychain guarded by `accessControl`.
    private func saveProtected(key: String, data: Data, accessControl: SecAccessControl) throws {
        try? deleteProtected(key: key)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: accessControl,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.saveFailed(status) }
    }

    /// Read a data-protection-keychain item using a pre-authenticated context.
    private func loadProtected(key: String, context: LAContext) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess: return result as? Data
        case errSecItemNotFound: return nil
        default: throw KeychainError.loadFailed(status)
        }
    }

    private func deleteProtected(key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }

    /// Existence probe for a protected item that never shows an auth prompt.
    private func existsProtected(_ key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: false,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip,
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    // MARK: - Low-level Keychain Operations

    private func save(key: String, value: String, accessControl: SecAccessControl? = nil, context: LAContext? = nil) throws {
        guard let data = value.data(using: .utf8) else { return }

        try? deleteItem(key: key)

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        if let ac = accessControl {
            query[kSecAttrAccessControl as String] = ac
            query.removeValue(forKey: kSecAttrAccessible as String)
        }
        if let ctx = context {
            query[kSecUseAuthenticationContext as String] = ctx
        }

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }

    private func load(key: String, context: LAContext? = nil) throws -> String? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let ctx = context {
            query[kSecUseAuthenticationContext as String] = ctx
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { return nil }
            return String(data: data, encoding: .utf8)
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.loadFailed(status)
        }
    }

    private func deleteItem(key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: key,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }
}

// MARK: - Per-account scoped view

/// Value-typed accessor for one account's secrets. Setters are `nonmutating` because
/// the backing storage is the Keychain, not the struct itself.
struct KeychainAccountStore {
    let accountId: String
    fileprivate let service: KeychainService

    var serverURL: String? { service.loadField(.serverURL, accountId) }
    func setServerURL(_ value: String?) throws { try service.writeField(.serverURL, accountId, value) }

    var email: String? { service.loadField(.email, accountId) }
    func setEmail(_ value: String?) throws { try service.writeField(.email, accountId, value) }

    var accessToken: String? { service.loadField(.accessToken, accountId) }
    func setAccessToken(_ value: String?) throws { try service.writeField(.accessToken, accountId, value) }

    var refreshToken: String? { service.loadField(.refreshToken, accountId) }
    func setRefreshToken(_ value: String?) throws { try service.writeField(.refreshToken, accountId, value) }

    var encryptedKey: String? { service.loadField(.encryptedKey, accountId) }
    func setEncryptedKey(_ value: String?) throws { try service.writeField(.encryptedKey, accountId, value) }

    var kdfIterations: Int? { service.intField(.kdfIterations, accountId) }
    var kdfType: Int? { service.intField(.kdfType, accountId) }
    var kdfMemory: Int? { service.intField(.kdfMemory, accountId) }
    var kdfParallelism: Int? { service.intField(.kdfParallelism, accountId) }
    /// Persist all KDF parameters together (used at login).
    func setKdf(type: Int?, iterations: Int?, memory: Int?, parallelism: Int?) throws {
        try service.writeField(.kdfType, accountId, type.map(String.init))
        try service.writeField(.kdfIterations, accountId, iterations.map(String.init))
        try service.writeField(.kdfMemory, accountId, memory.map(String.init))
        try service.writeField(.kdfParallelism, accountId, parallelism.map(String.init))
    }

    /// Random key (Base64) sealing this account's offline vault cache at rest.
    var cacheKey: String? { service.loadField(.cacheKey, accountId) }
    func setCacheKey(_ value: String?) throws { try service.writeField(.cacheKey, accountId, value) }

    // Biometric unlock stores the vault key (+ master-password hash), never the password.
    func saveBiometricUnlock(userKey: Data, passwordHash: String) throws {
        try service.saveBiometricUnlock(userKey: userKey, passwordHash: passwordHash, accountId: accountId)
    }
    func getBiometricUnlock(reason: String = L10n.Biometric.unlockReason.localized) async throws -> (userKey: Data, passwordHash: String)? {
        try await service.getBiometricUnlock(accountId: accountId, reason: reason)
    }
    var hasBiometricUnlock: Bool { service.hasBiometricUnlock(accountId: accountId) }
    func clearBiometricUnlock() throws { try service.clearBiometricUnlock(accountId: accountId) }

    /// Wipe every secret for this account.
    func clear() throws { try service.clearAccount(accountId) }
}

/// On-disk shape of the biometric-unlock secret (base64 user key + master-password hash).
private struct BiometricUnlockPayload: Codable {
    let userKey: String
    let passwordHash: String
}

enum KeychainError: LocalizedError {
    case saveFailed(OSStatus)
    case loadFailed(OSStatus)
    case deleteFailed(OSStatus)

    /// The underlying OSStatus (non-sensitive), for diagnostics/logging.
    var status: OSStatus {
        switch self {
        case .saveFailed(let s), .loadFailed(let s), .deleteFailed(let s): return s
        }
    }

    var errorDescription: String? {
        switch self {
        case .saveFailed(let s): return "\(L10n.Keychain.saveError.localized): \(s)"
        case .loadFailed(let s): return "\(L10n.Keychain.loadError.localized): \(s)"
        case .deleteFailed(let s): return "\(L10n.Keychain.deleteError.localized): \(s)"
        }
    }
}

/// App-language wrapper for LocalAuthentication errors (LAError is OS-language localized).
enum BiometricError: LocalizedError {
    case cancelled
    case failed
    case unavailable
    case other(String)

    var errorDescription: String? {
        switch self {
        case .cancelled: return L10n.Biometric.cancelled.localized
        case .failed: return L10n.Biometric.failed.localized
        case .unavailable: return L10n.Biometric.unavailable.localized
        case .other(let m): return m
        }
    }

    static func from(_ e: LAError) -> BiometricError {
        switch e.code {
        case .userCancel, .appCancel, .systemCancel, .userFallback: return .cancelled
        case .authenticationFailed: return .failed
        case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout, .passcodeNotSet: return .unavailable
        default: return .other(e.localizedDescription)
        }
    }
}
