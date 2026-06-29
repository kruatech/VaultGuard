import Foundation

/// Identifiers shared between the main app and the AutoFill extension.
///
/// Keychain items are split across two access groups: a SHARED group readable by both the
/// app and the AutoFill extension (minimal AutoFill state only), and an APP-PRIVATE group
/// the extension is not entitled to (tokens, encrypted key, cache key, account index, …).
/// `KeychainService` sets `kSecAttrAccessGroup` explicitly on every item so placement is
/// deterministic. See `sharedKeychainGroup` / `privateKeychainGroup` below.
///
/// `appGroupIdentifier` is the App Group container for the shared, encrypted vault cache.
/// Access is strict: if the group isn't provisioned/usable, `VaultCache` does NOT fall back
/// to the local sandbox (except in builds compiled with `DEBUG_APPGROUP_FALLBACK`), and the
/// main app surfaces a configuration error so the misconfiguration is visible.
enum SharedConfig {
    /// App Group for the shared, encrypted vault cache, shared with the AutoFill extension.
    static let appGroupIdentifier: String? = "group.com.kruatech.vaultguard"

    /// The shared App Group container URL, or `nil` if the group isn't provisioned/usable.
    static var appGroupContainerURL: URL? {
        guard let group = appGroupIdentifier else { return nil }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)
    }

    /// Whether the shared App Group container is currently usable. The main app shows a
    /// configuration error when this is `false` (the AutoFill cache cannot be shared).
    static var isAppGroupAvailable: Bool { appGroupContainerURL != nil }

    // MARK: - AutoFill key TTL (shared setting)

    /// UserDefaults key for the AutoFill shared-key TTL, in seconds.
    static let autoFillKeyTTLKey = "autoFillKeyTTLSeconds"

    /// Default AutoFill shared-key TTL (seconds) when nothing is stored. 4 hours.
    static let autoFillKeyTTLDefault = 14400

    /// Defaults in the App Group suite, shared with the AutoFill extension. `nil` if the
    /// group isn't usable.
    static var appGroupDefaults: UserDefaults? {
        guard let group = appGroupIdentifier else { return nil }
        return UserDefaults(suiteName: group)
    }

    /// Effective AutoFill shared-key TTL in seconds. Read from the App Group suite so the main
    /// app and the extension agree on a single source; falls back to the default when unset.
    static var autoFillKeyTTLSeconds: Int {
        guard let d = appGroupDefaults, d.object(forKey: autoFillKeyTTLKey) != nil else {
            return autoFillKeyTTLDefault
        }
        return d.integer(forKey: autoFillKeyTTLKey)
    }

    // MARK: - Keychain access groups

    /// Apple Team ID prefix (e.g. "A1B2C3D4E5.") resolved at runtime from Info.plist, where
    /// the build populates `VGAppIdentifierPrefix` with `$(AppIdentifierPrefix)`. This removes
    /// any hard-coded Team ID from source: every contributor's signed build automatically uses
    /// their own prefix, matching the `$(AppIdentifierPrefix)`-based entitlements in
    /// project.yml. Both the app and the AutoFill extension carry the key in their Info.plist,
    /// so the resolved groups are identical across the two processes.
    ///
    /// In unsigned builds (CI with CODE_SIGNING_ALLOWED=NO) the prefix expands to an empty
    /// string; Keychain APIs are unusable there anyway, and the fault below makes an
    /// accidental unsigned run visible instead of failing mysteriously deeper in SecItem calls.
    static let appIdentifierPrefix: String = {
        let raw = Bundle.main.object(forInfoDictionaryKey: "VGAppIdentifierPrefix") as? String ?? ""
        if raw.isEmpty { Log.fault("VGAppIdentifierPrefix is empty — unsigned build? Keychain access groups will not resolve") }
        return raw
    }()

    /// Shared keychain access group (main app + AutoFill extension). Holds only the minimal
    /// AutoFill state the extension needs: the short-lived AutoFill secret, vault kind,
    /// passkeys, and the active account id.
    static let sharedKeychainGroup = "\(appIdentifierPrefix)com.kruatech.vaultguard"

    /// App-private keychain access group (main app only). Holds tokens, encrypted key, KDF
    /// params, cache key, account index, server/email, KeePass bookmarks, biometric secret —
    /// never visible to the extension.
    static let privateKeychainGroup = "\(appIdentifierPrefix)com.kruatech.vaultguard.private"
}
