import Foundation

/// Identifiers shared between the main app and the AutoFill extension.
///
/// Keychain items are shared automatically: both targets list the same single
/// `keychain-access-groups` entitlement, so items land in that group by default and no
/// code sets `kSecAttrAccessGroup` explicitly.
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
}
