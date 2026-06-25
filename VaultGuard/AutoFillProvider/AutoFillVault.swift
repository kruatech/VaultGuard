import Foundation
import AuthenticationServices

struct AutoFillCredential {
    let recordIdentifier: String
    let name: String
    let user: String
    let password: String
    let uris: [String]
}

enum AutoFillError: LocalizedError {
    case notConfigured, locked, noCache, decodeFailed
    var errorDescription: String? {
        switch self {
        case .notConfigured: return L10n.AutoFill.errNotConfigured.localized
        case .locked: return L10n.AutoFill.errLocked.localized
        case .noCache: return L10n.AutoFill.errNoCache.localized
        case .decodeFailed: return L10n.AutoFill.errDecode.localized
        }
    }
}

/// Reads the active account's shared, encrypted vault cache, unlocks it with that
/// account's master password (behind biometric), and exposes matching login credentials
/// to the extension.
///
/// Scoped to the active account (`KeychainService.activeAccountId`). Serving credentials
/// aggregated across all accounts would require unlocking each one separately and is left
/// for a later iteration.
@MainActor
final class AutoFillVault {
    static let shared = AutoFillVault()

    private let crypto = CryptoService()
    private let keychain = KeychainService.shared
    private(set) var credentials: [AutoFillCredential] = []

    /// Variant B: the main app shares the vault key only while it is unlocked. If the key is
    /// absent the vault is locked, and the extension tells the user to open VaultGuard — no
    /// biometric prompt happens inside the extension.
    func unlock() async throws {
        guard let accountId = keychain.activeAccountId else { throw AutoFillError.notConfigured }
        guard keychain.account(accountId).encryptedKey != nil else { throw AutoFillError.notConfigured }
        guard let userKey = keychain.sharedVaultKey(accountId: accountId) else { throw AutoFillError.locked }

        crypto.restoreSession(userKey: userKey, passwordHash: "")

        guard let data = VaultCache.forAccount(accountId).load() else { throw AutoFillError.noCache }
        guard let sync = try? JSONDecoder().decode(SyncResponse.self, from: data) else { throw AutoFillError.decodeFailed }

        if let pk = sync.profile?.privateKey { crypto.setPrivateKey(from: pk) }
        if let orgs = sync.profile?.organizations, !orgs.isEmpty { crypto.setOrganizationKeys(orgs) }

        credentials = (sync.ciphers ?? []).compactMap { c in
            guard c.deletedDate == nil, let id = c.id, let login = c.login,
                  let user = crypto.decrypt(login.username, orgId: c.organizationId), !user.isEmpty,
                  let pass = crypto.decrypt(login.password, orgId: c.organizationId), !pass.isEmpty else { return nil }
            let uris = (login.uris ?? []).compactMap { crypto.decrypt($0.uri, orgId: c.organizationId) }
            let name = crypto.decrypt(c.name, orgId: c.organizationId) ?? user
            return AutoFillCredential(recordIdentifier: id, name: name, user: user, password: pass, uris: uris)
        }
    }

    func lock() {
        crypto.clearKeys()
        credentials = []
    }

    /// Credentials whose URIs match any of the requested service identifiers by host
    /// (exact or subdomain on a label boundary), never by substring.
    func matches(for serviceIdentifiers: [ASCredentialServiceIdentifier]) -> [AutoFillCredential] {
        let requestHosts = serviceIdentifiers.compactMap { Self.host(from: $0.identifier) }
        guard !requestHosts.isEmpty else { return credentials }
        return credentials.filter { cred in
            cred.uris.contains { uriStr in
                guard let credHost = Self.host(from: uriStr) else { return false }
                return requestHosts.contains { Self.hostMatches(credentialHost: credHost, requestHost: $0) }
            }
        }
    }

    func credential(for identity: ASPasswordCredentialIdentity) -> AutoFillCredential? {
        if let rid = identity.recordIdentifier,
           let match = credentials.first(where: { $0.recordIdentifier == rid }) { return match }
        return credentials.first { $0.user == identity.user }
    }

    /// Normalized host from a full URL or a bare-host identifier; nil if unparseable.
    private static func host(from identifier: String) -> String? {
        var s = identifier.trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty else { return nil }
        let lower = s.lowercased()
        if !lower.hasPrefix("http://") && !lower.hasPrefix("https://") { s = "https://" + s }
        guard let host = URL(string: s)?.host else { return nil }
        return normalizeHost(host)
    }

    private static func normalizeHost(_ host: String) -> String {
        var h = host.lowercased()
        while h.hasSuffix(".") { h.removeLast() }
        return h
    }

    /// Exact host match, or one host is a subdomain of the other on a label boundary.
    /// Rejects look-alikes: evil-example.com and example.com.evil.com never match example.com.
    private static func hostMatches(credentialHost: String, requestHost: String) -> Bool {
        if credentialHost == requestHost { return true }
        if requestHost.hasSuffix("." + credentialHost) { return true }
        if credentialHost.hasSuffix("." + requestHost) { return true }
        return false
    }
}
