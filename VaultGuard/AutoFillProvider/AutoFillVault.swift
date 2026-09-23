import Foundation
import AuthenticationServices

struct AutoFillCredential {
    let recordIdentifier: String
    let name: String
    let user: String
    let password: String
    let uris: [String]
    /// Normalized hosts of `uris`, resolved once when the cache is opened. Matching used to
    /// re-parse every URI of every credential on every request; the set of URIs cannot change
    /// while the extension is running, so the work is done once here instead.
    let hosts: [String]
    /// Last change to the source item, when the cache carries it. See `AutoFillRecord`.
    let revisionDate: Date?
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

/// Reads the active account's minimal AutoFill cache, unsealing it with a key derived
/// from the short-lived AutoFill secret the main app publishes while the vault is
/// unlocked, and exposes matching login credentials to the extension. The extension
/// never sees the master password, the real vault/user key, or any session token.
///
/// Scoped to the active account (`KeychainService.activeAccountId`). Serving credentials
/// aggregated across all accounts would require unlocking each one separately and is left
/// for a later iteration.
@MainActor
final class AutoFillVault {
    static let shared = AutoFillVault()

    private let keychain = KeychainService.shared
    private(set) var credentials: [AutoFillCredential] = []

    /// Open the minimal AutoFill cache for the active account. Requires a valid (non-expired)
    /// AutoFill secret payload: the TTL is enforced inside `KeychainService.autoFillSecret`,
    /// which returns nil (and cleans up) when the secret is absent / expired / malformed /
    /// legacy. The extension derives the cache key from that secret and never reads the app's
    /// session secrets (`cacheKey`, `encryptedKey`, tokens).
    func unlock() async throws {
        guard let accountId = keychain.activeAccountId else { throw AutoFillError.notConfigured }
        guard let secret = keychain.autoFillSecret(accountId: accountId) else { throw AutoFillError.locked }
        let kind = keychain.vaultKind(accountId: accountId) ?? "server"

        switch AutoFillCache.open(secret: secret, accountId: accountId, kind: kind) {
        case .records(let records):
            credentials = records.map {
                AutoFillCredential(recordIdentifier: $0.id, name: $0.name,
                                   user: $0.user, password: $0.password, uris: $0.uris,
                                   hosts: $0.uris.compactMap(Self.host(from:)),
                                   revisionDate: $0.revisionDate)
            }
        case .missing:
            credentials = []
            throw AutoFillError.noCache
        case .corrupted:
            credentials = []
            throw AutoFillError.decodeFailed
        }
    }

    func lock() {
        credentials = []
    }

    func matches(for serviceIdentifiers: [ASCredentialServiceIdentifier]) -> [AutoFillCredential] {
        let requestHosts = serviceIdentifiers.compactMap { Self.host(from: $0.identifier) }
        guard !requestHosts.isEmpty else { return credentials }
        return credentials.filter { cred in
            cred.hosts.contains { credHost in
                requestHosts.contains { Self.hostMatches(credentialHost: credHost, requestHost: $0) }
            }
        }
    }

    func credential(for identity: ASPasswordCredentialIdentity) -> AutoFillCredential? {
        if let rid = identity.recordIdentifier,
           let match = credentials.first(where: { $0.recordIdentifier == rid }) { return match }
        // Fallback for a missing/stale recordIdentifier: match by username, but ONLY among
        // credentials whose URIs match the identity's service host. A bare username match
        // across the whole vault could fill site A's password into site B when usernames
        // coincide — never do that. Fail closed when the service host is unparseable
        // (matches(for:) would otherwise return the full list for an empty host set).
        guard Self.host(from: identity.serviceIdentifier.identifier) != nil else { return nil }
        let serviceScoped = matches(for: [identity.serviceIdentifier])
        // Several entries can share a host and username with different passwords (an old one
        // kept around after a rotation, say). Taking the first match handed out whichever
        // happened to come first in the vault; prefer the most recently updated one. Entries
        // with no revision date sort oldest, so a dated entry always wins over an undated one.
        return serviceScoped
            .filter { $0.user == identity.user }
            .max { ($0.revisionDate ?? .distantPast) < ($1.revisionDate ?? .distantPast) }
    }

    // Host parsing and matching live in `AutoFillHostMatcher` so the unit-test target can
    // compile them without the keychain and the cache this type depends on.
    private static func host(from identifier: String) -> String? {
        AutoFillHostMatcher.host(from: identifier)
    }

    private static func hostMatches(credentialHost: String, requestHost: String) -> Bool {
        AutoFillHostMatcher.hostMatches(credentialHost: credentialHost, requestHost: requestHost)
    }
}
