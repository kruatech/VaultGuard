import Foundation
import CryptoKit

/// A signed-in account. Metadata only — never holds secrets (tokens, keys and the
/// master password live in the Keychain under `KeychainService.account(id)`).
struct Account: Codable, Identifiable, Hashable {
    let id: String
    var serverURL: String
    var email: String
    var profileName: String
    /// Optional user-defined connection name. When set, it is the primary label in the
    /// account switcher; otherwise the switcher falls back to `email · host`.
    var label: String?
    var addedAt: Date

    init(id: String, serverURL: String, email: String, profileName: String, label: String? = nil, addedAt: Date = Date()) {
        self.id = id
        self.serverURL = serverURL
        self.email = email
        self.profileName = profileName
        self.label = label
        self.addedAt = addedAt
    }

    /// Stable id derived from the normalized (serverURL, email) pair. The same server +
    /// email always yields the same id, so re-logging into an existing account updates it
    /// in place instead of creating a duplicate.
    static func makeId(serverURL: String, email: String) -> String {
        let url = normalizeServer(serverURL)
        let mail = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let digest = SHA256.hash(data: Data("\(url)|\(mail)".utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Canonical server string used for id derivation and storage: trimmed, lowercased,
    /// with an explicit scheme and without a trailing slash. `vault.example.com` and
    /// `https://vault.example.com/` therefore map to the same account/cache/keychain id.
    static func normalizeServer(_ s: String) -> String {
        var u = s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !u.hasPrefix("http://") && !u.hasPrefix("https://") { u = "https://" + u }
        while u.hasSuffix("/") { u.removeLast() }
        return u
    }

    /// Human label for the account switcher: the user's connection name if set,
    /// otherwise `email · host` so accounts with the same email on different servers
    /// stay distinguishable.
    var displayName: String {
        if let label, !label.trimmingCharacters(in: .whitespaces).isEmpty { return label }
        return "\(email) · \(serverHost)"
    }

    /// Host shown as a secondary line (e.g. "vault.bitwarden.com"), without scheme or path.
    var serverHost: String {
        var host = URL(string: serverURL)?.host ?? serverURL
        if host.hasPrefix("www.") { host.removeFirst(4) }
        return host
    }
}
