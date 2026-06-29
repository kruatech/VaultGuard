import Foundation
import AuthenticationServices

/// Mirrors the vault's logins into the system credential-identity store so the
/// QuickType bar can suggest VaultGuard credentials. No-op unless the AutoFill
/// Credential Provider capability is enabled for the app.
enum CredentialIdentityStoreManager {

    static func update(with ciphers: [VaultCipher]) {
        ASCredentialIdentityStore.shared.getState { state in
            guard state.isEnabled else { return }
            var identities: [any ASCredentialIdentity] = []
            for cipher in ciphers {
                guard let login = cipher.login, let user = login.username, !user.isEmpty else { continue }
                for uri in (login.uris ?? []) {
                    guard let raw = uri.uri, !raw.isEmpty else { continue }
                    let host = URL(string: raw)?.host ?? raw
                    let service = ASCredentialServiceIdentifier(identifier: host, type: .domain)
                    identities.append(ASPasswordCredentialIdentity(
                        serviceIdentifier: service, user: user, recordIdentifier: cipher.id))
                }
            }
            Task { try? await ASCredentialIdentityStore.shared.replaceCredentialIdentities(identities) }
        }
    }

    static func clear() {
        ASCredentialIdentityStore.shared.removeAllCredentialIdentities { _, _ in }
    }
}
