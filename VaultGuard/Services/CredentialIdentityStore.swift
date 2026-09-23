import Foundation
import AuthenticationServices

/// Mirrors the vault's logins into the system credential-identity store so the
/// QuickType bar can suggest VaultGuard credentials. No-op unless the AutoFill
/// Credential Provider capability is enabled for the app.
///
/// Registered identities deliberately survive a lock, and are only removed on logout. The
/// trade is explicit: while locked, the QuickType bar still shows usernames and domains from
/// the vault, so someone at an unlocked Mac learns which accounts exist without knowing the
/// master password. Clearing them on lock would remove that, and would also remove the
/// suggestion the whole AutoFill flow starts from — tapping it is what brings the user to the
/// unlock prompt. Identities carry no passwords; the sealed cache and the shared secret, which
/// do, are both destroyed by `AppState.lock()`.
enum CredentialIdentityStoreManager {

    static func update(with ciphers: [VaultCipher]) {
        ASCredentialIdentityStore.shared.getState { state in
            guard state.isEnabled else { return }
            var identities: [any ASCredentialIdentity] = []
            // Bitwarden UriMatchType 5 is "never": the user asked that this URI never be used
            // to fill. `publishAutoFill` already drops those from the sealed cache, and the
            // same rule has to hold here — otherwise QuickType keeps offering the credential
            // for a site the extension will then refuse to fill, which is both wrong and a
            // dead end for the user.
            let uriMatchNever = 5
            var seen = Set<String>()
            for cipher in ciphers {
                guard let login = cipher.login, let user = login.username, !user.isEmpty else { continue }
                for uri in (login.uris ?? []) {
                    guard uri.match != uriMatchNever, let raw = uri.uri, !raw.isEmpty else { continue }
                    // One host parser for the whole AutoFill path. The local version here
                    // accepted anything it could not parse verbatim, so a bare host worked by
                    // accident, case and trailing dots were kept as-is, and a non-web scheme
                    // registered a nonsense domain.
                    guard let host = AutoFillHostMatcher.host(from: raw) else { continue }
                    // The same host can appear on several URIs of one item; registering it
                    // twice gives the QuickType bar duplicate suggestions.
                    guard seen.insert("\(cipher.id)|\(host)|\(user)").inserted else { continue }
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
