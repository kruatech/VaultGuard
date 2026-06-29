import Foundation
import LocalAuthentication

/// Local, per-account passkey storage. Credentials are kept in the shared keychain group (so the
/// AutoFill extension can read them) as a JSON array of `Fido2.Credential`, guarded by a
/// user-presence access control: reads require a pre-authenticated `LAContext` (obtained via
/// `KeychainService.passkeyAuthContext`). This is deliberately independent of Bitwarden's
/// server-side `fido2Credentials` format: passkeys created here do NOT sync to other Bitwarden
/// clients, but the format is fully under our control and verifiable.
struct PasskeyStore {
    let accountId: String
    private let keychain = KeychainService.shared

    static func forAccount(_ accountId: String) -> PasskeyStore { PasskeyStore(accountId: accountId) }

    /// All stored credentials for this account. Requires an authenticated context.
    func all(context: LAContext) -> [Fido2.Credential] {
        guard let json = keychain.loadPasskeys(accountId: accountId, context: context),
              let data = json.data(using: .utf8),
              let creds = try? JSONDecoder().decode([Fido2.Credential].self, from: data) else { return [] }
        return creds
    }

    /// Persist the full credential set (overwrites). Writing needs no auth context.
    func save(_ creds: [Fido2.Credential]) {
        guard let data = try? JSONEncoder().encode(creds),
              let json = String(data: data, encoding: .utf8) else { return }
        keychain.savePasskeys(json, accountId: accountId)
    }

    /// Add a credential (replacing any with the same credentialId).
    func add(_ cred: Fido2.Credential, context: LAContext) {
        var creds = all(context: context).filter { $0.credentialId != cred.credentialId }
        creds.append(cred)
        save(creds)
    }

    func remove(credentialId: Data, context: LAContext) {
        save(all(context: context).filter { $0.credentialId != credentialId })
    }

    /// Discoverable credentials for a relying party (assertion + identity registration).
    func credentials(rpId: String, context: LAContext) -> [Fido2.Credential] {
        all(context: context).filter { $0.rpId == rpId }
    }

    func credential(credentialId: Data, context: LAContext) -> Fido2.Credential? {
        all(context: context).first { $0.credentialId == credentialId }
    }

    /// Increment and persist a credential's signature counter after an assertion; returns the new value.
    func bumpCounter(credentialId: Data, context: LAContext) -> UInt32 {
        var creds = all(context: context)
        guard let i = creds.firstIndex(where: { $0.credentialId == credentialId }) else { return 0 }
        creds[i].counter &+= 1
        save(creds)
        return creds[i].counter
    }
}
