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

    /// Why a read failed, for callers that must not mistake it for an empty vault.
    enum StoreError: Error {
        /// Credentials exist but could not be read or decoded. Never treat as "none stored".
        case unreadable
    }

    /// All stored credentials for this account, or a failure.
    ///
    /// Read-modify-write callers must use this rather than `all(context:)`. Nothing here
    /// syncs anywhere — the credentials in this store exist in exactly one place — so writing
    /// a set assembled from a failed read destroys the user's passkeys permanently, and takes
    /// whatever accounts they unlock with them.
    ///
    /// A decode failure throws instead of yielding an empty array. `JSONDecoder` rejects the
    /// whole array if any element does not match, so a future change to `Fido2.Credential`
    /// would otherwise make the next registration wipe every existing credential — with no
    /// attacker and no error anywhere.
    func loadAll(context: LAContext) throws -> [Fido2.Credential] {
        guard let json = try keychain.loadPasskeys(accountId: accountId, context: context) else {
            return []      // nothing stored yet — the one case where an empty set is real
        }
        guard let data = json.data(using: .utf8),
              let creds = try? JSONDecoder().decode([Fido2.Credential].self, from: data) else {
            throw StoreError.unreadable
        }
        return creds
    }

    /// All stored credentials, treating any failure as none. Only for read-only callers —
    /// listing credentials to show or to match against a request. Never for a path that
    /// writes the set back.
    func all(context: LAContext) -> [Fido2.Credential] {
        (try? loadAll(context: context)) ?? []
    }

    /// Persist the full credential set (overwrites). Writing needs no auth context.
    func save(_ creds: [Fido2.Credential]) {
        guard let data = try? JSONEncoder().encode(creds),
              let json = String(data: data, encoding: .utf8) else { return }
        keychain.savePasskeys(json, accountId: accountId)
    }

    /// Add a credential, replacing any with the same id.
    ///
    /// Throws rather than writing when the existing set cannot be read. Refusing to register
    /// a new passkey is recoverable — the user authenticates again and retries; silently
    /// dropping the others is not.
    func add(_ cred: Fido2.Credential, context: LAContext) throws {
        var creds = try loadAll(context: context).filter { $0.credentialId != cred.credentialId }
        creds.append(cred)
        save(creds)
    }

    /// Remove one credential. Throws rather than writing when the set cannot be read — the
    /// same read-modify-write hazard, where the write would remove everything.
    func remove(credentialId: Data, context: LAContext) throws {
        save(try loadAll(context: context).filter { $0.credentialId != credentialId })
    }

    /// Discoverable credentials for a relying party (assertion + identity registration).
    func credentials(rpId: String, context: LAContext) -> [Fido2.Credential] {
        all(context: context).filter { $0.rpId == rpId }
    }

    func credential(credentialId: Data, context: LAContext) -> Fido2.Credential? {
        all(context: context).first { $0.credentialId == credentialId }
    }

    /// Increment and persist a credential's signature counter after an assertion.
    ///
    /// - Returns: the new counter, or nil when the set could not be read or the credential is
    ///   not in it. Nil must abort the assertion: signing with a counter of zero while the
    ///   relying party has already seen higher values is exactly the pattern it watches for to
    ///   detect a cloned authenticator, and it may lock the account.
    func bumpCounter(credentialId: Data, context: LAContext) -> UInt32? {
        guard var creds = try? loadAll(context: context),
              let i = creds.firstIndex(where: { $0.credentialId == credentialId }) else { return nil }
        creds[i].counter &+= 1
        save(creds)
        return creds[i].counter
    }
}
