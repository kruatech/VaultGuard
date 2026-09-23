import Foundation

extension AppState {
    // MARK: - Master Password Reprompt

    /// Run `action` immediately, unless the item is reprompt-protected and hasn't
    /// been verified yet this session — in which case prompt for the master password.
    func guardReprompt(_ cipher: VaultCipher, perform action: @escaping () -> Void) {
        if cipher.reprompt == 1 && !repromptVerifiedCipherIds.contains(cipher.id) {
            pendingReprompt = RepromptRequest(cipherId: cipher.id, cipherName: cipher.name, onVerified: action)
        } else {
            action()
        }
    }

    /// Verify the entered master password against the pending reprompt and, on
    /// success, run the deferred action. Returns false on an incorrect password.
    @discardableResult
    func submitReprompt(_ password: String) async -> Bool {
        guard let req = pendingReprompt, await verifyMasterPassword(password) else { return false }
        // The sheet may have been dismissed, or a different item reprompted, while the KDF ran.
        guard pendingReprompt?.cipherId == req.cipherId else { return false }
        repromptVerifiedCipherIds.insert(req.cipherId)
        let action = req.onVerified
        pendingReprompt = nil
        action()
        return true
    }

    func cancelReprompt() { pendingReprompt = nil }

    /// Re-derive the master-password hash from the entered password (using a
    /// throwaway crypto instance so the live session keys are untouched) and
    /// compare it in constant time to the hash from the active session.
    ///
    /// The derivation runs off the main actor for the same reason as at login: it is the full
    /// master-password KDF, and running it here froze the window while the sheet waited. The
    /// probe is a throwaway instance that nothing else holds, so moving it is safe.
    func verifyMasterPassword(_ password: String) async -> Bool {
        guard !password.isEmpty,
              let store = activeStore,
              let email = store.email,
              let iter = store.kdfIterations,
              let currentHash = crypto.passwordHash else { return false }
        let kdf = store.kdfType ?? 0, memory = store.kdfMemory, parallelism = store.kdfParallelism
        let candidate: String? = await Task.detached(priority: .userInitiated) {
            let probe = CryptoService()
            defer { probe.clearKeys() }
            do {
                try probe.deriveKeys(password: password, email: email, kdf: kdf,
                                     kdfIterations: iter, kdfMemory: memory, kdfParallelism: parallelism)
                return probe.passwordHash
            } catch { return nil }
        }.value
        guard let candidate else { return false }
        return AppState.constantTimeEqual(candidate, currentHash)
    }

    private static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let ab = Array(a.utf8), bb = Array(b.utf8)
        guard ab.count == bb.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<ab.count { diff |= ab[i] ^ bb[i] }
        return diff == 0
    }
}
