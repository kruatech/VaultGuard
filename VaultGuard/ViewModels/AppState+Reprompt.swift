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
    func submitReprompt(_ password: String) -> Bool {
        guard let req = pendingReprompt, verifyMasterPassword(password) else { return false }
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
    func verifyMasterPassword(_ password: String) -> Bool {
        guard !password.isEmpty,
              let store = activeStore,
              let email = store.email,
              let iter = store.kdfIterations,
              let currentHash = crypto.passwordHash else { return false }
        let probe = CryptoService()
        defer { probe.clearKeys() }
        do {
            try probe.deriveKeys(password: password, email: email, kdf: store.kdfType ?? 0,
                                 kdfIterations: iter, kdfMemory: store.kdfMemory, kdfParallelism: store.kdfParallelism)
            guard let candidate = probe.passwordHash else { return false }
            return AppState.constantTimeEqual(candidate, currentHash)
        } catch { return false }
    }

    private static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let ab = Array(a.utf8), bb = Array(b.utf8)
        guard ab.count == bb.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<ab.count { diff |= ab[i] ^ bb[i] }
        return diff == 0
    }
}
