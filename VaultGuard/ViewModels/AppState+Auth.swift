import Foundation

extension AppState {
    // MARK: - Login (also the "add account" path)

    /// Log in to `serverURL` as `email`. Doubles as "add account": a successful login
    /// registers the account, makes it active and unlocks it. Any previously-unlocked
    /// session is torn down first.
    func login(serverURL: String, email: String, password: String, saveBiometric: Bool, allowSelfSigned: Bool? = nil, label: String? = nil) async {
        isLoading = true; errorMessage = nil
        rebuildActiveSession()
        let ss = allowSelfSigned ?? UserDefaults.standard.bool(forKey: "allowSelfSigned")
        do {
            await api.configure(serverURL: serverURL, allowSelfSigned: ss)
            let pre = try await api.prelogin(email: email)
            try crypto.deriveKeys(password: password, email: email, kdf: pre.kdf,
                                  kdfIterations: pre.kdfIterations, kdfMemory: pre.kdfMemory, kdfParallelism: pre.kdfParallelism)
            guard let hash = crypto.passwordHash else { throw AuthError.keyDerivationFailed }
            let tok: TokenResponse
            do {
                tok = try await api.login(email: email, masterPasswordHash: hash)
            } catch APIError.twoFactorRequired(let providers) {
                // Server requires 2FA — show the prompt with the offered providers.
                pending2FALogin = PendingLogin(
                    serverURL: serverURL, email: email, passwordHash: hash,
                    saveBiometric: saveBiometric, password: password,
                    kdf: pre.kdf, kdfIterations: pre.kdfIterations,
                    kdfMemory: pre.kdfMemory, kdfParallelism: pre.kdfParallelism,
                    encryptedKey: nil, label: label,
                    providers: providers.isEmpty ? [0] : providers
                )
                show2FA = true
                isLoading = false
                return
            }
            try await establishSession(serverURL: serverURL, email: email, password: password,
                                       saveBiometric: saveBiometric, tok: tok,
                                       kdf: pre.kdf, kdfIterations: pre.kdfIterations,
                                       kdfMemory: pre.kdfMemory, kdfParallelism: pre.kdfParallelism, label: label)
        } catch {
            // A self-signed server whose certificate isn't trusted yet: show its fingerprint
            // and let the user confirm, instead of failing with a generic error.
            if ss, presentCertTrustIfNeeded(serverURL: serverURL, email: email,
                                            password: password, saveBiometric: saveBiometric,
                                            allowSelfSigned: ss, label: label) {
                isLoading = false
                return
            }
            errorMessage = error.localizedDescription
        }
        isLoading = false
    }

    // MARK: - Self-signed certificate trust (fingerprint pinning)

    /// Host used for pinning, matching `APIService.configure`'s https-default behaviour.
    private func certHost(for serverURL: String) -> String? {
        var u = serverURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = u.lowercased()
        if !lower.hasPrefix("http://") && !lower.hasPrefix("https://") { u = "https://" + u }
        return URL(string: u)?.host?.lowercased()
    }

    /// If the last failed handshake surfaced an untrusted fingerprint that isn't the one the
    /// user already trusts, stash a pending trust request and return true.
    private func presentCertTrustIfNeeded(serverURL: String, email: String,
                                          password: String, saveBiometric: Bool,
                                          allowSelfSigned: Bool, label: String?) -> Bool {
        guard let host = certHost(for: serverURL),
              let seen = certTrust.seenFingerprint(host: host),
              certTrust.pinnedFingerprint(host: host) != seen else { return false }
        pendingCertTrust = PendingCertTrust(
            host: host, fingerprint: seen, changed: certTrust.pinnedFingerprint(host: host) != nil,
            serverURL: serverURL, email: email, password: password,
            saveBiometric: saveBiometric, allowSelfSigned: allowSelfSigned, label: label
        )
        showCertTrust = true
        return true
    }

    /// User confirmed the fingerprint: pin it and retry the original login.
    func trustPendingCert() {
        guard let p = pendingCertTrust else { return }
        certTrust.pin(host: p.host, fingerprint: p.fingerprint)
        certTrust.clearSeen(host: p.host)
        pendingCertTrust = nil; showCertTrust = false
        Task { await login(serverURL: p.serverURL, email: p.email, password: p.password,
                           saveBiometric: p.saveBiometric, allowSelfSigned: p.allowSelfSigned, label: p.label) }
    }

    /// User declined: drop the request and the seen fingerprint.
    func cancelPendingCert() {
        if let p = pendingCertTrust { certTrust.clearSeen(host: p.host) }
        pendingCertTrust = nil; showCertTrust = false
        showToast(.info(L10n.CertTrust.cancelled.localized))
    }

    func complete2FALogin(code: String, remember: Bool, provider: Int) async {
        guard let pending = pending2FALogin else { return }
        isLoading = true; errorMessage = nil
        do {
            let tok = try await api.login2FA(
                email: pending.email, masterPasswordHash: pending.passwordHash,
                twoFactorCode: code, twoFactorProvider: provider, rememberDevice: remember
            )
            try await establishSession(serverURL: pending.serverURL, email: pending.email, password: pending.password,
                                       saveBiometric: pending.saveBiometric, tok: tok,
                                       kdf: pending.kdf, kdfIterations: pending.kdfIterations,
                                       kdfMemory: pending.kdfMemory, kdfParallelism: pending.kdfParallelism, label: pending.label)
            show2FA = false; pending2FALogin = nil
        } catch { errorMessage = error.localizedDescription }
        isLoading = false
    }

    /// Ask the server to email a login 2FA code (provider 1 = Email).
    func sendTwoFactorEmail() async {
        guard let pending = pending2FALogin else { return }
        do {
            try await api.sendTwoFactorEmailLogin(email: pending.email, masterPasswordHash: pending.passwordHash)
            showToast(.info(L10n.Auth.twoFactorEmailSent.localized))
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - Establish session after a successful (2FA) login

    /// Set up crypto keys, persist the per-account secrets, register the account, then sync.
    private func establishSession(serverURL: String, email: String, password: String, saveBiometric: Bool,
                                  tok: TokenResponse, kdf: Int, kdfIterations: Int,
                                  kdfMemory: Int?, kdfParallelism: Int?, label: String? = nil) async throws {
        await api.setTokens(access: tok.accessToken, refresh: tok.refreshToken, expiresIn: tok.expiresIn)
        guard let ek = tok.key else { throw AuthError.noEncryptionKey }
        // Fresh login derives the master key first, so unwrap the protected key here. A
        // biometric unlock that fell through to a 2FA re-login already restored `encKey`
        // directly (no master key on hand), so don't try to unwrap again.
        if !crypto.hasKeys { try crypto.setEncryptionKey(from: ek) }
        crypto.setPrivateKey(from: tok.privateKey)

        let normalizedURL = Account.normalizeServer(serverURL)
        let accountId = Account.makeId(serverURL: serverURL, email: email)

        let store = keychain.account(accountId)
        do {
            try store.setServerURL(normalizedURL)
            try store.setEmail(email)
            try store.setAccessToken(tok.accessToken)
            try store.setRefreshToken(tok.refreshToken)
            try store.setEncryptedKey(ek)
            try store.setKdf(type: kdf, iterations: kdfIterations, memory: kdfMemory, parallelism: kdfParallelism)
        } catch {
            // A partial write must not look like a successful login: wipe and fail cleanly.
            try? keychain.clearAccount(accountId)
            throw error
        }
        // Store the vault key (+ password hash) under biometric protection — never the
        // master password. Only when biometric is actually available on this device.
        if saveBiometric, keychain.isBiometricAvailable,
           let userKey = crypto.exportUserKey(), let hash = crypto.passwordHash {
            do { try store.saveBiometricUnlock(userKey: userKey, passwordHash: hash) }
            catch {
                Log.fault("biometric unlock save failed")
                showToast(.info(L10n.Account.biometricNotEnabled.localized))
            }
        }

        accounts.upsert(Account(id: accountId, serverURL: normalizedURL, email: email, profileName: email, label: label))
        accounts.setActive(accountId)
        reloadFolderOrderForActiveAccount()

        try await syncVault()

        // syncVault() fills profileName/profileEmail; refresh the stored display name.
        let display = !profileName.isEmpty ? profileName : (!profileEmail.isEmpty ? profileEmail : email)
        accounts.upsert(Account(id: accountId, serverURL: normalizedURL, email: email, profileName: display, label: label))

        // Publish the vault key for the AutoFill extension while this account is unlocked.
        if let userKey = crypto.exportUserKey() { keychain.shareVaultKey(userKey, accountId: accountId) }
        if !SharedConfig.isAppGroupAvailable { showToast(.error(L10n.Account.appGroupUnavailable.localized)) }
        isUnlocked = true; startAutoLockTimer(); setupSleepObservers()
    }

    // MARK: - Unlock (active account, via biometric)

    func unlockWithBiometric() async {
        isLoading = true; errorMessage = nil
        let ss = UserDefaults.standard.bool(forKey: "allowSelfSigned")
        do {
            guard let store = activeStore,
                  let url = store.serverURL, let email = store.email,
                  let ek = store.encryptedKey else { throw AuthError.noSavedSession }
            guard let unlock = try await store.getBiometricUnlock() else { throw AuthError.biometricFailed }
            reloadFolderOrderForActiveAccount()

            // Restore the vault key directly from the biometric-protected secret. No master
            // password, no KDF re-derivation. The stored hash is kept for reprompt checks
            // and for a server re-login if the refresh token is dead.
            crypto.restoreSession(userKey: unlock.userKey, passwordHash: unlock.passwordHash)

            await api.configure(serverURL: url, allowSelfSigned: ss)

            // Try to revive the saved session with the refresh token; fall back to a hash
            // login (which may, in turn, require a 2FA challenge).
            var needPasswordLogin = false
            if let rt = store.refreshToken {
                await api.setTokens(access: store.accessToken ?? "", refresh: rt, expiresIn: 0)
                do {
                    let nt = try await api.refreshAccessToken()
                    try store.setAccessToken(nt.accessToken)
                    if let r = nt.refreshToken { try store.setRefreshToken(r) }
                    crypto.setPrivateKey(from: nt.privateKey)
                } catch {
                    needPasswordLogin = true
                }
            } else {
                needPasswordLogin = true
            }

            if needPasswordLogin {
                let tok: TokenResponse
                do {
                    tok = try await api.login(email: email, masterPasswordHash: unlock.passwordHash)
                } catch APIError.twoFactorRequired(let providers) {
                    // Refresh token is dead and the server now wants 2FA. The vault key is
                    // already restored on `crypto`; stash the context (no raw password) and
                    // let complete2FALogin finish.
                    pending2FALogin = PendingLogin(
                        serverURL: url, email: email, passwordHash: unlock.passwordHash,
                        saveBiometric: true, password: "",
                        kdf: store.kdfType ?? 0, kdfIterations: store.kdfIterations ?? 0,
                        kdfMemory: store.kdfMemory, kdfParallelism: store.kdfParallelism,
                        encryptedKey: ek,
                        providers: providers.isEmpty ? [0] : providers
                    )
                    show2FA = true
                    isLoading = false
                    return
                }
                await api.setTokens(access: tok.accessToken, refresh: tok.refreshToken, expiresIn: tok.expiresIn)
                try store.setAccessToken(tok.accessToken); try store.setRefreshToken(tok.refreshToken)
                if let k = tok.key { try store.setEncryptedKey(k) }
                crypto.setPrivateKey(from: tok.privateKey)
            }

            try await syncVault()
            keychain.shareVaultKey(unlock.userKey, accountId: store.accountId)
            isUnlocked = true; startAutoLockTimer(); setupSleepObservers()
        } catch { errorMessage = error.localizedDescription }
        isLoading = false
    }

    // MARK: - Account switching

    /// Switch to another signed-in account. The current account is locked (keys wiped) and
    /// the target is re-unlocked via biometric — no two accounts are held unlocked at once.
    func switchAccount(to accountId: String) async {
        guard accountId != accounts.activeAccountId, accounts.contains(accountId) else { return }
        lock()
        rebuildActiveSession()
        accounts.setActive(accountId)
        await unlockWithBiometric()
    }

    // MARK: - Lock / Logout

    func lock() {
        isUnlocked = false; ciphers = []; folders = []; collections = []; organizations = []
        selectedCipherId = nil; activeVaultId = nil; wipeCryptoSession()
        repromptVerifiedCipherIds.removeAll(); pendingReprompt = nil
        autoLockTimer?.invalidate(); autoLockTimer = nil
        removeSleepObservers()
        // Revoke AutoFill access: the shared key is only valid while unlocked.
        if let id = accounts.activeAccountId {
            do { try keychain.clearSharedVaultKey(accountId: id) }
            catch { Log.fault("clear shared vault key on lock failed") }
        }
    }

    /// Log out of the active account: wipe its secrets and drop it. If other accounts remain,
    /// the next becomes active (locked); otherwise the app returns to the login screen.
    func logout() {
        let id = accounts.activeAccountId
        lock()
        Task { await api.clearTokens() }
        var wipeFailed = false
        if let id {
            VaultCache.forAccount(id).clear() // wipe this account's cache file + key
            do { try accounts.remove(id) }    // also reassigns the active pointer
            catch { wipeFailed = true }
        }
        CredentialIdentityStoreManager.clear()
        rebuildActiveSession()
        if wipeFailed {
            Log.fault("logout: account secret wipe incomplete")
            showToast(.error(L10n.Account.dataNotRemoved.localized))
        }
    }

    /// Log out of every account and clear all stored secrets.
    func logoutAllAccounts() {
        lock()
        Task { await api.clearTokens() }
        let ids = accounts.accounts.map { $0.id }
        for id in ids { VaultCache.forAccount(id).clear() }
        CredentialIdentityStoreManager.clear()
        var wipeFailed = false
        do { try accounts.removeAll(ids) } catch { wipeFailed = true }
        rebuildActiveSession()
        if wipeFailed {
            Log.fault("logout-all: account secret wipe incomplete")
            showToast(.error(L10n.Account.dataNotRemoved.localized))
        }
    }

    /// Remove a non-active account from the list (e.g. from Settings). Removing the active
    /// account falls back to `logout()`.
    func removeAccount(_ id: String) {
        if id == accounts.activeAccountId { logout(); return }
        VaultCache.forAccount(id).clear()
        do { try accounts.remove(id) }
        catch {
            Log.fault("removeAccount: secret wipe incomplete")
            showToast(.error(L10n.Account.dataNotRemoved.localized))
        }
    }

    /// Disable biometric unlock for the active account. Returns `true` if the secret was
    /// fully removed; on failure it logs a fault, shows a toast, and returns `false` so the
    /// UI can keep reflecting that biometric is still enabled.
    @discardableResult
    func disableBiometricUnlock() -> Bool {
        guard let id = accounts.activeAccountId else { return true }
        do { try keychain.clearBiometricUnlock(accountId: id); return true }
        catch {
            Log.fault("disable biometric unlock failed")
            showToast(.error(L10n.Account.biometricNotDisabled.localized))
            return false
        }
    }
}
