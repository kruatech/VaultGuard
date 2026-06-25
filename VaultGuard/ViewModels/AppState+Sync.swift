import Foundation

extension AppState {
    // MARK: - Sync

    func syncVault() async throws {
        let cache = activeCache
        var networkError: Error?
        do {
            let data = try await api.syncData()
            if await applySync(data) {
                cache?.save(data)
                return
            }
            // Decoded nothing usable — fall through to the cached vault.
        } catch {
            networkError = error
        }

        if let cache, let cached = cache.load(), await applySync(cached) {
            showToast(.info(L10n.Offline.usingCache.localized))
            return
        }

        if let networkError { throw networkError }
        throw APIError.invalidResponse
    }

    /// Decode + decrypt the sync payload off the main thread, then publish the
    /// results on the main actor. Returns false if the payload didn't decode
    /// (existing vault state is left untouched in that case).
    @discardableResult
    private func applySync(_ data: Data) async -> Bool {
        let crypto = self.crypto
        let noName = "misc.noName".localized
        let noOrgKey = "misc.noOrgKey".localized
        let undecryptable = "misc.undecryptable".localized

        let result = await Task.detached(priority: .userInitiated) {
            VaultDecryptor.decrypt(data: data, crypto: crypto, noName: noName, noOrgKey: noOrgKey, undecryptable: undecryptable)
        }.value

        guard let result else { return false }

        profileName = result.profileName; profileEmail = result.profileEmail
        organizations = result.organizations
        folders = result.folders
        collections = result.collections
        ciphers = result.ciphers
        CredentialIdentityStoreManager.update(with: ciphers)

        let existingIds = Set(folderOrder)
        for folder in folders where !existingIds.contains(folder.id) { folderOrder.append(folder.id) }
        folderOrder = folderOrder.filter { id in folders.contains { $0.id == id } }
        return true
    }

    func refresh() async {
        do { try await syncVault(); showToast(.info(L10n.syncComplete.localized)) }
        catch { showToast(.error(L10n.syncError.localized)) }
    }
}
