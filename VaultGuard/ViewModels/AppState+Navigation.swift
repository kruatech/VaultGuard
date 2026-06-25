import Foundation
import SwiftUI

extension AppState {
    func switchVault(to orgId: String?) {
        activeVaultId = orgId; filter = .all; selectedCipherId = nil; searchText = ""
    }

    // MARK: - Folder Reorder

    func moveFolderInOrder(from source: IndexSet, to destination: Int) {
        var ordered = activeFolders.map { $0.id }
        ordered.move(fromOffsets: source, toOffset: destination)
        folderOrder = ordered
        folderSortMode = .manual
    }

    // MARK: - Keyboard Navigation

    func selectNextCipher() {
        let items = filteredCiphers
        guard !items.isEmpty else { return }
        if let current = selectedCipherId, let idx = items.firstIndex(where: { $0.id == current }) {
            let next = items.index(after: idx)
            selectedCipherId = next < items.endIndex ? items[next].id : items[items.startIndex].id
        } else {
            selectedCipherId = items.first?.id
        }
    }

    func selectPreviousCipher() {
        let items = filteredCiphers
        guard !items.isEmpty else { return }
        if let current = selectedCipherId, let idx = items.firstIndex(where: { $0.id == current }) {
            if idx > items.startIndex {
                selectedCipherId = items[items.index(before: idx)].id
            } else {
                selectedCipherId = items.last?.id
            }
        } else {
            selectedCipherId = items.last?.id
        }
    }

    func copySelectedPassword() {
        guard let cipher = selectedCipher, let pw = cipher.login?.password else { return }
        copyToClipboard(pw)
    }

    func copySelectedUsername() {
        guard let cipher = selectedCipher, let un = cipher.login?.username else { return }
        copyToClipboard(un)
    }
}
