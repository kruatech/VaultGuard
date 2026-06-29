import SwiftUI
import AppKit

struct ItemsListView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        Group {
            if appState.filteredCiphers.isEmpty {
                VStack(spacing: VGSpacing.m) {
                    Image(systemName: "magnifyingglass").font(VGFont.emptyGlyph).foregroundColor(VGColor.quaternary)
                    Text(L10n.Items.notFound.localized).font(VGFont.bodyLarge).foregroundColor(VGColor.secondary)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    List(selection: $appState.selectedCipherId) {
                        ForEach(appState.filteredCiphers) { cipher in
                            CipherRowView(cipher: cipher).tag(cipher.id).id(cipher.id).handCursor()
                        }
                    }
                    .listStyle(.plain)
                    .onChange(of: appState.selectedCipherId) { _, newId in
                        if let newId { withAnimation { proxy.scrollTo(newId, anchor: .center) } }
                    }
                }
            }
        }
    }
}

struct CipherRowView: View {
    @EnvironmentObject var appState: AppState
    let cipher: VaultCipher

    var body: some View {
        HStack(spacing: VGSpacing.l) {
            CipherAvatar(cipher: cipher)
            VStack(alignment: .leading, spacing: VGSpacing.xxs) {
                Text(cipher.name).font(VGFont.bodyEmphasis).lineLimit(1)
                if !cipher.displayUsername.isEmpty {
                    Text(cipher.displayUsername).font(VGFont.caption).foregroundColor(VGColor.secondary).lineLimit(1)
                }
            }
            Spacer()
            if cipher.favorite, appState.activeVaultKind != .keepass { Image(systemName: "star.fill").font(VGFont.label).foregroundColor(.orange) }
        }
        .padding(.vertical, VGSpacing.xs).contentShape(Rectangle())
        .contextMenu {
            Button(L10n.edit.localized) { appState.editingCipher = cipher; appState.showEditSheet = true }
            Button(L10n.Items.duplicate.localized) { Task { await appState.duplicateCipher(cipher) } }
            if appState.activeVaultKind != .keepass {
                Button(cipher.favorite ? L10n.Items.removeFavorite.localized : L10n.Items.addFavorite.localized) {
                    Task { await appState.toggleFavorite(cipher) }
                }
            }
            if appState.isPersonalVault && !appState.folders.isEmpty {
                Menu(L10n.Items.moveToFolder.localized) {
                    Button(L10n.noFolder.localized) { Task { await appState.moveCipherToFolder(cipher.id, folderId: nil) } }
                    Divider()
                    ForEach(appState.folders) { folder in
                        Button(folder.name) { Task { await appState.moveCipherToFolder(cipher.id, folderId: folder.id) } }
                    }
                }
            }
            Divider()
            Button(L10n.delete.localized, role: .destructive) { appState.deletingCipher = cipher; appState.showDeleteConfirm = true }
        }
    }
}


// MARK: - KeePass entry icon badge (custom PNG or standard SF Symbol)

struct KeePassIconImage: View {
    let ref: KeePassIconRef
    var size: CGFloat = 34
    var glyph: CGFloat = 16
    var corner: CGFloat = VGRadius.medium

    var body: some View {
        switch ref {
        case .custom(let data):
            Group {
                if let img = NSImage(data: data) {
                    Image(nsImage: img).resizable().interpolation(.high).aspectRatio(contentMode: .fit).padding(VGSpacing.xs)
                } else {
                    Image(systemName: "key.fill").font(.system(size: glyph)).foregroundColor(VGColor.onAccent)
                }
            }
            .frame(width: size, height: size)
            .background(RoundedRectangle(cornerRadius: corner).fill(VGColor.surface))
            .clipShape(RoundedRectangle(cornerRadius: corner))
        case .standard(let idx):
            RoundedRectangle(cornerRadius: corner)
                .fill(LinearGradient(colors: [.blue, .cyan], startPoint: .topLeading, endPoint: .bottomTrailing))
                .frame(width: size, height: size)
                .overlay {
                    Image(systemName: KeePassIconRef.sfSymbol(forStandard: idx))
                        .font(.system(size: glyph, weight: .semibold)).foregroundColor(VGColor.onAccent)
                }
        }
    }
}
