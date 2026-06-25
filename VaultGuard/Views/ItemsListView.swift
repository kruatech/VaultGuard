import SwiftUI
import AppKit

struct ItemsListView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(appState.filterTitle).font(.system(size: 18, weight: .bold))
                    Text(L10n.Items.itemsCount.localized(appState.filteredCiphers.count, appState.activeVaultName))
                        .font(.system(size: 12)).foregroundColor(.secondary)
                }
                Spacer()
            }.padding(.horizontal, 16).padding(.top, 16).padding(.bottom, 10)

            HStack(spacing: 6) {
                if appState.filter != .trash {
                    Button(action: { appState.startNewItem() }) {
                        Label(L10n.Items.newItem.localized, systemImage: "plus").font(.system(size: 12, weight: .medium))
                    }.buttonStyle(.borderedProminent).controlSize(.small).handCursor()
                }

                Button(action: { appState.sort = appState.sort == .name ? .modified : .name }) {
                    Label(appState.sort.displayName, systemImage: "arrow.up.arrow.down").font(.system(size: 12, weight: .medium))
                }.buttonStyle(.bordered).controlSize(.small).handCursor()

                Spacer()

                Button(action: { Task { await appState.refresh() } }) {
                    Image(systemName: "arrow.clockwise").font(.system(size: 12))
                }.buttonStyle(.bordered).controlSize(.small).handCursor()
            }.padding(.horizontal, 12).padding(.bottom, 8)

            Divider()

            if appState.filteredCiphers.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "magnifyingglass").font(.system(size: 36, weight: .ultraLight)).foregroundColor(Color(NSColor.quaternaryLabelColor))
                    Text(L10n.Items.notFound.localized).font(.system(size: 14)).foregroundColor(.secondary)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    List(selection: $appState.selectedCipherId) {
                        ForEach(appState.filteredCiphers) { cipher in
                            CipherRowView(cipher: cipher).tag(cipher.id).id(cipher.id).handCursor()
                        }
                    }
                    .listStyle(.plain)
                    .onChange(of: appState.selectedCipherId) { newId in
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
        HStack(spacing: 10) {
            RoundedRectangle(cornerRadius: 8).fill(accentGradient).frame(width: 34, height: 34)
                .overlay { Text(cipher.initials).font(.system(size: 13, weight: .bold)).foregroundColor(.white) }
            VStack(alignment: .leading, spacing: 2) {
                Text(cipher.name).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                if !cipher.displayUsername.isEmpty {
                    Text(cipher.displayUsername).font(.system(size: 11)).foregroundColor(.secondary).lineLimit(1)
                }
            }
            Spacer()
            if cipher.favorite { Image(systemName: "star.fill").font(.system(size: 12)).foregroundColor(.orange) }
        }
        .padding(.vertical, 4).contentShape(Rectangle())
        .contextMenu {
            Button(L10n.edit.localized) { appState.editingCipher = cipher; appState.showEditSheet = true }
            Button(L10n.Items.duplicate.localized) { Task { await appState.duplicateCipher(cipher) } }
            Button(cipher.favorite ? L10n.Items.removeFavorite.localized : L10n.Items.addFavorite.localized) {
                Task { await appState.toggleFavorite(cipher) }
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

    private var accentGradient: LinearGradient {
        let c: [Color] = { switch cipher.accentColorName {
        case "blue": return [.blue, .cyan]; case "green": return [.green, .mint]
        case "orange": return [.orange, .yellow]; case "purple": return [.purple, .pink]
        case "red": return [.red, .orange]; default: return [.blue, .cyan]
        } }()
        return LinearGradient(colors: c, startPoint: .topLeading, endPoint: .bottomTrailing)
    }
}

