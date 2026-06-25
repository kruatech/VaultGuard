import SwiftUI
import AppKit

struct SidebarView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var accounts: AccountManager
    @FocusState private var searchFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            vaultPicker

            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundColor(.secondary).font(.system(size: 12))
                TextField("\(L10n.search.localized)… ⌘K", text: $appState.searchText)
                    .textFieldStyle(.plain).font(.system(size: 13)).focused($searchFocused)
                if !appState.searchText.isEmpty {
                    Button(action: { appState.searchText = "" }) {
                        Image(systemName: "xmark.circle.fill").foregroundColor(.secondary).font(.system(size: 11))
                    }.buttonStyle(.plain)
                }
            }
            .padding(8).background(Color(NSColor.controlBackgroundColor)).cornerRadius(8)
            .padding(.horizontal, 10).padding(.top, 4).padding(.bottom, 4)

            List(selection: Binding<VaultFilter?>(
                get: { appState.filter },
                set: { if let f = $0 { DispatchQueue.main.async { appState.filter = f; appState.selectedCipherId = nil } } }
            )) {
                Section(L10n.Sidebar.vault.localized) {
                    sidebarRow(.all, icon: "tray.fill", label: L10n.Sidebar.allItems.localized)
                    sidebarRow(.favorites, icon: "star.fill", label: L10n.Sidebar.favorites.localized)
                }

                Section(L10n.Sidebar.types.localized) {
                    ForEach(CipherType.allCases) { type in
                        sidebarRow(.type(type), icon: type.icon, label: type.localizedName)
                    }
                }

                if appState.isPersonalVault {
                    if !appState.activeFolders.isEmpty {
                        Section(L10n.Sidebar.folders.localized) {
                            ForEach(appState.activeFolders) { folder in
                                folderRow(folder)
                            }
                            .onMove { source, dest in
                                appState.moveFolderInOrder(from: source, to: dest)
                            }
                        }
                    }
                } else {
                    if !appState.activeCollections.isEmpty {
                        Section(L10n.Sidebar.collections.localized) {
                            ForEach(appState.activeCollections) { col in
                                sidebarRow(.collection(col.id), icon: "rectangle.stack.fill", label: col.name)
                            }
                        }
                    }
                }

                Section {
                    sidebarRow(.trash, icon: "trash", label: L10n.Sidebar.trash.localized)
                }
            }
            .listStyle(.sidebar)

            Divider()

            VStack(spacing: 2) {
                if appState.isPersonalVault {
                    Button(action: { appState.folderInputName = ""; appState.showCreateFolder = true }) {
                        Label(L10n.Sidebar.newFolder.localized, systemImage: "folder.badge.plus")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }.buttonStyle(SidebarButtonStyle())
                }

                Button(action: { appState.showGenerator = true }) {
                    Label(L10n.Sidebar.generator.localized, systemImage: "key.fill")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }.buttonStyle(SidebarButtonStyle())

                Button(action: { appState.showSettings = true }) {
                    Label(L10n.Sidebar.settings.localized, systemImage: "gearshape.fill")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }.buttonStyle(SidebarButtonStyle())

                profileMenu
            }
            .padding(8)
        }
        .onReceive(NotificationCenter.default.publisher(for: .focusSearch)) { _ in searchFocused = true }
        .alert(L10n.Folder.newTitle.localized, isPresented: $appState.showCreateFolder) {
            TextField(L10n.Folder.namePlaceholder.localized, text: $appState.folderInputName)
            Button(L10n.create.localized) {
                let name = appState.folderInputName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty else { return }
                Task { await appState.createFolder(name: name) }
            }
            Button(L10n.cancel.localized, role: .cancel) {}
        }
        .alert(L10n.Folder.renameTitle.localized, isPresented: $appState.showRenameFolder) {
            TextField(L10n.Folder.namePlaceholder.localized, text: $appState.folderInputName)
            Button(L10n.save.localized) {
                let name = appState.folderInputName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty, let folder = appState.renamingFolder else { return }
                Task { await appState.renameFolder(id: folder.id, newName: name) }
            }
            Button(L10n.cancel.localized, role: .cancel) {}
        }
        .confirmationDialog(
            L10n.Folder.deleteTitle.localized(appState.deletingFolder?.name ?? ""),
            isPresented: $appState.showDeleteFolderConfirm, titleVisibility: .visible
        ) {
            Button(L10n.delete.localized, role: .destructive) {
                if let f = appState.deletingFolder { Task { await appState.deleteFolder(id: f.id) } }
            }
            Button(L10n.cancel.localized, role: .cancel) {}
        } message: { Text(L10n.Folder.deleteMessage.localized) }
    }

    // MARK: - Vault Picker

    private var vaultPicker: some View {
        Menu {
            Button(action: { appState.switchVault(to: nil) }) {
                HStack {
                    Label(L10n.Sidebar.myVault.localized, systemImage: "person.fill")
                    if appState.isPersonalVault { Image(systemName: "checkmark") }
                }
            }
            if !appState.organizations.isEmpty {
                Divider()
                ForEach(appState.organizations) { org in
                    Button(action: { appState.switchVault(to: org.id) }) {
                        HStack {
                            Label(org.name, systemImage: "person.2.wave.2.fill")
                            if appState.activeVaultId == org.id { Image(systemName: "checkmark") }
                        }
                    }
                }
            }
        } label: {
            HStack(spacing: 8) {
                Image(systemName: appState.isPersonalVault ? "person.fill" : "person.2.wave.2.fill")
                    .font(.system(size: 12)).foregroundColor(.accentColor)
                Text(appState.activeVaultName).font(.system(size: 13, weight: .semibold)).lineLimit(1)
                Spacer()
                Image(systemName: "chevron.up.chevron.down").font(.system(size: 10)).foregroundColor(.secondary)
            }
            .padding(.horizontal, 10).padding(.vertical, 8)
            .background(Color(NSColor.controlBackgroundColor)).cornerRadius(8)
        }
        .buttonStyle(.plain).padding(.horizontal, 10).padding(.top, 8)
    }

    // MARK: - Rows

    private func sidebarRow(_ filter: VaultFilter, icon: String, label: String) -> some View {
        HStack {
            Label(label, systemImage: icon)
            Spacer()
            Text("\(appState.countFor(filter: filter))")
                .font(.system(size: 11)).foregroundColor(.secondary).monospacedDigit()
        }.tag(filter).handCursor()
    }

    private func folderRow(_ folder: VaultFolder) -> some View {
        HStack {
            Label(folder.name, systemImage: "folder.fill")
            Spacer()
            Text("\(appState.countFor(filter: .folder(folder.id)))")
                .font(.system(size: 11)).foregroundColor(.secondary).monospacedDigit()
        }
        .tag(VaultFilter.folder(folder.id))
        .contextMenu {
            Button("misc.rename".localized) {
                appState.renamingFolder = folder; appState.folderInputName = folder.name; appState.showRenameFolder = true
            }
            Divider()
            Button("misc.sortAlphabetically".localized) { appState.folderSortMode = .alphabetical }
            Button("misc.sortManually".localized) { appState.folderSortMode = .manual }
            Divider()
            Button(L10n.delete.localized, role: .destructive) {
                appState.deletingFolder = folder; appState.showDeleteFolderConfirm = true
            }
        }
        .handCursor()
    }

    // MARK: - Profile Menu

    private var profileMenu: some View {
        Menu {
            if accounts.ordered.count > 1 || accounts.hasAccounts {
                ForEach(accounts.ordered) { acc in
                    Button(action: {
                        if acc.id != accounts.activeAccountId { Task { await appState.switchAccount(to: acc.id) } }
                    }) {
                        HStack {
                            Text(acc.displayName)
                            if acc.id == accounts.activeAccountId { Image(systemName: "checkmark") }
                        }
                    }
                }
                Divider()
            }
            Button(L10n.Auth.addAccount.localized) { appState.showAddAccount = true }
            Divider()
            Button(L10n.Sidebar.sync.localized) { Task { await appState.refresh() } }
            Button(L10n.Sidebar.lock.localized) { appState.lock() }
            Button(L10n.Sidebar.logout.localized, role: .destructive) { appState.logout() }
        } label: {
            HStack(spacing: 8) {
                Circle()
                    .fill(.linearGradient(colors: [.blue, .purple], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 28, height: 28)
                    .overlay { Text(String(appState.profileName.prefix(1)).uppercased()).font(.system(size: 11, weight: .bold)).foregroundColor(.white) }
                VStack(alignment: .leading, spacing: 1) {
                    Text(accounts.activeAccount?.label ?? (appState.profileName.isEmpty ? "misc.user".localized : appState.profileName))
                        .font(.system(size: 12, weight: .semibold)).lineLimit(1)
                    Text(appState.profileEmail).font(.system(size: 10)).foregroundColor(.secondary).lineLimit(1)
                }
                Spacer()
            }
            .padding(.horizontal, 8).padding(.vertical, 6).contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .handCursor()
    }
}

struct SidebarButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .medium))
            .padding(.horizontal, 8).padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(configuration.isPressed ? Color.accentColor.opacity(0.1) : .clear)
            .cornerRadius(6)
            .contentShape(Rectangle())
            .handCursor()
    }
}

