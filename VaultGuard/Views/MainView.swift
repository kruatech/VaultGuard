import SwiftUI

struct MainView: View {
    @EnvironmentObject var appState: AppState
    @FocusState private var searchFocused: Bool

    var body: some View {
        NavigationSplitView {
            SidebarView()
        } detail: {
            VStack(spacing: 0) {
                appGroupBanner
                unifiedHeader
                batchProgressBar
                Divider()
                HSplitView {
                    ItemsListView()
                        .frame(minWidth: 280, idealWidth: 340, maxWidth: 480)
                    DetailView()
                        .frame(minWidth: 360, maxWidth: .infinity)
                }
            }
        }
        .navigationSplitViewStyle(.balanced)
        .sheet(isPresented: $appState.showEditSheet) {
            EditItemView(cipher: appState.editingCipher).environmentObject(appState)
        }
        .sheet(isPresented: $appState.showGenerator) {
            GeneratorView().environmentObject(appState)
        }
        .sheet(isPresented: $appState.showSends) {
            SendsView().environmentObject(appState)
        }
        .sheet(isPresented: $appState.showPasswordHealth) {
            PasswordHealthView().environmentObject(appState)
        }
        .confirmationDialog(
            L10n.DeleteConfirm.title.localized(appState.deletingCipher?.name ?? ""),
            isPresented: $appState.showDeleteConfirm, titleVisibility: .visible
        ) {
            Button(L10n.delete.localized, role: .destructive) {
                if let cipher = appState.deletingCipher { Task { await appState.deleteCipher(cipher) } }
            }
            Button(L10n.cancel.localized, role: .cancel) {}
        } message: { Text(L10n.DeleteConfirm.message.localized) }
        // Separate from the single-item dialog: the message has to say how many items are
        // about to go, and a bulk delete is the one place where a mis-click is expensive.
        .confirmationDialog(
            L10n.Items.bulkDeleteConfirm.localized(appState.selectedCipherIds.count),
            isPresented: $appState.showBulkDeleteConfirm, titleVisibility: .visible
        ) {
            Button(L10n.Items.bulkDelete.localized(appState.selectedCipherIds.count), role: .destructive) {
                Task { await appState.deleteSelectedCiphers() }
            }
            Button(L10n.cancel.localized, role: .cancel) {}
        } message: { Text(L10n.DeleteConfirm.message.localized) }
        .overlay(alignment: .bottomTrailing) { toastOverlay }
        .onReceive(NotificationCenter.default.publisher(for: .newItem)) { _ in
            appState.startNewItem()
        }
        .onReceive(NotificationCenter.default.publisher(for: .focusSearch)) { _ in searchFocused = true }
        .onReceive(NotificationCenter.default.publisher(for: .lockVault)) { _ in appState.lock() }
        .onReceive(NotificationCenter.default.publisher(for: .showGenerator)) { _ in
            appState.showGenerator = true
        }
        // `refresh()` already reports success and failure through a toast, and is a no-op-ish
        // re-read for KeePass vaults, so ⌘R is safe from either vault kind.
        .onReceive(NotificationCenter.default.publisher(for: .syncVault)) { _ in
            Task { await appState.refresh() }
        }
        // Keyboard shortcuts
        .background(KeyboardShortcutView(appState: appState))
    }

    /// Per-item progress for a bulk action. Each item is a separate network round trip, so
    /// without this a fifty-item delete looks like the window has hung.
    @ViewBuilder
    private var batchProgressBar: some View {
        if appState.isBatchRunning {
            HStack(spacing: VGSpacing.m) {
                ProgressView(value: appState.batchProgress).frame(maxWidth: 200)
                Text("\(appState.batchDone) / \(appState.batchTotal)")
                    .font(VGFont.caption).foregroundColor(VGColor.secondary)
                    .accessibilityValue(Text("\(appState.batchDone) / \(appState.batchTotal)"))
                Spacer()
            }
            .padding(.horizontal, VGSpacing.l)
            .padding(.vertical, VGSpacing.s)
            .background(VGColor.surface)
        }
    }

    /// Shown when the shared App Group container is unreachable — usually a provisioning
    /// mismatch between the app and the extension. Without it the only symptom is that
    /// AutoFill silently never has any credentials, with nothing on screen to explain why.
    @ViewBuilder
    private var appGroupBanner: some View {
        if !SharedConfig.isAppGroupAvailable {
            HStack(spacing: VGSpacing.s) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.orange)
                Text(L10n.Account.appGroupUnavailable.localized)
                    .font(VGFont.label).foregroundColor(VGColor.primary)
                Spacer()
            }
            .padding(.horizontal, VGSpacing.l)
            .padding(.vertical, VGSpacing.s)
            .background(Color.orange.opacity(0.12))
        }
    }

    // MARK: - Unified header (spans list + detail)

    private var unifiedHeader: some View {
        HStack(spacing: VGSpacing.l) {
            VStack(alignment: .leading, spacing: VGSpacing.xxs) {
                Text(appState.filterTitle).font(VGFont.largeTitle).lineLimit(1)
                Text(L10n.Items.itemsCount.localized(appState.filteredCiphers.count, appState.activeVaultName))
                    .font(VGFont.label).foregroundColor(VGColor.secondary).lineLimit(1)
            }

            Spacer(minLength: VGSpacing.l)

            HStack(spacing: VGSpacing.s) {
                Image(systemName: "magnifyingglass").foregroundColor(VGColor.secondary).font(VGFont.label)
                TextField("\(L10n.search.localized)…", text: $appState.searchText)
                    .textFieldStyle(.plain).font(VGFont.body).focused($searchFocused)
                    // Identifiers rather than labels for the elements UI tests drive: a label
                    // is user-facing text that changes with the language, and a test that
                    // matches on it passes or fails depending on the locale.
                if !appState.searchText.isEmpty {
                    Button(action: { appState.searchText = "" }) {
                        Image(systemName: "xmark.circle.fill").foregroundColor(VGColor.secondary).font(VGFont.caption)
                    }.buttonStyle(.plain).vgHelp(L10n.clear.localized)
                }
            }
            .padding(.horizontal, VGSpacing.m).frame(height: 28).frame(maxWidth: 320)
            .background(VGColor.surface).cornerRadius(VGRadius.medium)

            HStack(spacing: VGSpacing.s) {
                if appState.filter != .trash {
                    Button(action: { appState.startNewItem() }) {
                        Label(L10n.Items.newItem.localized, systemImage: "plus").font(VGFont.labelMedium)
                    }.buttonStyle(.borderedProminent).controlSize(.small).handCursor()
                }
                Button(action: { appState.sort = appState.sort == .name ? .modified : .name }) {
                    Label(appState.sort.displayName, systemImage: "arrow.up.arrow.down").font(VGFont.labelMedium)
                }.buttonStyle(.bordered).controlSize(.small).handCursor()
                Button(action: { Task { await appState.refresh() } }) {
                    Image(systemName: "arrow.clockwise").font(VGFont.label)
                }.buttonStyle(.bordered).controlSize(.small).handCursor()
                    .vgHelp(L10n.Sidebar.sync.localized)
            }
        }
        .padding(.horizontal, VGSpacing.xxl).padding(.vertical, VGSpacing.l)
    }

    @ViewBuilder
    private var toastOverlay: some View {
        VStack(spacing: VGSpacing.s) {
            ForEach(appState.toasts) { toast in
                HStack(spacing: VGSpacing.s) {
                    Image(systemName: toast.icon).font(VGFont.labelBold)
                    Text(toast.text).font(VGFont.bodyMedium)
                }
                .padding(.horizontal, VGSpacing.xl).padding(.vertical, VGSpacing.m)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: VGRadius.large))
                .shadow(color: .black.opacity(0.1), radius: 8, y: 4)
                .transition(.asymmetric(insertion: .move(edge: .bottom).combined(with: .opacity), removal: .opacity))
            }
        }
        .padding(VGSpacing.xxl).animation(.spring(response: 0.3), value: appState.toasts.count)
    }
}

// MARK: - Keyboard Shortcuts Handler

struct KeyboardShortcutView: NSViewRepresentable {
    let appState: AppState

    func makeNSView(context: Context) -> KeyboardHandlerView {
        let view = KeyboardHandlerView()
        view.appState = appState
        return view
    }

    func updateNSView(_ nsView: KeyboardHandlerView, context: Context) {
        // Keep the reference current if the environment's AppState instance changes.
        nsView.appState = appState
    }
}

class KeyboardHandlerView: NSView {
    /// Set by `KeyboardShortcutView`. Weak so the handler never keeps AppState alive.
    weak var appState: AppState?

    override var acceptsFirstResponder: Bool { true }

    override func keyDown(with event: NSEvent) {
        // `keyDown` is delivered on the main thread; AppState is @MainActor, so it is
        // safe to touch it directly here.
        guard let appState = MainActor.assumeIsolated({ self.appState }) else {
            super.keyDown(with: event)
            return
        }

        // ⌘C — copy password
        if event.modifierFlags.contains(.command) && event.charactersIgnoringModifiers == "c" && !event.modifierFlags.contains(.shift) {
            MainActor.assumeIsolated { appState.copySelectedPassword() }
            return
        }
        // ⌘⇧C — copy username
        if event.modifierFlags.contains(.command) && event.modifierFlags.contains(.shift) && event.charactersIgnoringModifiers == "c" {
            MainActor.assumeIsolated { appState.copySelectedUsername() }
            return
        }

        switch event.keyCode {
        case 125: // ↓
            MainActor.assumeIsolated { appState.selectNextCipher() }
        case 126: // ↑
            MainActor.assumeIsolated { appState.selectPreviousCipher() }
        case 36: // Enter — edit selected
            MainActor.assumeIsolated {
                if let cipher = appState.selectedCipher {
                    appState.editingCipher = cipher
                    appState.showEditSheet = true
                }
            }
        case 53: // Escape — deselect
            MainActor.assumeIsolated { appState.selectedCipherId = nil }
        default:
            super.keyDown(with: event)
        }
    }
}
