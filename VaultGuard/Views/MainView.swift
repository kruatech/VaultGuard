import SwiftUI

struct MainView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        NavigationSplitView(
            sidebar: { SidebarView() },
            content: { ItemsListView() },
            detail: { DetailView() }
        )
        .navigationSplitViewStyle(.balanced)
        .sheet(isPresented: $appState.showEditSheet) {
            EditItemView(cipher: appState.editingCipher).environmentObject(appState)
        }
        .sheet(isPresented: $appState.showGenerator) {
            GeneratorView().environmentObject(appState)
        }
        .sheet(isPresented: $appState.showSettings) {
            SettingsView()
                .environmentObject(appState)
                .environmentObject(appState.accounts)
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
        .overlay(alignment: .bottomTrailing) { toastOverlay }
        .onReceive(NotificationCenter.default.publisher(for: .newItem)) { _ in
            appState.startNewItem()
        }
        // Keyboard shortcuts
        .background(KeyboardShortcutView(appState: appState))
    }

    @ViewBuilder
    private var toastOverlay: some View {
        VStack(spacing: 6) {
            ForEach(appState.toasts) { toast in
                HStack(spacing: 6) {
                    Image(systemName: toast.icon).font(.system(size: 12, weight: .bold))
                    Text(toast.text).font(.system(size: 13, weight: .medium))
                }
                .padding(.horizontal, 14).padding(.vertical, 8)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 10))
                .shadow(color: .black.opacity(0.1), radius: 8, y: 4)
                .transition(.asymmetric(insertion: .move(edge: .bottom).combined(with: .opacity), removal: .opacity))
            }
        }
        .padding(16).animation(.spring(response: 0.3), value: appState.toasts.count)
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
