import SwiftUI

struct VaultGuardApp: App {
    @StateObject private var appState = AppState()
    @StateObject private var localization = LocalizationManager.shared
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .environmentObject(appState.accounts)
                .environmentObject(localization)
                .frame(minWidth: 900, minHeight: 600)
                .onAppear {
                    NSWindow.allowsAutomaticWindowTabbing = false
                    appState.applyTheme()
                }
                .onOpenURL { url in
                    guard url.scheme == "vaultguard", url.host == "unlock" else { return }
                    NSApp.activate(ignoringOtherApps: true)
                    NSApp.windows.first?.makeKeyAndOrderFront(nil)
                }
        }
        .windowStyle(.titleBar)
        .windowToolbarStyle(.unified(showsTitle: false))
        .commands {
            CommandGroup(replacing: .newItem) {
                Button(L10n.Items.newItem.localized) {
                    NotificationCenter.default.post(name: .newItem, object: nil)
                }
                .keyboardShortcut("n", modifiers: .command)
            }
            CommandGroup(after: .textEditing) {
                Button(L10n.search.localized) {
                    NotificationCenter.default.post(name: .focusSearch, object: nil)
                }
                .keyboardShortcut("k", modifiers: .command)
            }
        }
    }
}

/// Minimal app booted only while unit tests run, so the real app (and its login
/// flow) doesn't start inside the XCTest host and trigger the SwiftUI-lifecycle
/// "More than one NSApplication instance was created" crash.
struct VaultGuardTestApp: App {
    var body: some Scene {
        WindowGroup { EmptyView() }
    }
}

/// Real `@main` entry point: pick the empty app under XCTest, the real app otherwise.
@main
struct AppLauncher {
    static func main() {
        if ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil {
            VaultGuardTestApp.main()
        } else {
            VaultGuardApp.main()
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var appState: AppState
    @State private var eventMonitor: Any?
    var body: some View {
        Group {
            if appState.isUnlocked {
                MainView()
                    .onAppear { installEventMonitor() }
                    .onDisappear { removeEventMonitor() }
            } else {
                AuthView()
            }
        }
        .animation(.easeInOut(duration: 0.3), value: appState.isUnlocked)
        .sheet(isPresented: $appState.showAddAccount) {
            AuthView(isAddMode: true)
                .environmentObject(appState)
                .environmentObject(appState.accounts)
        }
    }
    private func installEventMonitor() {
        // Remove any existing monitor first to prevent leaks
        removeEventMonitor()
        eventMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.keyDown, .leftMouseDown, .rightMouseDown, .scrollWheel, .mouseMoved]
        ) { [weak appState] event in
            appState?.recordActivity()
            return event
        }
    }
    private func removeEventMonitor() {
        if let monitor = eventMonitor {
            NSEvent.removeMonitor(monitor)
            eventMonitor = nil
        }
    }
}

extension Notification.Name {
    static let newItem = Notification.Name("newItem")
    static let focusSearch = Notification.Name("focusSearch")
}
