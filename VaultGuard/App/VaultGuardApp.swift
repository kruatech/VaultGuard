import SwiftUI

struct VaultGuardApp: App {
    @StateObject private var appState = AppState()
    @StateObject private var localization = LocalizationManager.shared
    @StateObject private var textScale = TextScaleManager.shared
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .environmentObject(appState.accounts)
                .environmentObject(localization)
                .environmentObject(textScale)
                // VGFont reads a plain static, so nothing in the view tree depends on the
                // scale as far as SwiftUI can tell. Tying the window's identity to the value
                // forces a rebuild when it changes; without it the setting only takes effect
                // on the next launch.
                .id(textScale.scale)
                .background(MainWindowAccessor())
                .onAppear {
                    NSWindow.allowsAutomaticWindowTabbing = false
                    appDelegate.appState = appState
                    appState.applyTheme()
                }
                .onOpenURL(perform: handleOpenURL)
        }
        .windowStyle(.titleBar)
        .windowToolbarStyle(.unified(showsTitle: false))
        .commands {
            CommandGroup(replacing: .newItem) {
                Button(L10n.Items.newItem.localized) {
                    NotificationCenter.default.post(name: .newItem, object: nil)
                }
                .keyboardShortcut("n", modifiers: .command)
                Divider()
                // ⌘L is the lock shortcut every password manager uses; not having it was the
                // most surprising omission. Both post a notification rather than touching
                // AppState directly, matching the existing commands: the main window picks
                // them up only while it is showing the unlocked UI, so invoking either from
                // the lock screen does nothing instead of misfiring.
                Button(L10n.Sidebar.lock.localized) {
                    NotificationCenter.default.post(name: .lockVault, object: nil)
                }
                .keyboardShortcut("l", modifiers: .command)
                Button(L10n.Sidebar.generator.localized) {
                    NotificationCenter.default.post(name: .showGenerator, object: nil)
                }
                .keyboardShortcut("g", modifiers: [.command, .shift])
                Button(L10n.Sidebar.sync.localized) {
                    NotificationCenter.default.post(name: .syncVault, object: nil)
                }
                .keyboardShortcut("r", modifiers: .command)
            }
            CommandGroup(after: .textEditing) {
                Button(L10n.search.localized) {
                    NotificationCenter.default.post(name: .focusSearch, object: nil)
                }
                .keyboardShortcut("f", modifiers: .command)
                // Second binding (⌘K) for the same action; hidden so the menu shows ⌘F only.
                Button(L10n.search.localized) {
                    NotificationCenter.default.post(name: .focusSearch, object: nil)
                }
                .keyboardShortcut("k", modifiers: .command)
                .hidden()
            }
            CommandGroup(after: .toolbar) {
                Button(L10n.Settings.textLarger.localized) { textScale.increase() }
                    .keyboardShortcut("+", modifiers: .command)
                    .disabled(!textScale.canIncrease)
                Button(L10n.Settings.textSmaller.localized) { textScale.decrease() }
                    .keyboardShortcut("-", modifiers: .command)
                    .disabled(!textScale.canDecrease)
                Button(L10n.Settings.textReset.localized) { textScale.reset() }
                    .keyboardShortcut("0", modifiers: .command)
                Divider()
            }
            CommandGroup(before: .windowList) {
                Divider()
                Button(L10n.Window.showMain.localized) {
                    MainWindowController.shared.showMainWindow()
                }
                // Moved off ⌘0, which now resets the text size — that is what ⌘0 means
                // everywhere else on the Mac, and the audit already flagged ⌘0 for "show
                // window" as surprising.
                .keyboardShortcut("0", modifiers: [.command, .shift])
            }
        }

        Settings {
            SettingsView()
                .environmentObject(appState)
                .environmentObject(appState.accounts)
                .environmentObject(localization)
                .environmentObject(textScale)
                .id(textScale.scale)
        }
    }

    private func handleOpenURL(_ url: URL) {
        guard url.scheme == "vaultguard", url.host == "unlock" else { return }
        MainWindowController.shared.showMainWindow()
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
        .onAppear { applyWindowSize(unlocked: appState.isUnlocked) }
        .onChange(of: appState.isUnlocked) { _, newValue in applyWindowSize(unlocked: newValue) }
        .sheet(isPresented: $appState.showAddAccount) {
            AuthView(isAddMode: true)
                .environmentObject(appState)
                .environmentObject(appState.accounts)
        }
    }
    /// Login/unlock screen gets a compact window; the unlocked MainView needs a large one.
    /// Same shared window, so resize the NSWindow on the locked/unlocked transition.
    private func applyWindowSize(unlocked: Bool) {
        DispatchQueue.main.async {
            MainWindowController.shared.withMainWindow { w in
                if unlocked {
                    w.maxSize = NSSize(
                        width: CGFloat.greatestFiniteMagnitude,
                        height: CGFloat.greatestFiniteMagnitude
                    )
                    w.minSize = NSSize(width: 900, height: 600)
                    if w.frame.width < 900 || w.frame.height < 600 {
                        w.setContentSize(NSSize(width: 1100, height: 720))
                        w.center()
                    }
                } else {
                    // Auth/login window: fixed height (non-resizable vertically).
                    w.minSize = NSSize(width: 500, height: 770)
                    w.maxSize = NSSize(
                        width: CGFloat.greatestFiniteMagnitude,
                        height: 770
                    )
                    w.setContentSize(NSSize(width: 525, height: 770))
                    w.center()
                }
            }
        }
    }

    private func installEventMonitor() {
        // Remove any existing monitor first to prevent leaks
        removeEventMonitor()
        // `.mouseMoved` used to be in this list, so a cursor merely passing over the window —
        // or resting on it while the user worked in another app — kept resetting the idle timer,
        // and the vault never auto-locked. Using the vault means typing, clicking or scrolling.
        eventMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.keyDown, .leftMouseDown, .rightMouseDown, .scrollWheel]
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

/// Restores the main window when the user reopens the running app from the Dock
/// or Finder. Explicit app termination still locks the active vault first.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    var appState: AppState?

    func applicationShouldTerminateAfterLastWindowClosed(
        _ sender: NSApplication
    ) -> Bool {
        false
    }

    func applicationShouldHandleReopen(
        _ sender: NSApplication,
        hasVisibleWindows flag: Bool
    ) -> Bool {
        MainWindowController.shared.showMainWindow()
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        appState?.lock()
    }
}

extension Notification.Name {
    static let newItem = Notification.Name("newItem")
    static let focusSearch = Notification.Name("focusSearch")
    static let lockVault = Notification.Name("lockVault")
    static let showGenerator = Notification.Name("showGenerator")
    static let syncVault = Notification.Name("syncVault")
}
