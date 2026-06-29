import AppKit
import SwiftUI

extension NSUserInterfaceItemIdentifier {
    static let vaultGuardMainWindow = NSUserInterfaceItemIdentifier(
        "com.kruatech.vaultguard.main-window"
    )
}

/// Owns the single primary window independently of Settings and other AppKit windows.
/// The retained NSWindow is reused after the red close button, so reopening never
/// creates a duplicate scene or loses window-local SwiftUI state.
@MainActor
final class MainWindowController {
    static let shared = MainWindowController()

    private(set) var window: NSWindow?
    private var pendingShowRequest = false
    private var pendingWindowActions: [(NSWindow) -> Void] = []

    private init() {}

    func register(_ window: NSWindow) {
        if self.window !== window {
            self.window = window
            window.identifier = .vaultGuardMainWindow
            window.title = "VaultGuard"
            window.isReleasedWhenClosed = false
            window.tabbingMode = .disallowed
            _ = window.setFrameAutosaveName("VaultGuardMainWindow")
        }

        let actions = pendingWindowActions
        pendingWindowActions.removeAll()
        actions.forEach { $0(window) }

        if pendingShowRequest {
            showMainWindow()
        }
    }

    func withMainWindow(_ action: @escaping (NSWindow) -> Void) {
        if let window {
            action(window)
        } else {
            pendingWindowActions.append(action)
        }
    }

    @discardableResult
    func showMainWindow() -> Bool {
        guard let window else {
            pendingShowRequest = true
            NSApp.activate(ignoringOtherApps: true)
            return false
        }

        pendingShowRequest = false
        NSApp.activate(ignoringOtherApps: true)

        if window.isMiniaturized {
            window.deminiaturize(nil)
        }

        window.makeKeyAndOrderFront(nil)
        return true
    }
}

/// Finds the NSWindow created by SwiftUI's primary WindowGroup without relying on
/// NSApp.windows ordering, which can point at Settings or a sheet instead.
struct MainWindowAccessor: NSViewRepresentable {
    func makeNSView(context: Context) -> MainWindowProbeView {
        MainWindowProbeView(frame: .zero)
    }

    func updateNSView(_ nsView: MainWindowProbeView, context: Context) {
        nsView.registerCurrentWindow()
    }
}

final class MainWindowProbeView: NSView {
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        registerCurrentWindow()
    }

    func registerCurrentWindow() {
        Task { @MainActor [weak self] in
            guard let window = self?.window else { return }
            MainWindowController.shared.register(window)
        }
    }
}
