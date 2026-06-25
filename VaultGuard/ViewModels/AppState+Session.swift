import Foundation
import AppKit

extension AppState {
    // MARK: - Sleep Lock

    func setupSleepObservers() {
        removeSleepObservers()

        let ws = NSWorkspace.shared.notificationCenter
        let nc = DistributedNotificationCenter.default()

        sleepObservers.append(
            ws.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.lock() }
            }
        )
        sleepObservers.append(
            ws.addObserver(forName: NSWorkspace.screensDidSleepNotification, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.lock() }
            }
        )
        sleepObservers.append(
            nc.addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.lock() }
            }
        )
        sleepObservers.append(
            ws.addObserver(forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.lock() }
            }
        )
    }

    func removeSleepObservers() {
        for obs in sleepObservers {
            NSWorkspace.shared.notificationCenter.removeObserver(obs)
            DistributedNotificationCenter.default().removeObserver(obs)
        }
        sleepObservers.removeAll()
    }

    // MARK: - Auto-lock

    func startAutoLockTimer() {
        autoLockTimer?.invalidate()
        let timeout = UserDefaults.standard.integer(forKey: "lockTimeout")
        guard timeout > 0 else { return }
        lastActivityDate = Date()
        autoLockTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self, self.isUnlocked else { return }
                if Date().timeIntervalSince(self.lastActivityDate) >= TimeInterval(timeout) { self.lock() }
            }
        }
    }

    func recordActivity() { lastActivityDate = Date() }

    func applyTheme() {
        let raw = UserDefaults.standard.string(forKey: "appTheme") ?? "system"
        NSApp.appearance = (AppTheme(rawValue: raw) ?? .system).appearance
    }
}
