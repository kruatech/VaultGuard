import Foundation
import AppKit

extension AppState {
    func copyToClipboard(_ text: String) {
        let pb = NSPasteboard.general
        let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
        let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
        // Declaring the concealed/transient types signals clipboard managers and
        // Universal Clipboard not to record or sync the secret.
        pb.declareTypes([.string, concealed, transient], owner: nil)
        pb.setString(text, forType: .string)
        pb.setString(text, forType: concealed)
        pb.setString("", forType: transient)
        showToast(.copied())

        let timeout = clipboardTimeoutSeconds
        guard timeout > 0 else { return }
        let cur = text
        DispatchQueue.main.asyncAfter(deadline: .now() + TimeInterval(timeout)) {
            if NSPasteboard.general.string(forType: .string) == cur { NSPasteboard.general.clearContents() }
        }
    }

    /// Auto-clear timeout in seconds. Enabled (30s) by default until the user
    /// changes it in Settings; `0` means "never clear".
    private var clipboardTimeoutSeconds: Int {
        let defaults = UserDefaults.standard
        guard defaults.object(forKey: "clipboardTimeout") != nil else { return 30 }
        return defaults.integer(forKey: "clipboardTimeout")
    }

    func showToast(_ t: ToastMessage) {
        toasts.append(t)
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { [weak self] in self?.toasts.removeAll { $0.id == t.id } }
    }
}
