import Foundation
import AppKit

extension AppState {
    /// Copy, and note that the item was used.
    ///
    /// Separate from the plain `copyToClipboard` because not every copy comes from an entry —
    /// the generator's output and a Send link do not belong in "recently used".
    func copyToClipboard(_ text: String, from cipher: VaultCipher) {
        recordCipherUsed(cipher.id)
        copyToClipboard(text)
    }

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

        lastCopiedValue = text

        let timeout = clipboardTimeoutSeconds
        guard timeout > 0 else { return }
        let cur = text
        DispatchQueue.main.asyncAfter(deadline: .now() + TimeInterval(timeout)) { [weak self] in
            if NSPasteboard.general.string(forType: .string) == cur { NSPasteboard.general.clearContents() }
            if self?.lastCopiedValue == cur { self?.lastCopiedValue = nil }
        }
    }

    /// Drop a copied secret from the pasteboard, if it is still the one we put there.
    ///
    /// Called on lock as well as on the timer. Locking the vault and leaving the password
    /// sitting on the clipboard defeats the point of locking: anything that can read the
    /// pasteboard — another app, Universal Clipboard, a clipboard manager that ignored the
    /// concealed-type hint — still has it.
    ///
    /// The value is compared first so that a lock does not wipe something the user copied
    /// from somewhere else in the meantime.
    func clearClipboardIfOurs() {
        guard let copied = lastCopiedValue else { return }
        if NSPasteboard.general.string(forType: .string) == copied {
            NSPasteboard.general.clearContents()
        }
        lastCopiedValue = nil
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
