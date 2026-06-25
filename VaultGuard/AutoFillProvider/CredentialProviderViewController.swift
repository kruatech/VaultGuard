import AuthenticationServices
import SwiftUI

/// System AutoFill credential provider. Appears in Safari and other apps when the
/// user picks VaultGuard for a login field.
///
/// Requires (paid Apple Developer account): the "AutoFill Credential Provider"
/// capability on this target and the main app, a shared App Group for the cache,
/// and the shared Keychain access group (already in the entitlements).
class CredentialProviderViewController: ASCredentialProviderViewController {

    // MARK: - Lifecycle

    /// Show the credential list for the requested services (after biometric unlock).
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        present(
            AutoFillListView(
                serviceIdentifiers: serviceIdentifiers,
                onSelect: { [weak self] cred in self?.complete(cred) },
                onCancel: { [weak self] in self?.cancel(.userCanceled) },
                onOpenApp: { [weak self] in self?.openMainApp() }
            )
        )
    }

    /// The vault is unlocked by the main app, not silently here, so we can't provide without UI.
    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        cancel(.userInteractionRequired)
    }

    /// Return the credential for a specific identity (e.g. QuickType bar tap), or prompt the
    /// user to open VaultGuard if the vault is locked.
    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        present(
            AutoFillProvideView(
                identity: credentialIdentity,
                onComplete: { [weak self] cred in self?.complete(cred) },
                onCancel: { [weak self] in self?.cancel(.userCanceled) },
                onOpenApp: { [weak self] in self?.openMainApp() }
            )
        )
    }

    // MARK: - Helpers

    private func complete(_ cred: AutoFillCredential) {
        let credential = ASPasswordCredential(user: cred.user, password: cred.password)
        extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
    }

    private func cancel(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }

    /// Bring the main app forward so the user can unlock (Variant B). Requires the `vaultguard`
    /// URL scheme registered in the main app.
    private func openMainApp() {
        guard let url = URL(string: "vaultguard://unlock") else { return }
        extensionContext.open(url, completionHandler: nil)
    }

    private func present(_ rootView: some View) {
        let hosting = NSHostingController(rootView: rootView)
        addChild(hosting)
        hosting.view.frame = view.bounds
        hosting.view.autoresizingMask = [.width, .height]
        view.addSubview(hosting.view)
    }
}

// MARK: - List UI (prepareCredentialList)

struct AutoFillListView: View {
    let serviceIdentifiers: [ASCredentialServiceIdentifier]
    let onSelect: (AutoFillCredential) -> Void
    let onCancel: () -> Void
    let onOpenApp: () -> Void

    @State private var state: LoadState = .locked
    @State private var matches: [AutoFillCredential] = []
    @State private var all: [AutoFillCredential] = []
    @State private var search = ""
    @State private var errorText: String?

    enum LoadState { case locked, loading, loaded }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content
        }
        .frame(width: 340, height: 440)
    }

    private var header: some View {
        HStack {
            Image(systemName: "lock.shield.fill").foregroundColor(.accentColor)
            Text("VaultGuard").font(.system(size: 15, weight: .bold))
            Spacer()
            Button(action: onCancel) {
                Image(systemName: "xmark.circle.fill").font(.system(size: 18)).foregroundColor(.secondary)
            }.buttonStyle(.plain)
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
    }

    @ViewBuilder
    private var content: some View {
        switch state {
        case .locked:
            unlockPrompt
        case .loading:
            ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
        case .loaded:
            list
        }
    }

    private var unlockPrompt: some View {
        VStack(spacing: 14) {
            Image(systemName: "lock.fill").font(.system(size: 36, weight: .ultraLight)).foregroundColor(.secondary)
            Text(errorText ?? L10n.AutoFill.errLocked.localized)
                .font(.system(size: 12)).foregroundColor(errorText == nil ? .secondary : .red)
                .multilineTextAlignment(.center)
            Button(L10n.AutoFill.openApp.localized) { onOpenApp() }.buttonStyle(.borderedProminent)
            Button(L10n.AutoFill.tryAgain.localized) { unlock() }.buttonStyle(.plain).foregroundColor(.accentColor)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear(perform: unlock)
    }

    private var list: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundColor(.secondary).font(.system(size: 12))
                TextField(L10n.search.localized, text: $search).textFieldStyle(.plain).font(.system(size: 13))
            }
            .padding(8).background(Color(NSColor.controlBackgroundColor)).cornerRadius(8)
            .padding(.horizontal, 12).padding(.vertical, 8)

            List(filtered, id: \.recordIdentifier) { cred in
                Button { onSelect(cred) } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(cred.name).font(.system(size: 13, weight: .semibold))
                        Text(cred.user).font(.system(size: 11)).foregroundColor(.secondary)
                    }
                }.buttonStyle(.plain)
            }
        }
    }

    private var filtered: [AutoFillCredential] {
        let base = matches.isEmpty ? all : matches
        guard !search.isEmpty else { return base }
        return base.filter { $0.name.localizedCaseInsensitiveContains(search) || $0.user.localizedCaseInsensitiveContains(search) }
    }

    private func unlock() {
        state = .loading
        Task {
            do {
                try await AutoFillVault.shared.unlock()
                all = AutoFillVault.shared.credentials
                matches = AutoFillVault.shared.matches(for: serviceIdentifiers)
                state = .loaded
            } catch {
                errorText = error.localizedDescription
                state = .locked
            }
        }
    }
}

// MARK: - Single-credential UI (prepareInterfaceToProvideCredential)

struct AutoFillProvideView: View {
    let identity: ASPasswordCredentialIdentity
    let onComplete: (AutoFillCredential) -> Void
    let onCancel: () -> Void
    let onOpenApp: () -> Void

    @State private var errorText: String?
    @State private var working = true

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.shield.fill").font(.system(size: 40)).foregroundColor(.accentColor)
            Text("VaultGuard").font(.system(size: 17, weight: .bold))
            if working {
                ProgressView()
            } else if let errorText {
                Text(errorText).font(.system(size: 12)).foregroundColor(.red).multilineTextAlignment(.center)
                HStack(spacing: 12) {
                    Button(L10n.cancel.localized) { onCancel() }
                    Button(L10n.AutoFill.openApp.localized) { onOpenApp() }.buttonStyle(.borderedProminent)
                }
                Button(L10n.AutoFill.tryAgain.localized) { unlock() }.buttonStyle(.plain).foregroundColor(.accentColor)
            }
        }
        .padding(30)
        .frame(width: 300, height: 240)
        .onAppear(perform: unlock)
    }

    private func unlock() {
        working = true
        Task {
            do {
                try await AutoFillVault.shared.unlock()
                if let cred = AutoFillVault.shared.credential(for: identity) {
                    onComplete(cred)
                } else {
                    errorText = L10n.AutoFill.errNoMatch.localized
                    working = false
                }
            } catch {
                errorText = error.localizedDescription
                working = false
            }
        }
    }
}
