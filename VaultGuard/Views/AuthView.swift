import SwiftUI
import AppKit

struct AuthView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var accounts: AccountManager
    @Environment(\.dismiss) private var dismiss

    /// When true, the view is presented as a sheet to add another account: it always shows
    /// the login form and dismisses itself once a new account becomes active.
    var isAddMode: Bool = false

    @State private var serverURL: String = ""
    @State private var connectionName: String = ""
    @State private var email: String = ""
    @State private var password: String = ""
    @State private var saveBiometric: Bool = true
    @State private var showPassword = false
    @State private var addingAccount = false   // tapped "add account" from the unlock screen
    @State private var passwordFallback = false // re-login the active account by password
    @State private var initialActiveId: String?
    @State private var showAccountMenu = false
    @State private var loggingIn = false   // a fresh login is in flight; hold the form until it finishes
    @AppStorage("allowSelfSigned") private var allowSelfSigned = false

    private let keychain = KeychainService.shared

    private var activeAccount: Account? { accounts.activeAccount }

    private var activeHasBiometric: Bool {
        guard let id = accounts.activeAccountId else { return false }
        return keychain.account(id).hasBiometricUnlock
    }

    /// Show the credential form (no active account, explicit add, password fallback, or the
    /// active account has no saved master password); otherwise show the biometric unlock.
    private var showLoginForm: Bool {
        isAddMode || addingAccount || passwordFallback || loggingIn || activeAccount == nil || !activeHasBiometric
    }

    private var isFreshLogin: Bool { isAddMode || addingAccount }

    var body: some View {
        ZStack {
            Color(NSColor.windowBackgroundColor).ignoresSafeArea()
            VStack(spacing: 0) {
                if isAddMode {
                    HStack {
                        Button(L10n.cancel.localized) { dismiss() }.buttonStyle(.plain).foregroundColor(.secondary).handCursor()
                        Spacer()
                    }.padding(.horizontal, 16).padding(.top, 12)
                }

                Spacer()
                VStack(spacing: 10) {
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 48, weight: .light))
                        .foregroundStyle(.linearGradient(colors: [.blue, .purple], startPoint: .topLeading, endPoint: .bottomTrailing))
                    Text(L10n.Auth.title.localized).font(.system(size: 28, weight: .bold, design: .rounded))
                    Text(L10n.Auth.subtitle.localized).font(.subheadline).foregroundColor(.secondary)
                }.padding(.bottom, 32)

                if showLoginForm { loginForm } else { unlockView }

                if showLoginForm, let err = appState.errorMessage {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.red)
                        Text(err).foregroundColor(.red)
                    }.font(.system(size: 12)).padding(.top, 12).frame(width: 320)
                }

                Spacer()
            }
        }
        .frame(minWidth: 500, minHeight: 500)
        .onAppear {
            initialActiveId = accounts.activeAccountId
            if !isFreshLogin, let acc = activeAccount {
                serverURL = acc.serverURL; email = acc.email
            }
            if !showLoginForm { Task { await appState.unlockWithBiometric() } }
        }
        .onChange(of: appState.isLoading) { loading in
            if !loading { loggingIn = false }
            // In add mode, close the sheet once the login finishes successfully (waiting for
            // isLoading to drop avoids cancelling the in-flight sync Task by dismissing early).
            if isAddMode, !loading, appState.errorMessage == nil,
               accounts.activeAccountId != initialActiveId {
                dismiss()
            }
        }
        .sheet(isPresented: $appState.show2FA) { TwoFactorView() }
        .sheet(isPresented: $appState.showCertTrust) { CertTrustView() }
    }

    // MARK: - Unlock (active account, biometric)

    private var unlockView: some View {
        VStack(spacing: 12) {
            accountSwitcher

            Button(action: { Task { await appState.unlockWithBiometric() } }) {
                HStack(spacing: 8) {
                    if appState.isLoading { ProgressView().controlSize(.small) } else { Image(systemName: "touchid") }
                    Text(L10n.Auth.unlockWith.localized(keychain.biometricType))
                }.frame(maxWidth: .infinity, minHeight: 36)
            }.buttonStyle(.borderedProminent).disabled(appState.isLoading).handCursor()

            if let err = appState.errorMessage {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.red)
                    Text(err).foregroundColor(.red).multilineTextAlignment(.center)
                }.font(.system(size: 12)).frame(maxWidth: .infinity)
            }

            Button(action: { passwordFallback = true }) {
                HStack(spacing: 8) {
                    Image(systemName: "key")
                    Text(L10n.Auth.useMasterPassword.localized)
                }
                .font(.system(size: 13, weight: .medium))
                .frame(maxWidth: .infinity, minHeight: 36)
                .background(Color(NSColor.controlBackgroundColor)).cornerRadius(8)
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.secondary.opacity(0.15), lineWidth: 1))
            }.buttonStyle(.plain).handCursor()
        }
        .frame(width: 320)
    }

    private var accountInitial: String {
        String((activeAccount?.displayName ?? activeAccount?.email ?? "?").prefix(1)).uppercased()
    }

    private var accountSwitcher: some View {
        Button(action: { showAccountMenu.toggle() }) {
            HStack(spacing: 10) {
                avatarCircle(initial: accountInitial, colors: gradientColors(for: activeAccount?.id ?? ""), size: 36)
                VStack(alignment: .leading, spacing: 1) {
                    Text(activeAccount?.displayName ?? activeAccount?.email ?? "—").font(.system(size: 14, weight: .semibold)).lineLimit(1)
                    if let email = activeAccount?.email, email != (activeAccount?.displayName ?? "") {
                        Text(email).font(.system(size: 12)).foregroundColor(.secondary).lineLimit(1)
                    }
                }
                Spacer()
                Image(systemName: "chevron.down").font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
            }
            .padding(.horizontal, 12).padding(.vertical, 10)
            .frame(maxWidth: .infinity)
            .background(Color(NSColor.controlBackgroundColor)).cornerRadius(10)
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.secondary.opacity(0.15), lineWidth: 1))
        }
        .buttonStyle(.plain).handCursor()
        .popover(isPresented: $showAccountMenu, arrowEdge: .bottom) { accountMenuContent }
    }

    private var accountMenuContent: some View {
        VStack(spacing: 0) {
            ForEach(accounts.ordered) { acc in
                let isActive = acc.id == accounts.activeAccountId
                Button(action: { appState.selectAccount(acc.id); showAccountMenu = false }) {
                    HStack(spacing: 12) {
                        Image(systemName: "checkmark").font(.system(size: 13, weight: .bold)).foregroundColor(.accentColor)
                            .frame(width: 14).opacity(isActive ? 1 : 0)
                        avatarCircle(initial: String(acc.displayName.prefix(1)).uppercased(), colors: gradientColors(for: acc.id), size: 34)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(acc.displayName).font(.system(size: 14, weight: .semibold)).lineLimit(1)
                            Text(acc.email).font(.system(size: 12)).foregroundColor(.secondary).lineLimit(1)
                        }
                        Spacer(minLength: 12)
                        if isActive {
                            Text(L10n.Auth.currentAccount.localized)
                                .font(.system(size: 11, weight: .medium)).foregroundColor(.accentColor)
                                .padding(.horizontal, 8).padding(.vertical, 3)
                                .background(Color.accentColor.opacity(0.12)).cornerRadius(6)
                        }
                    }
                    .padding(.horizontal, 12).padding(.vertical, 8)
                    .frame(maxWidth: .infinity)
                    .background(isActive ? Color.accentColor.opacity(0.08) : Color.clear)
                    .contentShape(Rectangle())
                }.buttonStyle(.plain).handCursor()
            }
            Divider().padding(.vertical, 4)
            Button(action: { showAccountMenu = false; startAddingAccount() }) {
                HStack(spacing: 12) {
                    Image(systemName: "plus").font(.system(size: 14, weight: .semibold)).foregroundColor(.accentColor).frame(width: 34)
                    Text(L10n.Auth.addAccount.localized).font(.system(size: 14, weight: .medium)).foregroundColor(.accentColor)
                    Spacer()
                }
                .padding(.horizontal, 12).padding(.vertical, 8)
                .frame(maxWidth: .infinity)
                .contentShape(Rectangle())
            }.buttonStyle(.plain).handCursor()
        }
        .padding(.vertical, 6)
        .frame(width: 360)
    }

    private func avatarCircle(initial: String, colors: [Color], size: CGFloat) -> some View {
        Circle()
            .fill(.linearGradient(colors: colors, startPoint: .topLeading, endPoint: .bottomTrailing))
            .frame(width: size, height: size)
            .overlay { Text(initial).font(.system(size: size * 0.42, weight: .bold)).foregroundColor(.white) }
    }

    /// Stable per-account gradient (does not change between launches).
    private func gradientColors(for id: String) -> [Color] {
        let palettes: [[Color]] = [[.blue, .purple], [.green, .teal], [.orange, .pink], [.indigo, .blue], [.pink, .red], [.teal, .blue]]
        var h = 5381
        for b in id.utf8 { h = ((h << 5) &+ h) &+ Int(b) }
        return palettes[abs(h) % palettes.count]
    }

    // MARK: - Login form (first account / add / re-login)

    private func fieldLabel(_ text: String) -> some View {
        Text(text).font(.system(size: 13, weight: .semibold)).foregroundColor(.secondary)
    }

    private var loginDisabled: Bool {
        appState.isLoading || serverURL.isEmpty || email.isEmpty || password.isEmpty
    }

    private func fieldBox<Content: View>(icon: String, @ViewBuilder content: () -> Content) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon).font(.system(size: 14)).foregroundColor(.secondary).frame(width: 18)
            content()
        }
        .padding(.horizontal, 12).frame(height: 42)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(NSColor.controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.secondary.opacity(0.2), lineWidth: 1))
    }

    private var loginForm: some View {
        VStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 5) {
                fieldLabel(L10n.Auth.serverLabel.localized)
                fieldBox(icon: "globe") {
                    TextField(L10n.Auth.serverPlaceholder.localized, text: $serverURL).textFieldStyle(.plain).font(.system(size: 14)).lineLimit(1)
                        .onChange(of: serverURL) { v in if v.count > 255 { serverURL = String(v.prefix(255)) } }
                }
            }
            VStack(alignment: .leading, spacing: 5) {
                fieldLabel(L10n.Auth.connectionName.localized)
                fieldBox(icon: "tag") {
                    TextField("", text: $connectionName).textFieldStyle(.plain).font(.system(size: 14)).lineLimit(1)
                        .onChange(of: connectionName) { v in if v.count > 48 { connectionName = String(v.prefix(48)) } }
                }
            }
            VStack(alignment: .leading, spacing: 5) {
                fieldLabel(L10n.Auth.emailLabel.localized)
                fieldBox(icon: "envelope") {
                    TextField(L10n.Auth.emailPlaceholder.localized, text: $email).textFieldStyle(.plain).font(.system(size: 14)).lineLimit(1)
                        .onChange(of: email) { v in if v.count > 254 { email = String(v.prefix(254)) } }
                }
            }
            VStack(alignment: .leading, spacing: 5) {
                fieldLabel(L10n.Auth.masterPasswordLabel.localized)
                fieldBox(icon: "lock") {
                    Group {
                        if showPassword { TextField(L10n.Auth.masterPasswordPlaceholder.localized, text: $password) }
                        else { SecureField(L10n.Auth.masterPasswordPlaceholder.localized, text: $password) }
                    }.textFieldStyle(.plain).font(.system(size: 14)).lineLimit(1)
                    Button(action: { showPassword.toggle() }) {
                        Image(systemName: showPassword ? "eye.slash" : "eye").foregroundColor(.secondary)
                    }.buttonStyle(.plain).handCursor()
                }
            }
            VStack(alignment: .leading, spacing: 4) {
                Toggle(isOn: $allowSelfSigned) {
                    Label(L10n.Settings.selfSigned.localized, systemImage: "lock.shield").font(.system(size: 13))
                }.toggleStyle(.checkbox).handCursor()
                Text(L10n.Settings.selfSignedHint.localized).font(.system(size: 11)).foregroundColor(.secondary).padding(.leading, 2)
            }.frame(maxWidth: .infinity, alignment: .leading)

            if keychain.isBiometricAvailable {
                VStack(alignment: .leading, spacing: 4) {
                    Toggle(isOn: $saveBiometric) {
                        Label(L10n.Auth.rememberBiometric.localized(keychain.biometricType), systemImage: "touchid").font(.system(size: 13))
                    }.toggleStyle(.checkbox).handCursor()
                    Text(L10n.Auth.biometricHint.localized).font(.system(size: 11)).foregroundColor(.secondary).padding(.leading, 2)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }

            Button(action: { loggingIn = true; Task { await appState.login(serverURL: serverURL, email: email, password: password, saveBiometric: saveBiometric, allowSelfSigned: allowSelfSigned, label: connectionName.trimmingCharacters(in: .whitespaces).isEmpty ? nil : connectionName) } }) {
                HStack(spacing: 8) {
                    if appState.isLoading { ProgressView().controlSize(.small) } else { Image(systemName: "arrow.right.circle.fill") }
                    Text(L10n.Auth.loginButton.localized).fontWeight(.semibold)
                }
                .foregroundColor(.white)
                .frame(maxWidth: .infinity, minHeight: 44)
                .background(RoundedRectangle(cornerRadius: 10).fill(loginDisabled ? Color.accentColor.opacity(0.5) : Color.accentColor))
            }.buttonStyle(.plain)
            .disabled(loginDisabled)
            .keyboardShortcut(.return)
            .handCursor()

            // Offer a way back to the biometric unlock when one is available.
            if !isAddMode, activeAccount != nil, activeHasBiometric, (addingAccount || passwordFallback) {
                HStack(spacing: 12) {
                    Rectangle().fill(Color.secondary.opacity(0.25)).frame(height: 1)
                    Text(L10n.Auth.orDivider.localized).font(.system(size: 12)).foregroundColor(.secondary)
                    Rectangle().fill(Color.secondary.opacity(0.25)).frame(height: 1)
                }.padding(.vertical, 2)
                Button(L10n.cancel.localized) { cancelFreshLogin() }
                    .buttonStyle(.plain).font(.system(size: 13, weight: .medium)).foregroundColor(.accentColor).handCursor()
            }
        }.frame(width: 360)
    }

    // MARK: - Helpers

    private func startAddingAccount() {
        appState.errorMessage = nil
        serverURL = ""; connectionName = ""; email = ""; password = ""
        addingAccount = true
    }

    private func cancelFreshLogin() {
        appState.errorMessage = nil
        addingAccount = false; passwordFallback = false
        connectionName = ""
        if let acc = activeAccount { serverURL = acc.serverURL; email = acc.email }
        password = ""
    }
}

// MARK: - 2FA View

struct TwoFactorView: View {
    @EnvironmentObject var appState: AppState
    @State private var code = ""
    @State private var rememberDevice = false
    @State private var selectedProvider = 0

    // Providers this client can actually handle: 0 Authenticator, 1 Email, 3 YubiKey OTP.
    private let supportedProviders: Set<Int> = [0, 1, 3]

    private var offered: [Int] {
        let p = (appState.pending2FALogin?.providers ?? [0]).filter { supportedProviders.contains($0) }
        return p.isEmpty ? [] : p
    }

    private func providerName(_ id: Int) -> String {
        switch id {
        case 1: return L10n.Auth.twoFactorProviderEmail.localized
        case 3: return L10n.Auth.twoFactorProviderYubiKey.localized
        default: return L10n.Auth.twoFactorProviderAuthenticator.localized
        }
    }

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield.fill").font(.system(size: 40)).foregroundColor(.accentColor)
            Text(L10n.Auth.twoFactorTitle.localized).font(.system(size: 17, weight: .bold))

            if offered.isEmpty {
                Text(L10n.Auth.twoFactorUnsupported.localized)
                    .font(.system(size: 12)).foregroundColor(.secondary).multilineTextAlignment(.center)
                Button(L10n.cancel.localized) { appState.show2FA = false; appState.pending2FALogin = nil }.handCursor()
            } else {
                Text(L10n.Auth.twoFactorPrompt.localized).font(.system(size: 13)).foregroundColor(.secondary).multilineTextAlignment(.center)

                if offered.count > 1 {
                    Picker(L10n.Auth.twoFactorProviderLabel.localized, selection: $selectedProvider) {
                        ForEach(offered, id: \.self) { Text(providerName($0)).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 320)
                }

                if selectedProvider == 1 {
                    Button(L10n.Auth.twoFactorSendEmail.localized) {
                        Task { await appState.sendTwoFactorEmail() }
                    }.font(.system(size: 12)).handCursor()
                }

                TextField(L10n.Auth.twoFactorCode.localized, text: $code)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: selectedProvider == 3 ? 13 : 20, weight: .semibold, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .frame(width: selectedProvider == 3 ? 300 : 200)

                Toggle(L10n.Auth.twoFactorRemember.localized, isOn: $rememberDevice).toggleStyle(.checkbox).font(.system(size: 12)).handCursor()

                HStack(spacing: 12) {
                    Button(L10n.cancel.localized) { appState.show2FA = false; appState.pending2FALogin = nil }.handCursor()
                    Button(L10n.Auth.twoFactorVerify.localized) {
                        Task { await appState.complete2FALogin(code: code, remember: rememberDevice, provider: selectedProvider) }
                    }
                    .buttonStyle(.borderedProminent).disabled(code.isEmpty).handCursor()
                }
            }

            if appState.isLoading { ProgressView() }
            if let err = appState.errorMessage {
                Text(err).foregroundColor(.red).font(.system(size: 12))
            }
        }
        .padding(30)
        .frame(width: 360, height: 360)
        .onAppear { selectedProvider = offered.first ?? 0 }
    }
}

// MARK: - Self-signed certificate trust prompt
// User-facing strings are localized via L10n.CertTrust (Localizable.strings).
// "SHA-256" is left as a literal (technical token, identical across languages).
struct CertTrustView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        let pending = appState.pendingCertTrust
        let changed = pending?.changed == true
        VStack(spacing: 16) {
            Image(systemName: changed ? "exclamationmark.shield.fill" : "lock.shield")
                .font(.system(size: 40))
                .foregroundColor(changed ? .red : .orange)
            Text(changed ? L10n.CertTrust.titleChanged.localized : L10n.CertTrust.titleUntrusted.localized)
                .font(.system(size: 16, weight: .semibold))

            if let pending {
                Text(pending.host).font(.system(size: 13, weight: .semibold))
                Text(changed
                     ? L10n.CertTrust.bodyChanged.localized
                     : L10n.CertTrust.bodySelfSigned.localized)
                    .font(.system(size: 12)).foregroundColor(.secondary)
                    .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)

                Text("SHA-256").font(.system(size: 11, weight: .semibold)).foregroundColor(.secondary)
                Text(pending.fingerprint)
                    .font(.system(size: 11, design: .monospaced))
                    .textSelection(.enabled)
                    .multilineTextAlignment(.center)
                    .padding(8)
                    .frame(maxWidth: .infinity)
                    .background(Color(NSColor.controlBackgroundColor))
                    .cornerRadius(6)
            }

            HStack(spacing: 12) {
                Button(L10n.cancel.localized) { appState.cancelPendingCert() }
                    .keyboardShortcut(.cancelAction)
                Button(changed ? L10n.CertTrust.trustAnyway.localized : L10n.CertTrust.trust.localized) { appState.trustPendingCert() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }.padding(.top, 4)
        }
        .padding(24)
        .frame(width: 380)
    }
}
