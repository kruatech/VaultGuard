import SwiftUI
import AppKit
import UniformTypeIdentifiers

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

    // Storage type selection (Bitwarden server vs local KeePass .kdbx).
    @State private var storageKind: VaultKind = .bitwarden
    @State private var kdbxURL: URL?
    @State private var keyfileURL: URL?
    @State private var showKdbxImporter = false
    @State private var showKeyfileImporter = false

    /// KeePass session persistence chosen at open time.
    enum KeePassPersist: Hashable { case none, fileOnly, biometric }
    @State private var keePassPersist: KeePassPersist = .biometric

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
            VGColor.window.ignoresSafeArea()
            VStack(spacing: 0) {
                if isAddMode {
                    HStack {
                        Button(L10n.cancel.localized) { dismiss() }.buttonStyle(.plain).foregroundColor(VGColor.secondary).handCursor()
                        Spacer()
                    }.padding(.horizontal, 16).padding(.top, 12)
                }

                GeometryReader { geo in
                ScrollView {
                    VStack(spacing: 0) {
                        Spacer(minLength: 24)
                        VStack(spacing: 8) {
                            RoundedRectangle(cornerRadius: 14, style: .continuous)
                                .fill(.linearGradient(colors: [.blue, .purple], startPoint: .topLeading, endPoint: .bottomTrailing))
                                .frame(width: 48, height: 48)
                                .overlay {
                                    Image(systemName: "lock.shield.fill")
                                        .font(.system(size: 26, weight: .medium))
                                        .foregroundStyle(.white)
                                }
                                .shadow(color: .blue.opacity(0.2), radius: 6, y: 3)
                            Text(L10n.Auth.title.localized).font(VGFont.brandTitle)
                            Text(L10n.Auth.subtitle.localized).font(.subheadline).foregroundColor(VGColor.secondary)
                        }
                        .padding(.top, 16)
                        .padding(.bottom, 14)

                        if showLoginForm { loginForm } else { unlockView }

                        if showLoginForm, let err = appState.errorMessage {
                            HStack(spacing: 6) {
                                Image(systemName: "exclamationmark.triangle.fill").foregroundColor(VGColor.danger)
                                Text(err).foregroundColor(VGColor.danger)
                            }.font(VGFont.label).padding(.top, 12).frame(width: 320)
                        }
                        Spacer(minLength: 24)
                    }
                    .frame(maxWidth: .infinity, minHeight: geo.size.height, alignment: .center)
                }
                }
            }
        }
        .frame(minWidth: 500, minHeight: 540)
        .onAppear {
            initialActiveId = accounts.activeAccountId
            if !keychain.isBiometricAvailable, keePassPersist == .biometric { keePassPersist = .fileOnly }
            if !isFreshLogin, let acc = activeAccount {
                serverURL = acc.serverURL; email = acc.email
                if acc.kind == .keepass {
                    storageKind = .keepass
                    prefillRememberedKeePass(acc)
                }
            }
            if !showLoginForm { Task { await appState.unlockWithBiometric() } }
        }
        .onChange(of: appState.isLoading) { _, loading in
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
        VStack(spacing: 14) {
            accountSwitcher

            Button(action: { Task { await appState.unlockWithBiometric() } }) {
                HStack(spacing: 8) {
                    if appState.isLoading { ProgressView().controlSize(.small) } else { Image(systemName: "touchid") }
                    Text(L10n.Auth.unlockWith.localized(keychain.biometricType))
                }.frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent).controlSize(.large)
            .disabled(appState.isLoading).handCursor()

            if let err = appState.errorMessage {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundColor(VGColor.danger)
                    Text(err).foregroundColor(VGColor.danger).multilineTextAlignment(.center)
                }.font(VGFont.label).frame(maxWidth: .infinity)
            }

            Button(action: { passwordFallback = true }) {
                HStack(spacing: 8) {
                    Image(systemName: "key")
                    Text(L10n.Auth.useMasterPassword.localized)
                }.frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered).controlSize(.large).handCursor()
        }
        .frame(width: 340)
    }

    private var accountInitial: String {
        String((activeAccount?.displayName ?? activeAccount?.email ?? "?").prefix(1)).uppercased()
    }

    private var activeAccountSecondaryLine: String? {
        guard let activeAccount else { return nil }
        return accountSecondaryLine(activeAccount)
    }

    private func accountSecondaryLine(_ acc: Account) -> String? {
        let email = acc.email.trimmingCharacters(in: .whitespacesAndNewlines)
        guard acc.kind == .bitwarden, !email.isEmpty else { return nil }

        let customLabel = acc.label?.trimmingCharacters(in: .whitespacesAndNewlines)
        return (customLabel?.isEmpty == false) ? email : nil
    }

    private var accountSwitcher: some View {
        Button(action: { showAccountMenu.toggle() }) {
            HStack(spacing: 10) {
                avatarCircle(initial: accountInitial, colors: gradientColors(for: activeAccount?.id ?? ""), size: 36)
                VStack(alignment: .leading, spacing: activeAccountSecondaryLine == nil ? 0 : 1) {
                    Text(activeAccount?.displayName ?? activeAccount?.email ?? "—").font(VGFont.headline).lineLimit(1)
                    if let secondary = activeAccountSecondaryLine {
                        Text(secondary).font(VGFont.label).foregroundColor(VGColor.secondary).lineLimit(1)
                    }
                }
                Spacer()
                Image(systemName: "chevron.down").font(VGFont.labelEmphasis).foregroundColor(VGColor.secondary)
            }
            .padding(.horizontal, 12).padding(.vertical, 10)
            .frame(maxWidth: .infinity)
            .background(VGColor.surface).cornerRadius(VGRadius.large)
            .overlay(RoundedRectangle(cornerRadius: VGRadius.large).stroke(Color.secondary.opacity(0.15), lineWidth: 1))
        }
        .buttonStyle(.plain).handCursor()
        .popover(isPresented: $showAccountMenu, arrowEdge: .bottom) { accountMenuContent }
    }

    private var accountMenuContent: some View {
        VStack(spacing: 0) {
            ForEach(accounts.ordered) { acc in
                let isActive = acc.id == accounts.activeAccountId
                HStack(spacing: 0) {
                Button(action: { appState.selectAccount(acc.id); showAccountMenu = false }) {
                    HStack(spacing: 12) {
                        Image(systemName: "checkmark").font(VGFont.bodyBold).foregroundColor(VGColor.accent)
                            .frame(width: 14).opacity(isActive ? 1 : 0)
                        avatarCircle(initial: String(acc.displayName.prefix(1)).uppercased(), colors: gradientColors(for: acc.id), size: 34)
                        VStack(alignment: .leading, spacing: accountSecondaryLine(acc) == nil ? 0 : 1) {
                            Text(acc.displayName).font(VGFont.headline).lineLimit(1)
                            if let secondary = accountSecondaryLine(acc) {
                                Text(secondary).font(VGFont.label).foregroundColor(VGColor.secondary).lineLimit(1)
                            }
                        }
                        Spacer(minLength: 12)
                        if isActive {
                            Text(L10n.Auth.currentAccount.localized)
                                .font(VGFont.captionMedium).foregroundColor(VGColor.accent)
                                .padding(.horizontal, 8).padding(.vertical, 3)
                                .background(Color.accentColor.opacity(0.12)).cornerRadius(VGRadius.small)
                        }
                    }
                    .padding(.horizontal, 12).padding(.vertical, 8)
                    .frame(maxWidth: .infinity)
                    .background(isActive ? Color.accentColor.opacity(0.08) : Color.clear)
                    .contentShape(Rectangle())
                }.buttonStyle(.plain).handCursor()
                Button(action: { appState.removeAccount(acc.id); showAccountMenu = false }) {
                    Image(systemName: "trash").font(VGFont.body).foregroundColor(VGColor.danger)
                        .padding(.horizontal, 12).padding(.vertical, 10).contentShape(Rectangle())
                }.buttonStyle(.plain).handCursor().help(L10n.delete.localized)
                }
            }
            Divider().padding(.vertical, 4)
            Button(action: { showAccountMenu = false; startAddingAccount() }) {
                HStack(spacing: 12) {
                    Image(systemName: "plus").font(VGFont.headline).foregroundColor(VGColor.accent).frame(width: 34)
                    Text(L10n.Auth.addAccount.localized).font(VGFont.headlineMedium).foregroundColor(VGColor.accent)
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
            .overlay { Text(initial).font(.system(size: size * 0.42, weight: .bold)).foregroundColor(VGColor.onAccent) }
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
        Text(text).font(.system(size: 12, weight: .medium)).foregroundColor(VGColor.secondary)
    }

    private var loginDisabled: Bool {
        appState.isLoading || serverURL.isEmpty || email.isEmpty || password.isEmpty
    }

    private var keepassDisabled: Bool {
        appState.isLoading || kdbxURL == nil || password.isEmpty
    }

    /// Allowed file types for the .kdbx importer. Falls back to "any file" when the
    /// system doesn't recognize the extension (no registered UTType for kdbx/kdb).
    private var kdbxTypes: [UTType] {
        let t = [UTType(filenameExtension: "kdbx"), UTType(filenameExtension: "kdb")].compactMap { $0 }
        return t.isEmpty ? [.data] : t
    }

    private func fieldBox<Content: View>(icon: String, @ViewBuilder content: () -> Content) -> some View {
        HStack(spacing: 11) {
            Image(systemName: icon).font(.system(size: 15)).foregroundStyle(.secondary).frame(width: 20)
            content()
        }
        .padding(.horizontal, 14).frame(height: 40)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(VGColor.surface))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Color.primary.opacity(0.08), lineWidth: 1))
    }

    // MARK: Storage type picker

    /// Full-width storage selector styled like the form fields (two equal halves).
    private var storagePicker: some View {
        VStack(alignment: .leading, spacing: 3) {
            fieldLabel(L10n.Auth.storageLabel.localized)
            HStack(spacing: 4) {
                storageSegment(L10n.Auth.storageBitwarden.localized, kind: .bitwarden)
                storageSegment(L10n.Auth.storageKeePass.localized, kind: .keepass)
            }
            .padding(3)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(VGColor.surface))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(Color.primary.opacity(0.08), lineWidth: 1))
        }.frame(maxWidth: .infinity, alignment: .leading).padding(.bottom, 8)
    }

    private func storageSegment(_ title: String, kind: VaultKind) -> some View {
        let selected = storageKind == kind
        return Button(action: { if storageKind != kind { storageKind = kind; appState.errorMessage = nil } }) {
            Text(title)
                .font(VGFont.bodyMedium)
                .foregroundColor(selected ? VGColor.onAccent : VGColor.primary)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 9)
                .background {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .fill(selected ? Color.accentColor : Color.clear)
                }
                .contentShape(Rectangle())
        }.buttonStyle(.plain).handCursor()
    }

    // MARK: Shared fields

    private var connectionNameField: some View {
        VStack(alignment: .leading, spacing: 5) {
            fieldLabel(L10n.Auth.connectionName.localized)
            fieldBox(icon: "tag") {
                TextField(L10n.Auth.connectionNamePlaceholder.localized, text: $connectionName).textFieldStyle(.plain).font(VGFont.bodyLarge).lineLimit(1)
                    .onChange(of: connectionName) { _, v in if v.count > 48 { connectionName = String(v.prefix(48)) } }
            }
        }
    }

    private var passwordField: some View {
        VStack(alignment: .leading, spacing: 5) {
            fieldLabel(L10n.Auth.masterPasswordLabel.localized)
            fieldBox(icon: "lock") {
                Group {
                    if showPassword { TextField(L10n.Auth.masterPasswordPlaceholder.localized, text: $password) }
                    else { SecureField(L10n.Auth.masterPasswordPlaceholder.localized, text: $password) }
                }.textFieldStyle(.plain).font(VGFont.bodyLarge).lineLimit(1)
                Button(action: { showPassword.toggle() }) {
                    Image(systemName: showPassword ? "eye.slash" : "eye").foregroundColor(VGColor.secondary)
                }.buttonStyle(.plain).handCursor()
            }
        }
    }

    @ViewBuilder private var biometricToggle: some View {
        if keychain.isBiometricAvailable {
            let isKeePass = storageKind == .keepass
            VStack(alignment: .leading, spacing: 4) {
                Toggle(isOn: $saveBiometric) {
                    Text(isKeePass ? L10n.Auth.rememberBiometricKeePass.localized(keychain.biometricType)
                                   : L10n.Auth.rememberBiometric.localized(keychain.biometricType)).font(VGFont.body)
                }.toggleStyle(.checkbox).handCursor()
                Text(isKeePass ? L10n.Auth.biometricHintKeePass.localized(keychain.biometricType)
                               : L10n.Auth.biometricHint.localized)
                    .font(VGFont.caption).foregroundColor(VGColor.secondary).padding(.leading, 2)
                    .frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    /// KeePass session persistence as two native checkboxes mapped onto KeePassPersist:
    /// remember off → .none; remember on → .fileOnly; remember + biometric → .biometric.
    @ViewBuilder private var keePassPersistPicker: some View {
        VStack(alignment: .leading, spacing: 6) {
            Toggle(isOn: bindRememberBase) {
                Text(L10n.Auth.kpRememberBase.localized).font(VGFont.body)
            }.toggleStyle(.checkbox).handCursor()
            if keychain.isBiometricAvailable {
                Toggle(isOn: bindUseBiometric) {
                    Text(L10n.Auth.kpUseBiometric.localized(keychain.biometricType)).font(VGFont.body)
                }.toggleStyle(.checkbox).handCursor()
                .disabled(keePassPersist == .none)
            }
            Text(keePassPersistHint).font(VGFont.caption).foregroundColor(VGColor.secondary)
                .frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    private var bindRememberBase: Binding<Bool> {
        Binding(get: { keePassPersist != .none },
                set: { on in keePassPersist = on ? .fileOnly : .none })
    }
    private var bindUseBiometric: Binding<Bool> {
        Binding(get: { keePassPersist == .biometric },
                set: { on in keePassPersist = on ? .biometric : .fileOnly })
    }

    private var keePassPersistHint: String {
        switch keePassPersist {
        case .none:      return L10n.Auth.kpPersistNoneHint.localized
        case .fileOnly:  return L10n.Auth.kpPersistFileHint.localized
        case .biometric: return L10n.Auth.kpPersistBiometricHint.localized(keychain.biometricType)
        }
    }

    // MARK: Bitwarden (server) fields

    private var bitwardenFields: some View {
        VStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 5) {
                fieldLabel(L10n.Auth.serverLabel.localized)
                fieldBox(icon: "globe") {
                    TextField(L10n.Auth.serverPlaceholder.localized, text: $serverURL).textFieldStyle(.plain).font(VGFont.bodyLarge).lineLimit(1)
                        .onChange(of: serverURL) { _, v in if v.count > 255 { serverURL = String(v.prefix(255)) } }
                }
            }
            connectionNameField
            VStack(alignment: .leading, spacing: 5) {
                fieldLabel(L10n.Auth.emailLabel.localized)
                fieldBox(icon: "envelope") {
                    TextField(L10n.Auth.emailPlaceholder.localized, text: $email).textFieldStyle(.plain).font(VGFont.bodyLarge).lineLimit(1)
                        .onChange(of: email) { _, v in if v.count > 254 { email = String(v.prefix(254)) } }
                }
            }
            passwordField
            VStack(alignment: .leading, spacing: 4) {
                Toggle(isOn: $allowSelfSigned) {
                    Text(L10n.Settings.selfSigned.localized).font(VGFont.body)
                }.toggleStyle(.checkbox).handCursor()
                Text(L10n.Settings.selfSignedHint.localized).font(VGFont.caption).foregroundColor(VGColor.secondary).padding(.leading, 2)
                    .frame(maxWidth: .infinity, alignment: .leading).fixedSize(horizontal: false, vertical: true)
            }.frame(maxWidth: .infinity, alignment: .leading)
            biometricToggle
            loginButton
        }
    }

    private var loginButton: some View {
        Button(action: { loggingIn = true; Task { await appState.login(serverURL: serverURL, email: email, password: password, saveBiometric: saveBiometric, allowSelfSigned: allowSelfSigned, label: connectionName.trimmingCharacters(in: .whitespaces).isEmpty ? nil : connectionName) } }) {
            HStack(spacing: 8) {
                if appState.isLoading { ProgressView().controlSize(.small) } else { Image(systemName: "arrow.right.circle.fill") }
                Text(L10n.Auth.loginButton.localized).fontWeight(.semibold)
            }.frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent).controlSize(.large)
        .disabled(loginDisabled)
        .keyboardShortcut(.return)
        .handCursor()
    }

    // MARK: KeePass (local .kdbx) fields

    private var keepassFields: some View {
        VStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 5) {
                fieldLabel(L10n.Auth.kdbxFileLabel.localized)
                Button(action: { showKdbxImporter = true }) {
                    fieldBox(icon: "doc") {
                        Text(kdbxURL?.lastPathComponent ?? L10n.Auth.kdbxNone.localized)
                            .foregroundColor(kdbxURL == nil ? .secondary : .primary)
                            .font(VGFont.bodyLarge).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Text(L10n.Auth.chooseButton.localized).font(VGFont.bodyMedium).foregroundColor(VGColor.accent)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain).handCursor()
                .fileImporter(isPresented: $showKdbxImporter, allowedContentTypes: kdbxTypes, allowsMultipleSelection: false) { result in
                    if case .success(let urls) = result, let url = urls.first {
                        kdbxURL = url
                        appState.errorMessage = nil
                    }
                }
            }
            VStack(alignment: .leading, spacing: 5) {
                fieldLabel(L10n.Auth.keyfileLabel.localized)
                Button(action: { showKeyfileImporter = true }) {
                    fieldBox(icon: "key") {
                        Text(keyfileURL?.lastPathComponent ?? L10n.Auth.keyfileNone.localized)
                            .foregroundColor(keyfileURL == nil ? .secondary : .primary)
                            .font(VGFont.bodyLarge).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        if keyfileURL != nil {
                            Button(action: { keyfileURL = nil }) {
                                Image(systemName: "xmark.circle.fill").foregroundColor(VGColor.secondary)
                            }.buttonStyle(.plain).handCursor()
                        } else {
                            Text(L10n.Auth.chooseButton.localized).font(VGFont.bodyMedium).foregroundColor(VGColor.accent)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain).handCursor()
                .fileImporter(isPresented: $showKeyfileImporter, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
                    if case .success(let urls) = result, let url = urls.first { keyfileURL = url }
                }
            }
            connectionNameField
            passwordField
            keePassPersistPicker
            if password.isEmpty {
                Text(L10n.Auth.kpPasswordHint.localized)
                    .font(VGFont.caption).foregroundColor(VGColor.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            openButton
            createButton
        }
    }

    private var openButton: some View {
        Button(action: {
            guard let url = kdbxURL else { return }
            loggingIn = true
            Task {
                await appState.openKeePass(
                    fileURL: url, password: password, keyfileURL: keyfileURL,
                    saveBiometric: keePassPersist == .biometric,
                    rememberFile: keePassPersist != .none,
                    label: connectionName.trimmingCharacters(in: .whitespaces).isEmpty ? nil : connectionName
                )
            }
        }) {
            HStack(spacing: 8) {
                if appState.isLoading { ProgressView().controlSize(.small) } else { Image(systemName: "lock.open.fill") }
                Text(L10n.Auth.openButton.localized).fontWeight(.semibold)
            }.frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent).controlSize(.large)
        .disabled(keepassDisabled)
        .keyboardShortcut(.return)
        .handCursor()
    }

    /// Create a brand-new .kdbx: pick a destination, then build + open it with the entered
    /// master password. Requires only a password (no existing file selected).
    private var createButton: some View {
        Button(action: {
            let panel = NSSavePanel()
            panel.nameFieldStringValue = "New Database.kdbx"
            if !kdbxTypes.isEmpty { panel.allowedContentTypes = kdbxTypes }
            panel.canCreateDirectories = true
            if panel.runModal() == .OK, let url = panel.url {
                loggingIn = true
                Task {
                    await appState.createKeePassDatabase(
                        at: url, password: password,
                        label: connectionName.trimmingCharacters(in: .whitespaces).isEmpty ? nil : connectionName
                    )
                }
            }
        }) {
            HStack(spacing: 8) {
                Image(systemName: "plus.circle")
                Text(L10n.Auth.createDatabaseButton.localized).fontWeight(.medium)
            }.frame(maxWidth: .infinity)
        }
        .buttonStyle(.bordered).controlSize(.large).tint(.accentColor)
        .disabled(appState.isLoading || password.isEmpty)
        .handCursor()
    }

    private var loginForm: some View {
        VStack(spacing: 12) {
            storagePicker

            if storageKind == .bitwarden {
                bitwardenFields
            } else {
                keepassFields
            }

            // Offer a way back to the biometric unlock when one is available.
            if !isAddMode, activeAccount != nil, activeHasBiometric, (addingAccount || passwordFallback) {
                HStack(spacing: 12) {
                    Rectangle().fill(Color.secondary.opacity(0.25)).frame(height: 1)
                    Text(L10n.Auth.orDivider.localized).font(VGFont.label).foregroundColor(VGColor.secondary)
                    Rectangle().fill(Color.secondary.opacity(0.25)).frame(height: 1)
                }.padding(.vertical, 2)
                Button(L10n.cancel.localized) { cancelFreshLogin() }
                    .buttonStyle(.plain).font(VGFont.bodyMedium).foregroundColor(VGColor.accent).handCursor()
            }
        }
        .frame(width: 420)
    }

    // MARK: - Helpers

    /// For a remembered KeePass account (bookmark stored, no biometric): reflect the stored
    /// mode and resolve the bookmark so the file is pre-selected — the user just types the
    /// password. Reuses the normal open path; nothing happens if no bookmark is stored.
    private func prefillRememberedKeePass(_ acc: Account) {
        let store = keychain.account(acc.id)
        if let lbl = acc.label, !lbl.isEmpty { connectionName = lbl }
        guard let b64 = store.kpBookmark, let bm = Data(base64Encoded: b64) else { return }
        keePassPersist = store.hasBiometricUnlock ? .biometric : .fileOnly
        var stale = false
        if let url = try? URL(resolvingBookmarkData: bm, options: [.withSecurityScope],
                              relativeTo: nil, bookmarkDataIsStale: &stale) {
            kdbxURL = url
        }
    }

    private func startAddingAccount() {
        appState.errorMessage = nil
        serverURL = ""; connectionName = ""; email = ""; password = ""
        kdbxURL = nil; keyfileURL = nil; storageKind = .bitwarden
        addingAccount = true
    }

    private func cancelFreshLogin() {
        appState.errorMessage = nil
        addingAccount = false; passwordFallback = false
        connectionName = ""
        kdbxURL = nil; keyfileURL = nil; storageKind = .bitwarden
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
            VaultGuardLogo()
                .frame(width: 64, height: 64)
            Text(L10n.Auth.twoFactorTitle.localized).font(VGFont.title)

            if offered.isEmpty {
                Text(L10n.Auth.twoFactorUnsupported.localized)
                    .font(VGFont.label).foregroundColor(VGColor.secondary).multilineTextAlignment(.center)
                Button(L10n.cancel.localized) { appState.show2FA = false; appState.pending2FALogin = nil }.handCursor()
            } else {
                Text(L10n.Auth.twoFactorPrompt.localized).font(VGFont.body).foregroundColor(VGColor.secondary).multilineTextAlignment(.center)

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
                    }.font(VGFont.label).handCursor()
                }

                TextField(L10n.Auth.twoFactorCode.localized, text: $code)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: selectedProvider == 3 ? 13 : 20, weight: .semibold, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .frame(width: selectedProvider == 3 ? 300 : 200)

                Toggle(L10n.Auth.twoFactorRemember.localized, isOn: $rememberDevice).toggleStyle(.checkbox).font(VGFont.label).handCursor()

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
                Text(err).foregroundColor(VGColor.danger).font(VGFont.label)
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
                .font(VGFont.brandIcon)
                .foregroundColor(changed ? .red : .orange)
            Text(changed ? L10n.CertTrust.titleChanged.localized : L10n.CertTrust.titleUntrusted.localized)
                .font(VGFont.title2)

            if let pending {
                Text(pending.host).font(VGFont.bodyEmphasis)
                Text(changed
                     ? L10n.CertTrust.bodyChanged.localized
                     : L10n.CertTrust.bodySelfSigned.localized)
                    .font(VGFont.label).foregroundColor(VGColor.secondary)
                    .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)

                Text("SHA-256").font(VGFont.captionEmphasis).foregroundColor(VGColor.secondary)
                Text(pending.fingerprint)
                    .font(VGFont.captionMono)
                    .textSelection(.enabled)
                    .multilineTextAlignment(.center)
                    .padding(8)
                    .frame(maxWidth: .infinity)
                    .background(VGColor.surface)
                    .cornerRadius(VGRadius.small)
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
