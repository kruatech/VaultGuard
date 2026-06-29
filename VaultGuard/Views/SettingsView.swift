import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var accounts: AccountManager
    @EnvironmentObject var localization: LocalizationManager

    @AppStorage("allowSelfSigned") private var allowSelfSigned = false
    @AppStorage("clipboardTimeout") private var clipboardTimeout = 30
    @AppStorage("lockTimeout") private var lockTimeout = 300
    @AppStorage(SharedConfig.autoFillKeyTTLKey, store: SharedConfig.appGroupDefaults ?? .standard) private var autoFillKeyTTL = SharedConfig.autoFillKeyTTLDefault
    @AppStorage("showFavicons") private var showFavicons = true
    @AppStorage("appTheme") private var appTheme = "system"

    @State private var connectionName: String = ""
    @State private var masterPasswordSaved = false
    @State private var certTrusted = false
    @State private var showExportSheet = false
    @State private var exportPassword = ""
    @State private var exportConfirm = ""
    @State private var showImportSheet = false
    @State private var importPassword = ""
    @State private var importFileURL: URL?
    @State private var importKeyfileURL: URL?
    @FocusState private var connectionNameFocused: Bool

    private let keychain = KeychainService.shared

    var body: some View {
        TabView {
            accountTab
                .tabItem { Label(L10n.Settings.account.localized, systemImage: "person.crop.circle") }
            securityTab
                .tabItem { Label(L10n.Settings.security.localized, systemImage: "lock.shield") }
            interfaceTab
                .tabItem { Label(L10n.Settings.interface.localized, systemImage: "paintbrush") }
            dataTab
                .tabItem { Label(L10n.Settings.dataTab.localized, systemImage: "arrow.up.arrow.down") }
            aboutTab
                .tabItem { Label(L10n.Settings.about.localized, systemImage: "info.circle") }
        }
        .frame(minWidth: 620, maxWidth: 620, minHeight: 520)
        .onAppear {
            connectionName = accounts.activeAccount?.label ?? ""
            masterPasswordSaved = appState.activeStore?.hasBiometricUnlock ?? false
            certTrusted = activeCertHost.flatMap { appState.certTrust.pinnedFingerprint(host: $0) } != nil
        }
        .sheet(isPresented: $showExportSheet) { exportSheet }
        .sheet(isPresented: $showImportSheet) { importSheet }
    }

    // MARK: - Account tab

    private var accountTab: some View {
        Form {
            if appState.activeVaultKind != .keepass {
                Section(L10n.Settings.account.localized) {
                    if let acc = accounts.activeAccount {
                        HStack(spacing: 10) {
                            Circle()
                                .fill(.linearGradient(colors: [.blue, .purple], startPoint: .topLeading, endPoint: .bottomTrailing))
                                .frame(width: 26, height: 26)
                                .overlay { Text(String((acc.label ?? acc.email).prefix(1)).uppercased()).font(VGFont.captionBold).foregroundColor(VGColor.onAccent) }
                            VStack(alignment: .leading, spacing: 1) {
                                Text(acc.email).font(VGFont.labelMedium).lineLimit(1)
                                Text(acc.serverHost).font(VGFont.caption2).foregroundColor(VGColor.secondary).lineLimit(1)
                            }
                            Spacer()
                        }
                    } else {
                        Text("—").foregroundColor(VGColor.secondary)
                    }
                }
            }

            Section(L10n.Settings.server.localized) {
                LabeledContent("URL") {
                    Text(accounts.activeAccount?.serverURL ?? "—").font(VGFont.labelMono).textSelection(.enabled)
                }
                if appState.activeVaultKind != .keepass {
                    LabeledContent(L10n.Auth.emailLabel.localized) {
                        Text(accounts.activeAccount?.email ?? "—")
                    }
                }
                LabeledContent("KDF") {
                    Text((appState.activeStore?.kdfType == 1) ? "Argon2id" : "PBKDF2")
                }
                TextField(L10n.Settings.connectionName.localized,
                          text: $connectionName,
                          prompt: Text(L10n.Auth.connectionNamePlaceholder.localized))
                    .lineLimit(1)
                    .focused($connectionNameFocused)
                    .onChange(of: connectionName) { _, v in if v.count > 48 { connectionName = String(v.prefix(48)) } }
                    .onChange(of: connectionNameFocused) { _, focused in if !focused { commitConnectionName() } }
                    .onSubmit { commitConnectionName() }
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - Security tab

    private var securityTab: some View {
        Form {
            Section(L10n.Settings.unlock.localized) {
                LabeledContent(L10n.Settings.biometry.localized) {
                    if keychain.isBiometricAvailable {
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark.circle.fill").foregroundColor(VGColor.success)
                            Text(keychain.biometricType)
                        }
                    } else {
                        Text(L10n.Settings.biometryUnavailable.localized).foregroundColor(VGColor.secondary)
                    }
                }
                LabeledContent(L10n.Settings.masterPassword.localized) {
                    if masterPasswordSaved {
                        HStack(spacing: 8) {
                            HStack(spacing: 4) {
                                Image(systemName: "checkmark.circle.fill").foregroundColor(VGColor.success)
                                Text(L10n.Settings.storedInKeychain.localized)
                            }
                            Button(L10n.Settings.forget.localized) { forgetMasterPassword() }.buttonStyle(.link).handCursor()
                        }
                    } else {
                        Text(L10n.Settings.notSaved.localized).foregroundColor(VGColor.secondary)
                    }
                }
            }

            if appState.activeVaultKind != .keepass {
                Section {
                    LabeledContent(L10n.Settings.trustedCertificate.localized) {
                        if certTrusted {
                            HStack(spacing: 8) {
                                HStack(spacing: 4) {
                                    Image(systemName: "checkmark.circle.fill").foregroundColor(VGColor.success)
                                    Text(L10n.Settings.pinned.localized)
                                }
                                Button(L10n.Settings.forget.localized) { forgetTrustedCert() }.buttonStyle(.link).handCursor()
                            }
                        } else {
                            Text("—").foregroundColor(VGColor.secondary)
                        }
                    }
                    Toggle(L10n.Settings.selfSigned.localized, isOn: $allowSelfSigned).handCursor()
                } header: {
                    Text(L10n.Settings.certificates.localized)
                } footer: {
                    Text(L10n.Settings.selfSignedHint.localized).font(VGFont.caption).foregroundColor(VGColor.tertiary)
                }
            }

            Section(L10n.Settings.timeouts.localized) {
                Picker(L10n.Settings.clipboardTimeout.localized, selection: $clipboardTimeout) {
                    Text(L10n.Time.seconds10.localized).tag(10)
                    Text(L10n.Time.seconds30.localized).tag(30)
                    Text(L10n.Time.seconds60.localized).tag(60)
                    Text(L10n.Time.minutes2.localized).tag(120)
                    Text(L10n.Time.never.localized).tag(0)
                }
                Picker(L10n.Settings.autoLock.localized, selection: $lockTimeout) {
                    Text(L10n.Time.minute1.localized).tag(60)
                    Text(L10n.Time.minutes5.localized).tag(300)
                    Text(L10n.Time.minutes15.localized).tag(900)
                    Text(L10n.Time.hour1.localized).tag(3600)
                    Text(L10n.Time.never.localized).tag(0)
                }
                .onChange(of: lockTimeout) { _, _ in appState.startAutoLockTimer() }
            }

            Section {
                Picker(L10n.Settings.autoFillKeyTTL.localized, selection: $autoFillKeyTTL) {
                    Text(L10n.Time.minutes15.localized).tag(900)
                    Text(L10n.Time.hour1.localized).tag(3600)
                    Text(L10n.Time.hours4.localized).tag(14400)
                    Text(L10n.Time.hours8.localized).tag(28800)
                }
            } header: {
                Text(L10n.Settings.autofill.localized)
            } footer: {
                Text(L10n.Settings.autoFillKeyTTLHint.localized).font(VGFont.caption).foregroundColor(VGColor.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - Interface tab

    private var interfaceTab: some View {
        Form {
            Section(L10n.Settings.appearance.localized) {
                Picker(L10n.Settings.theme.localized, selection: $appTheme) {
                    ForEach(AppTheme.allCases, id: \.rawValue) { theme in
                        Text(theme.displayName).tag(theme.rawValue)
                    }
                }
                .onChange(of: appTheme) { _, _ in appState.applyTheme() }

                Toggle(L10n.Settings.showFavicons.localized, isOn: $showFavicons).handCursor()
            }

            Section(L10n.Settings.language.localized) {
                Picker(L10n.Settings.language.localized, selection: $localization.currentLanguage) {
                    ForEach(AppLanguage.allCases) { lang in
                        Text(lang.displayName).tag(lang)
                    }
                }
                .labelsHidden()
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - Data tab (export / import; Bitwarden vaults only)

    private var dataTab: some View {
        Form {
            if appState.activeVaultKind == .bitwarden {
                Section {
                    Button(action: { exportPassword = ""; exportConfirm = ""; showExportSheet = true }) {
                        Label(L10n.Migration.exportButton.localized, systemImage: "square.and.arrow.up").font(VGFont.labelMedium)
                    }.buttonStyle(.bordered).handCursor()
                } header: {
                    Text(L10n.Migration.exportTitle.localized)
                } footer: {
                    Text(L10n.Migration.exportHint.localized).font(VGFont.caption).foregroundColor(VGColor.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Section(L10n.Migration.importTitle.localized) {
                    Button(action: { importPassword = ""; importFileURL = nil; importKeyfileURL = nil; showImportSheet = true }) {
                        Label(L10n.Migration.importButton.localized, systemImage: "square.and.arrow.down").font(VGFont.labelMedium)
                    }.buttonStyle(.bordered).handCursor()
                    Text(L10n.Migration.importHint.localized).font(VGFont.caption).foregroundColor(VGColor.tertiary)
                        .fixedSize(horizontal: false, vertical: true)

                    Button(action: { importBitwardenJSON() }) {
                        Label(L10n.Migration.importJSONButton.localized, systemImage: "square.and.arrow.down.on.square").font(VGFont.labelMedium)
                    }.buttonStyle(.bordered).handCursor()
                    Text(L10n.Migration.importJSONHint.localized).font(VGFont.caption).foregroundColor(VGColor.tertiary)
                        .fixedSize(horizontal: false, vertical: true)

                    Button(action: { importCSV() }) {
                        Label(L10n.Migration.importCSVButton.localized, systemImage: "tablecells").font(VGFont.labelMedium)
                    }.buttonStyle(.bordered).handCursor()
                    Text(L10n.Migration.importCSVHint.localized).font(VGFont.caption).foregroundColor(VGColor.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - About tab

    private var aboutTab: some View {
        Form {
            Section(L10n.Settings.about.localized) {
                LabeledContent("VaultGuard") {
                    Text("v" + (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"))
                        .foregroundColor(VGColor.secondary)
                }
                Text(L10n.Settings.vaultguardDesc.localized).font(VGFont.label).foregroundColor(VGColor.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Bitwarden-compatible · AES-256 · PBKDF2 / Argon2id")
                    .font(VGFont.caption).foregroundColor(VGColor.tertiary)
            }

            Section(L10n.Settings.support.localized) {
                LabeledContent(L10n.Settings.author.localized) {
                    Text("Anton Krutilin").foregroundColor(VGColor.primary)
                }
                LabeledContent(L10n.Settings.sourceCode.localized) {
                    if let gh = URL(string: "https://github.com/kruatech/VaultGuard") {
                        Link("GitHub", destination: gh).handCursor()
                    }
                }
                LabeledContent(L10n.Settings.contact.localized) {
                    if let mail = URL(string: "mailto:a@krutilin.pro") {
                        Link("a@krutilin.pro", destination: mail).handCursor()
                    }
                }
            }

            Section {
                Button(role: .destructive, action: { appState.logout() }) {
                    Label(L10n.Settings.logoutButton.localized, systemImage: "trash").font(VGFont.labelMedium)
                }.buttonStyle(.bordered).tint(VGColor.danger).handCursor()
            }
        }
        .formStyle(.grouped)
    }

    // MARK: - Export / import actions

    private func importBitwardenJSON() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if let t = UTType(filenameExtension: "json") { panel.allowedContentTypes = [t] }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { await appState.importBitwardenJSONFile(fileURL: url) }
    }

    private func importCSV() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if let t = UTType(filenameExtension: "csv") { panel.allowedContentTypes = [t] }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { await appState.importCSVFile(fileURL: url) }
    }

    private var exportSheet: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L10n.Migration.exportTitle.localized).font(VGFont.title3)
            SecureField(L10n.Migration.newPassword.localized, text: $exportPassword).textFieldStyle(.roundedBorder)
            SecureField(L10n.Migration.confirmPassword.localized, text: $exportConfirm).textFieldStyle(.roundedBorder)
            if !exportConfirm.isEmpty, exportPassword != exportConfirm {
                Text(L10n.Migration.passwordMismatch.localized).font(VGFont.caption).foregroundColor(VGColor.danger)
            }
            HStack {
                Spacer()
                Button(L10n.cancel.localized) { showExportSheet = false }.handCursor()
                Button(L10n.Migration.exportButton.localized) { startExport() }
                    .buttonStyle(.borderedProminent).handCursor()
                    .disabled(exportPassword.isEmpty || exportPassword != exportConfirm)
            }
        }
        .padding(20)
        .frame(width: 360)
    }

    private func startExport() {
        let password = exportPassword
        showExportSheet = false
        let panel = NSSavePanel()
        let base = appState.profileName.isEmpty ? "VaultGuard" : appState.profileName
        panel.nameFieldStringValue = "\(base).kdbx"
        panel.canCreateDirectories = true
        if panel.runModal() == .OK, let url = panel.url {
            Task { await appState.exportActiveVaultToKDBX(at: url, password: password) }
        }
    }

    private var importSheet: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(L10n.Migration.importTitle.localized).font(VGFont.title3)
            Button(action: { chooseImportFile() }) {
                HStack {
                    Image(systemName: "doc.fill").foregroundColor(VGColor.secondary)
                    Text(importFileURL?.lastPathComponent ?? L10n.Migration.chooseFile.localized)
                        .foregroundColor(importFileURL == nil ? .secondary : .primary).lineLimit(1)
                    Spacer()
                }.padding(8).background(VGColor.surface).cornerRadius(VGRadius.small)
            }.buttonStyle(.plain).handCursor()
            HStack(spacing: 8) {
                Button(action: { chooseImportKeyfile() }) {
                    HStack {
                        Image(systemName: "key.fill").foregroundColor(VGColor.secondary)
                        Text(importKeyfileURL?.lastPathComponent ?? L10n.Auth.keyfileNone.localized)
                            .foregroundColor(importKeyfileURL == nil ? .secondary : .primary).lineLimit(1)
                        Spacer()
                    }.padding(8).background(VGColor.surface).cornerRadius(VGRadius.small)
                }.buttonStyle(.plain).handCursor()
                if importKeyfileURL != nil {
                    Button(action: { importKeyfileURL = nil }) { Image(systemName: "xmark.circle.fill").foregroundColor(VGColor.secondary) }
                        .buttonStyle(.plain).handCursor()
                }
            }
            SecureField(L10n.Auth.masterPasswordPlaceholder.localized, text: $importPassword).textFieldStyle(.roundedBorder)
            Text(L10n.Migration.importHint.localized).font(VGFont.caption).foregroundColor(VGColor.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button(L10n.cancel.localized) { showImportSheet = false }.handCursor()
                Button(L10n.Migration.importButton.localized) { startImport() }
                    .buttonStyle(.borderedProminent).handCursor()
                    .disabled(importFileURL == nil || importPassword.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 380)
    }

    private func chooseImportFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if let t = UTType(filenameExtension: "kdbx") { panel.allowedContentTypes = [t] }
        if panel.runModal() == .OK { importFileURL = panel.url }
    }

    private func chooseImportKeyfile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if panel.runModal() == .OK { importKeyfileURL = panel.url }
    }

    private func startImport() {
        guard let url = importFileURL else { return }
        let password = importPassword
        let keyfile = importKeyfileURL
        showImportSheet = false
        Task { await appState.importKDBXFile(fileURL: url, password: password, keyfileURL: keyfile) }
    }

    // MARK: - Helpers

    private func forgetMasterPassword() {
        if appState.disableBiometricUnlock() { masterPasswordSaved = false }
    }

    /// Host used for certificate pinning for the active account (matches APIService).
    private var activeCertHost: String? {
        guard var u = accounts.activeAccount?.serverURL, !u.isEmpty else { return nil }
        let lower = u.lowercased()
        if !lower.hasPrefix("http://") && !lower.hasPrefix("https://") { u = "https://" + u }
        return URL(string: u)?.host?.lowercased()
    }

    private func forgetTrustedCert() {
        if let host = activeCertHost { appState.certTrust.unpin(host: host) }
        certTrusted = false
    }

    private func commitConnectionName() {
        let v = String(connectionName.prefix(48)).trimmingCharacters(in: .whitespacesAndNewlines)
        if let id = accounts.activeAccountId { accounts.setLabel(v, for: id) }
        connectionName = v
    }
}
