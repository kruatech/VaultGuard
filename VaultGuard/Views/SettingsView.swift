import SwiftUI
import AppKit

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var accounts: AccountManager
    @EnvironmentObject var localization: LocalizationManager
    @Environment(\.dismiss) private var dismiss

    @AppStorage("allowSelfSigned") private var allowSelfSigned = false
    @AppStorage("clipboardTimeout") private var clipboardTimeout = 30
    @AppStorage("lockTimeout") private var lockTimeout = 300
    @AppStorage("showFavicons") private var showFavicons = true
    @AppStorage("appTheme") private var appTheme = "system"

    @State private var connectionName: String = ""
    @State private var editingConnectionName = false
    @State private var masterPasswordSaved = false
    @State private var certTrusted = false
    @FocusState private var connectionNameFocused: Bool

    private let keychain = KeychainService.shared

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(L10n.Settings.title.localized).font(.system(size: 17, weight: .bold))
                Spacer()
                Button(action: { dismiss() }) {
                    Image(systemName: "xmark").font(.system(size: 13, weight: .semibold)).foregroundColor(.secondary)
                        .frame(width: 26, height: 26).background(Color(NSColor.controlBackgroundColor).opacity(0.6)).clipShape(Circle())
                }.buttonStyle(.plain).keyboardShortcut(.escape).handCursor()
            }
            .padding(.horizontal, 24).padding(.top, 20).padding(.bottom, 12)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    accountsSection

                    settingsSection(L10n.Settings.server.localized, icon: "server.rack") {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text("URL").font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                                Spacer()
                                Text(accounts.activeAccount?.serverURL ?? "—").font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                            }
                            HStack {
                                Text("Email").font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                                Spacer(); Text(accounts.activeAccount?.email ?? "—").font(.system(size: 12))
                            }
                            HStack {
                                Text("KDF").font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                                Spacer(); Text((appState.activeStore?.kdfType == 1) ? "Argon2id" : "PBKDF2").font(.system(size: 12))
                            }
                            VStack(alignment: .leading, spacing: 4) {
                                if editingConnectionName {
                                    HStack {
                                        Text(L10n.Settings.connectionName.localized).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                                        Spacer(minLength: 12)
                                        HStack(spacing: 6) {
                                            TextField("", text: $connectionName)
                                                .textFieldStyle(.plain).font(.system(size: 12)).lineLimit(1)
                                                .focused($connectionNameFocused)
                                                .onChange(of: connectionName) { newValue in
                                                    if newValue.count > 48 { connectionName = String(newValue.prefix(48)) }
                                                }
                                                .onSubmit { commitConnectionName() }
                                            Button(action: { commitConnectionName() }) {
                                                Image(systemName: "checkmark.circle.fill").font(.system(size: 14)).foregroundColor(.accentColor)
                                            }.buttonStyle(.plain).handCursor()
                                        }
                                        .padding(.leading, 7).padding(.trailing, 4).padding(.vertical, 3)
                                        .frame(maxWidth: 240)
                                        .background(RoundedRectangle(cornerRadius: 6).fill(Color(NSColor.textBackgroundColor)))
                                        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Color.accentColor, lineWidth: 1))
                                        .onExitCommand { cancelConnectionName() }
                                    }
                                } else {
                                    HStack {
                                        Text(L10n.Settings.connectionName.localized).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                                        Spacer()
                                        Text(connectionName.isEmpty ? "—" : connectionName)
                                            .font(.system(size: 12)).foregroundColor(connectionName.isEmpty ? .secondary : .primary)
                                        Button(action: { startEditConnectionName() }) {
                                            Image(systemName: "pencil").font(.system(size: 12)).foregroundColor(.secondary)
                                        }.buttonStyle(.plain).handCursor()
                                    }
                                    .contentShape(Rectangle())
                                    .onTapGesture(count: 2) { startEditConnectionName() }
                                }
                            }
                            Toggle(L10n.Settings.selfSigned.localized, isOn: $allowSelfSigned).font(.system(size: 12)).padding(.top, 4).handCursor()
                            Text(L10n.Settings.selfSignedHint.localized).font(.system(size: 11)).foregroundColor(Color(NSColor.tertiaryLabelColor))
                        }
                    }
                    .onAppear {
                        connectionName = accounts.activeAccount?.label ?? ""
                        masterPasswordSaved = appState.activeStore?.hasBiometricUnlock ?? false
                        certTrusted = activeCertHost.flatMap { appState.certTrust.pinnedFingerprint(host: $0) } != nil
                    }

                    settingsSection(L10n.Settings.security.localized, icon: "lock.shield") {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text(L10n.Settings.biometry.localized).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                                Spacer()
                                if keychain.isBiometricAvailable {
                                    HStack(spacing: 4) {
                                        Image(systemName: "checkmark.circle.fill").foregroundColor(.green).font(.system(size: 12))
                                        Text(keychain.biometricType).font(.system(size: 12))
                                    }
                                } else { Text(L10n.Settings.biometryUnavailable.localized).font(.system(size: 12)).foregroundColor(.secondary) }
                            }
                            HStack {
                                Text(L10n.Settings.masterPassword.localized).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                                Spacer()
                                if masterPasswordSaved {
                                    HStack(spacing: 4) {
                                        Image(systemName: "checkmark.circle.fill").foregroundColor(.green).font(.system(size: 12))
                                        Text(L10n.Settings.storedInKeychain.localized).font(.system(size: 12))
                                    }
                                    Button(action: { forgetMasterPassword() }) {
                                        Text(L10n.Settings.forget.localized).font(.system(size: 12))
                                    }.buttonStyle(.link).handCursor()
                                } else {
                                    Text(L10n.Settings.notSaved.localized).font(.system(size: 12)).foregroundColor(.secondary)
                                }
                            }
                            HStack {
                                Text(L10n.Settings.trustedCertificate.localized).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                                Spacer()
                                if certTrusted {
                                    HStack(spacing: 4) {
                                        Image(systemName: "checkmark.circle.fill").foregroundColor(.green).font(.system(size: 12))
                                        Text(L10n.Settings.pinned.localized).font(.system(size: 12))
                                    }
                                    Button(action: { forgetTrustedCert() }) {
                                        Text(L10n.Settings.forget.localized).font(.system(size: 12))
                                    }.buttonStyle(.link).handCursor()
                                } else {
                                    Text("—").font(.system(size: 12)).foregroundColor(.secondary)
                                }
                            }
                            HStack {
                                Text(L10n.Settings.clipboardTimeout.localized).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                                Spacer()
                                Picker("", selection: $clipboardTimeout) {
                                Text(L10n.Time.seconds10.localized).tag(10)
                                Text(L10n.Time.seconds30.localized).tag(30)
                                Text(L10n.Time.seconds60.localized).tag(60)
                                Text(L10n.Time.minutes2.localized).tag(120)
                                Text(L10n.Time.never.localized).tag(0)
                            }.labelsHidden().font(.system(size: 12)).frame(width: 170, alignment: .trailing)
                            }
                            HStack {
                                Text(L10n.Settings.autoLock.localized).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                                Spacer()
                                Picker("", selection: $lockTimeout) {
                                Text(L10n.Time.minute1.localized).tag(60)
                                Text(L10n.Time.minutes5.localized).tag(300)
                                Text(L10n.Time.minutes15.localized).tag(900)
                                Text(L10n.Time.hour1.localized).tag(3600)
                                Text(L10n.Time.never.localized).tag(0)
                            }.labelsHidden().font(.system(size: 12)).frame(width: 170, alignment: .trailing)
                            }
                            .onChange(of: lockTimeout) { _ in appState.startAutoLockTimer() }
                        }
                    }

                    settingsSection(L10n.Settings.interface.localized, icon: "paintbrush") {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text(L10n.Settings.theme.localized).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                                Spacer()
                                Picker("", selection: $appTheme) {
                                ForEach(AppTheme.allCases, id: \.rawValue) { theme in
                                    Text(theme.displayName).tag(theme.rawValue)
                                }
                            }.labelsHidden().font(.system(size: 12)).frame(width: 170, alignment: .trailing)
                            }
                            .onChange(of: appTheme) { _ in appState.applyTheme() }

                            HStack {
                                Text(L10n.Settings.language.localized).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                                Spacer()
                                Picker("", selection: $localization.currentLanguage) {
                                ForEach(AppLanguage.allCases) { lang in
                                    Text(lang.displayName).tag(lang)
                                }
                            }.labelsHidden().font(.system(size: 12)).frame(width: 170, alignment: .trailing)
                            }

                            Toggle(L10n.Settings.showFavicons.localized, isOn: $showFavicons).font(.system(size: 12)).handCursor()
                        }
                    }

                    settingsSection(L10n.Settings.about.localized, icon: "info.circle") {
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Text("VaultGuard").font(.system(size: 13, weight: .semibold))
                                Spacer(); Text("v1.0.0").font(.system(size: 12)).foregroundColor(.secondary)
                            }
                            Text(L10n.Settings.vaultguardDesc.localized).font(.system(size: 12)).foregroundColor(.secondary)
                            Text("Bitwarden-compatible · AES-256 · PBKDF2 / Argon2id")
                                .font(.system(size: 11)).foregroundColor(Color(NSColor.tertiaryLabelColor))

                            Divider().padding(.vertical, 2)

                            aboutRow(label: L10n.Settings.author.localized) {
                                Text("Anton Krutilin").font(.system(size: 12)).foregroundColor(.primary)
                            }
                            aboutRow(label: L10n.Settings.sourceCode.localized) {
                                if let gh = URL(string: "https://github.com/kruatech/VaultGuard") {
                                    Link("GitHub", destination: gh).font(.system(size: 12)).handCursor()
                                }
                            }
                            aboutRow(label: L10n.Settings.contact.localized) {
                                if let mail = URL(string: "mailto:a@krutilin.pro") {
                                    Link("a@krutilin.pro", destination: mail).font(.system(size: 12)).handCursor()
                                }
                            }
                        }
                    }

                    Button(role: .destructive, action: { appState.logout() }) {
                        Label(L10n.Settings.logoutButton.localized, systemImage: "trash")
                            .font(.system(size: 12, weight: .medium))
                    }.buttonStyle(.bordered).tint(.red).padding(.top, 8)
                }
                .padding(24)
            }
        }
        .frame(minWidth: 480, maxWidth: 480, minHeight: 500, maxHeight: 700)
    }

    // MARK: - Account (identity only; name is edited in the Server section,
    // switching/adding live in the sidebar profile menu)

    private var accountsSection: some View {
        settingsSection(L10n.Settings.account.localized, icon: "person.crop.circle") {
            if let acc = accounts.activeAccount {
                HStack(spacing: 10) {
                    Circle()
                        .fill(.linearGradient(colors: [.blue, .purple], startPoint: .topLeading, endPoint: .bottomTrailing))
                        .frame(width: 26, height: 26)
                        .overlay { Text(String((acc.label ?? acc.email).prefix(1)).uppercased()).font(.system(size: 11, weight: .bold)).foregroundColor(.white) }
                    VStack(alignment: .leading, spacing: 1) {
                        Text(acc.email).font(.system(size: 12, weight: .medium)).lineLimit(1)
                        Text(acc.serverHost).font(.system(size: 10)).foregroundColor(.secondary).lineLimit(1)
                    }
                    Spacer()
                }
            } else {
                Text("—").font(.system(size: 12)).foregroundColor(.secondary)
            }
        }
    }

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

    private func startEditConnectionName() {
        connectionName = accounts.activeAccount?.label ?? ""
        editingConnectionName = true
        DispatchQueue.main.async { connectionNameFocused = true }
    }
    private func commitConnectionName() {
        let v = String(connectionName.prefix(48)).trimmingCharacters(in: .whitespacesAndNewlines)
        if let id = accounts.activeAccountId { accounts.setLabel(v, for: id) }
        connectionName = v
        connectionNameFocused = false
        editingConnectionName = false
    }
    private func cancelConnectionName() {
        connectionName = accounts.activeAccount?.label ?? ""
        connectionNameFocused = false
        editingConnectionName = false
    }

    private func settingsSection<Content: View>(_ title: String, icon: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title, systemImage: icon).font(.system(size: 13, weight: .bold)).foregroundColor(.primary)
            content()
                .padding(14).frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(NSColor.controlBackgroundColor)).cornerRadius(10)
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color.secondary.opacity(0.1), lineWidth: 0.5))
        }
    }

    /// System-style About row: label on the left, value on the right.
    private func aboutRow<Value: View>(label: String, @ViewBuilder value: () -> Value) -> some View {
        HStack {
            Text(label).font(.system(size: 12)).foregroundColor(.secondary)
            Spacer()
            value()
        }
    }
}

