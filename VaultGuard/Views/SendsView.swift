import SwiftUI
import AppKit

/// Sends screen: the main view lists active Sends; creating a new Send (text or file,
/// encrypted client-side, shared via a link whose fragment carries the key) happens in a
/// separate sheet opened from the "+" button. Active Sends can be enabled/disabled, edited,
/// have their link copied, or be deleted.
struct SendsView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var showNewSend = false
    @State private var name = ""
    @State private var text = ""
    @State private var sendNotes = ""
    @State private var hideText = false
    @State private var expirySeconds: Double = 604800   // 7 days
    @State private var isFile = false
    @State private var fileURL: URL?
    @State private var maxAccess = 0
    @State private var hideEmail = false
    @State private var sendPassword = ""
    @State private var editingSend: SendSummary?
    @State private var editName = ""
    @State private var editText = ""
    @State private var editNotes = ""
    @State private var editHidden = false
    @State private var editMaxAccess = 0
    @State private var editHideEmail = false
    @State private var editResetExpiry = false
    @State private var editExpirySeconds: Double = 604800

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                activeSection.padding(VGSpacing.xxxl)
            }
        }
        .frame(width: 480, height: 620)
        .task { await appState.loadSends() }
        .sheet(item: $editingSend) { editForm($0) }
        .sheet(isPresented: $showNewSend) { newSendForm }
    }

    /// Series-consistent close button (matches EditItem / Generator headers).
    private func closeButton(_ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: "xmark").font(VGFont.bodyEmphasis).foregroundColor(VGColor.secondary)
                .frame(width: 26, height: 26)
                .background(VGColor.surface.opacity(0.6)).clipShape(Circle())
        }
        .buttonStyle(.plain).keyboardShortcut(.escape).handCursor().help(L10n.close.localized)
    }

    private var header: some View {
        HStack(alignment: .top, spacing: VGSpacing.m) {
            VStack(alignment: .leading, spacing: VGSpacing.xxs) {
                Text(L10n.Send.title.localized).font(VGFont.title)
                Text(L10n.Send.subtitle.localized).font(VGFont.caption).foregroundColor(VGColor.secondary)
            }
            Spacer()
            Button(action: { resetNewSendFields(); showNewSend = true }) {
                Image(systemName: "plus").font(VGFont.bodyEmphasis).foregroundColor(VGColor.accent)
                    .frame(width: 26, height: 26)
                    .background(VGColor.surface.opacity(0.6)).clipShape(Circle())
            }.buttonStyle(.plain).handCursor().help(L10n.Send.createButton.localized)
            closeButton { dismiss() }
        }
        .padding(.horizontal, VGSpacing.xxxl).padding(.top, VGSpacing.xxxl).padding(.bottom, VGSpacing.xl)
    }

    // MARK: - Active list

    private var activeSection: some View {
        VStack(alignment: .leading, spacing: VGSpacing.l) {
            Text(L10n.Send.active.localized).font(VGFont.headline)
            if appState.sends.isEmpty {
                Text(L10n.Send.empty.localized).font(VGFont.label).foregroundColor(VGColor.secondary)
            } else {
                ForEach(appState.sends) { sendRow($0) }
            }
        }
    }

    private func sendRow(_ s: SendSummary) -> some View {
        VStack(alignment: .leading, spacing: VGSpacing.m) {
            HStack(spacing: VGSpacing.m) {
                Image(systemName: s.type == 1 ? "paperclip" : "doc.text")
                    .font(VGFont.bodyLarge).foregroundColor(VGColor.secondary).frame(width: 20)
                Text(s.name).font(VGFont.bodyMedium).lineLimit(1)
                Spacer()
                statusBadge(s)
            }
            Text(metaLine(s)).font(VGFont.caption).foregroundColor(VGColor.secondary)
            Text(datesLine(s)).font(VGFont.caption).foregroundColor(VGColor.secondary)
            HStack(spacing: VGSpacing.s) {
                if !s.shareURL.isEmpty {
                    Button(action: { copy(s.shareURL) }) {
                        Label(L10n.Send.copyLink.localized, systemImage: "doc.on.doc").font(VGFont.labelEmphasis)
                    }.buttonStyle(.borderedProminent).controlSize(.small).handCursor()
                }
                Button(L10n.Send.edit.localized) { beginEdit(s) }
                    .buttonStyle(.bordered).controlSize(.small).handCursor()
                Button(s.disabled ? L10n.Send.enable.localized : L10n.Send.disable.localized) {
                    Task { await appState.setSendDisabled(s, disabled: !s.disabled) }
                }.buttonStyle(.bordered).controlSize(.small).handCursor()
                Spacer()
                Button(action: { Task { await appState.deleteSend(s) } }) {
                    Image(systemName: "trash").foregroundColor(VGColor.danger)
                        .frame(width: 26, height: 22).contentShape(Rectangle())
                }.buttonStyle(.plain).handCursor().help(L10n.delete.localized)
            }
        }
        .vgCard()
    }

    private func statusBadge(_ s: SendSummary) -> some View {
        let active = !s.disabled
        return Text((active ? L10n.Send.statusActive : L10n.Send.statusDisabled).localized)
            .font(VGFont.badge)
            .foregroundColor(active ? VGColor.success : VGColor.warning)
            .padding(.horizontal, VGSpacing.s).padding(.vertical, 2)
            .background((active ? VGColor.success : VGColor.warning).opacity(0.15))
            .cornerRadius(VGRadius.small)
    }

    /// Line 1: type · size (files) · views.
    private func metaLine(_ s: SendSummary) -> String {
        var parts: [String] = [(s.type == 1 ? L10n.Send.typeFile : L10n.Send.typeText).localized]
        if let sz = s.sizeName, !sz.isEmpty { parts.append(sz) }
        parts.append(viewsText(s))
        return parts.joined(separator: " · ")
    }

    private func viewsText(_ s: SendSummary) -> String {
        if let max = s.maxAccessCount {
            return String(format: L10n.Send.viewsMaxFmt.localized, s.accessCount, max)
        }
        return String(format: L10n.Send.accessCount.localized, s.accessCount)
    }

    /// Line 2: expiration · auto-delete (only the facts that exist).
    private func datesLine(_ s: SendSummary) -> String {
        var parts = [expiresText(s)]
        if let ad = autoDeletesText(s) { parts.append(ad) }
        return parts.joined(separator: " · ")
    }

    private func expiresText(_ s: SendSummary) -> String {
        guard let exp = s.expirationDate, let d = parseISO(exp) else { return L10n.Send.noExpiration.localized }
        if d.timeIntervalSinceNow <= 0 { return L10n.Send.expired.localized }
        return String(format: L10n.Send.expiresIn.localized, shortDuration(until: d))
    }

    private func autoDeletesText(_ s: SendSummary) -> String? {
        guard let del = s.deletionDate, let d = parseISO(del), d.timeIntervalSinceNow > 0 else { return nil }
        return String(format: L10n.Send.autoDeletesIn.localized, shortDuration(until: d))
    }

    /// "7 дн." / "3 ч." / "<1 ч." — short, fully under our control.
    private func shortDuration(until date: Date) -> String {
        let secs = date.timeIntervalSinceNow
        let days = Int(secs / 86_400)
        if days >= 1 { return String(format: L10n.Send.durDays.localized, days) }
        let hours = Int(secs / 3_600)
        if hours >= 1 { return String(format: L10n.Send.durHours.localized, hours) }
        return L10n.Send.durSoon.localized
    }

    /// Parse server ISO dates, tolerating fractional (microsecond) seconds the formatter rejects.
    private func parseISO(_ s: String?) -> Date? {
        guard let s = s else { return nil }
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = iso.date(from: s) { return d }
        iso.formatOptions = [.withInternetDateTime]
        if let d = iso.date(from: s) { return d }
        if let r = s.range(of: #"\.\d+"#, options: .regularExpression) {
            var t = s; t.removeSubrange(r)
            return iso.date(from: t)
        }
        return nil
    }

    // MARK: - New Send (separate sheet)

    private var newSendForm: some View {
        VStack(spacing: 0) {
            HStack {
                Text((isFile ? L10n.Send.newFile : L10n.Send.newText).localized).font(VGFont.title)
                Spacer()
                closeButton { showNewSend = false }
            }
            .padding(.horizontal, VGSpacing.xxxl).padding(.top, VGSpacing.xxxl).padding(.bottom, VGSpacing.xl)
            Divider()
            ScrollView {
                newSendSection.padding(VGSpacing.xxxl)
            }
            Divider()
            newSendFooter
        }
        .frame(width: 480, height: 550)
    }

    private var newSendFooter: some View {
        Button(action: { createSend() }) {
            HStack(spacing: VGSpacing.m) {
                if appState.isLoading { ProgressView().controlSize(.small) }
                else { Image(systemName: "paperplane.fill") }
                Text(L10n.Send.createButton.localized).fontWeight(.semibold)
            }.frame(maxWidth: .infinity, minHeight: 32)
        }
        .buttonStyle(.borderedProminent).handCursor()
        .disabled(appState.isLoading || (isFile ? fileURL == nil : text.isEmpty))
        .padding(.horizontal, VGSpacing.xxxl).padding(.vertical, VGSpacing.l)
    }

    private var newSendSection: some View {
        VStack(alignment: .leading, spacing: VGSpacing.l) {
            Picker("", selection: $isFile) {
                Text(L10n.Send.modeText.localized).tag(false)
                Text(L10n.Send.modeFile.localized).tag(true)
            }.pickerStyle(.segmented).labelsHidden()
            TextField(L10n.Send.nameLabel.localized, text: $name).textFieldStyle(.roundedBorder)
            if isFile {
                Button(action: { chooseFile() }) {
                    HStack {
                        Image(systemName: "doc.fill").foregroundColor(VGColor.secondary)
                        Text(fileURL?.lastPathComponent ?? L10n.Send.chooseFile.localized)
                            .foregroundColor(fileURL == nil ? VGColor.secondary : VGColor.primary).lineLimit(1)
                        Spacer()
                    }.padding(VGSpacing.m).background(VGColor.surface).cornerRadius(VGRadius.small)
                }.buttonStyle(.plain).handCursor()
                if let u = fileURL, let sz = fileSizeString(u) {
                    Text(sz).font(VGFont.caption).foregroundColor(VGColor.secondary)
                }
            } else {
                Text(L10n.Send.contentLabel.localized).font(VGFont.label).foregroundColor(VGColor.secondary)
                TextEditor(text: $text)
                    .font(VGFont.body).frame(height: 110)
                    .overlay(RoundedRectangle(cornerRadius: VGRadius.small).stroke(VGColor.separator))
                Toggle(L10n.Send.hideText.localized, isOn: $hideText).font(VGFont.label).handCursor()
            }
            TextField(L10n.Send.notesLabel.localized, text: $sendNotes).textFieldStyle(.roundedBorder)
            HStack {
                Text(L10n.Send.expiry.localized).font(VGFont.label)
                Picker("", selection: $expirySeconds) {
                    Text(L10n.Send.hour1.localized).tag(3600.0)
                    Text(L10n.Send.days1.localized).tag(86400.0)
                    Text(L10n.Send.days2.localized).tag(172800.0)
                    Text(L10n.Send.days7.localized).tag(604800.0)
                    Text(L10n.Send.days14.localized).tag(1209600.0)
                    Text(L10n.Send.days30.localized).tag(2592000.0)
                }.labelsHidden().frame(width: 140)
            }
            SecureField(L10n.Send.password.localized, text: $sendPassword).textFieldStyle(.roundedBorder)
            Stepper(value: $maxAccess, in: 0...100) {
                Text(maxAccess == 0 ? L10n.Send.unlimited.localized
                                    : String(format: L10n.Send.maxAccess.localized, maxAccess)).font(VGFont.label)
            }
            Toggle(L10n.Send.hideEmail.localized, isOn: $hideEmail).font(VGFont.label).handCursor()
        }
    }

    // MARK: - Edit (separate sheet)

    private func beginEdit(_ s: SendSummary) {
        editName = (s.name == s.accessId) ? "" : s.name
        editText = s.text ?? ""
        editNotes = s.notes ?? ""
        editHidden = s.hidden
        editMaxAccess = s.maxAccessCount ?? 0
        editHideEmail = s.hideEmail
        editResetExpiry = false
        editExpirySeconds = 604800
        editingSend = s
    }

    private func saveEdit(_ s: SendSummary) {
        Task {
            await appState.updateSend(s, name: editName, text: editText, hidden: editHidden,
                                      notes: editNotes,
                                      deletionSeconds: editResetExpiry ? editExpirySeconds : nil,
                                      maxAccessCount: editMaxAccess == 0 ? nil : editMaxAccess,
                                      hideEmail: editHideEmail)
            editingSend = nil
        }
    }

    private func editForm(_ s: SendSummary) -> some View {
        VStack(spacing: 0) {
            HStack {
                Text(L10n.Send.edit.localized).font(VGFont.title)
                Spacer()
                closeButton { editingSend = nil }
            }
            .padding(.horizontal, VGSpacing.xxxl).padding(.top, VGSpacing.xxxl).padding(.bottom, VGSpacing.xl)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    TextField(L10n.Send.nameLabel.localized, text: $editName).textFieldStyle(.roundedBorder)
                    if s.type == 0 {
                        Text(L10n.Send.contentLabel.localized).font(VGFont.label).foregroundColor(VGColor.secondary)
                        TextEditor(text: $editText).font(VGFont.body).frame(height: 100)
                            .overlay(RoundedRectangle(cornerRadius: VGRadius.small).stroke(VGColor.separator))
                        Toggle(L10n.Send.hideText.localized, isOn: $editHidden).font(VGFont.label).handCursor()
                    }
                    TextField(L10n.Send.notesLabel.localized, text: $editNotes).textFieldStyle(.roundedBorder)
                    Stepper(value: $editMaxAccess, in: 0...100) {
                        Text(editMaxAccess == 0 ? L10n.Send.unlimited.localized
                                                : String(format: L10n.Send.maxAccess.localized, editMaxAccess)).font(VGFont.label)
                    }
                    Toggle(L10n.Send.hideEmail.localized, isOn: $editHideEmail).font(VGFont.label).handCursor()
                    Toggle(L10n.Send.resetExpiry.localized, isOn: $editResetExpiry).font(VGFont.label).handCursor()
                    if editResetExpiry {
                        Picker("", selection: $editExpirySeconds) {
                            Text(L10n.Send.hour1.localized).tag(3600.0)
                            Text(L10n.Send.days1.localized).tag(86400.0)
                            Text(L10n.Send.days2.localized).tag(172800.0)
                            Text(L10n.Send.days7.localized).tag(604800.0)
                            Text(L10n.Send.days14.localized).tag(1209600.0)
                            Text(L10n.Send.days30.localized).tag(2592000.0)
                        }.labelsHidden().frame(width: 140)
                    }
                    Button(action: { saveEdit(s) }) {
                        HStack(spacing: VGSpacing.m) {
                            if appState.isLoading { ProgressView().controlSize(.small) }
                            Text(L10n.save.localized).fontWeight(.semibold)
                        }.frame(maxWidth: .infinity, minHeight: 36)
                    }.buttonStyle(.borderedProminent).handCursor().disabled(appState.isLoading)
                }.padding(VGSpacing.xxxl)
            }
        }.frame(width: 420, height: 480)
    }

    // MARK: - Actions

    private func resetNewSendFields() {
        name = ""; text = ""; sendNotes = ""; hideText = false; expirySeconds = 604800
        isFile = false; fileURL = nil; maxAccess = 0; hideEmail = false; sendPassword = ""
    }

    private func createSend() {
        Task {
            let url: String?
            let cap = maxAccess == 0 ? nil : maxAccess
            if isFile, let f = fileURL {
                url = await appState.createFileSend(name: name, fileURL: f, deletionSeconds: expirySeconds,
                                                    notes: sendNotes.isEmpty ? nil : sendNotes,
                                                    maxAccessCount: cap, hideEmail: hideEmail,
                                                    sendPassword: sendPassword.isEmpty ? nil : sendPassword)
            } else {
                url = await appState.createTextSend(name: name, text: text, hidden: hideText, deletionSeconds: expirySeconds,
                                                    notes: sendNotes.isEmpty ? nil : sendNotes,
                                                    maxAccessCount: cap, hideEmail: hideEmail,
                                                    sendPassword: sendPassword.isEmpty ? nil : sendPassword)
            }
            if let url {
                copy(url)                       // copies link + shows toast
                resetNewSendFields()
                await appState.loadSends()      // refresh list so the new Send shows
                showNewSend = false
            }
        }
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        if panel.runModal() == .OK { fileURL = panel.url }
    }

    private func fileSizeString(_ url: URL) -> String? {
        guard let bytes = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize else { return nil }
        return ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
        appState.showToast(.info(L10n.Send.copied.localized))
    }
}
