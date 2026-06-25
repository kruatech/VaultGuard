import SwiftUI
import AppKit

enum GeneratorMode { case standalone, inline }

struct GeneratorView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss

    /// `.standalone` = Generator tab (primary "Copy password");
    /// `.inline` = opened from a password field (primary "Use password", returns via `onUse`).
    var mode: GeneratorMode = .standalone
    var onUse: ((String) -> Void)? = nil

    @State private var length: Double = 16
    @State private var uppercase = true
    @State private var lowercase = true
    @State private var digits = true
    @State private var symbols = true
    @State private var excludeAmbiguous = false
    @State private var generated = ""

    @State private var selectedTemplateId: String? = nil   // built-in id or custom UUID
    @State private var showTemplateMenu = false

    // Save-as-new name prompt
    @State private var showNamePrompt = false
    @State private var newName = ""
    // Rename prompt
    @State private var showRenamePrompt = false
    @State private var renameText = ""

    private var selectedTemplate: PasswordTemplate? { appState.template(id: selectedTemplateId) }

    /// Current control values as a comparable template (name/id/icon irrelevant).
    private var currentSettings: PasswordTemplate {
        PasswordTemplate(name: "", length: Int(length), uppercase: uppercase, lowercase: lowercase,
                         digits: digits, symbols: symbols, excludeAmbiguous: excludeAmbiguous)
    }
    private var matchesSelected: Bool {
        guard let t = selectedTemplate else { return false }
        return currentSettings.sameSettings(as: t)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    templatePicker
                    if selectedTemplate != nil && matchesSelected { appliedBanner }
                    lengthSection
                    charsetSection
                    resultSection
                    if selectedTemplate != nil && !matchesSelected { differsBanner }
                }.padding(20)
            }
            Divider()
            footer
        }
        .frame(width: 480, height: 620)
        .onAppear { loadInitialTemplate() }
        .alert(L10n.Generator.newTemplate.localized, isPresented: $showNamePrompt) {
            TextField(L10n.Generator.templateName.localized, text: $newName)
            Button(L10n.save.localized) { confirmSaveAsNew() }
            Button(L10n.cancel.localized, role: .cancel) {}
        }
        .alert(L10n.Generator.renameTemplate.localized, isPresented: $showRenamePrompt) {
            TextField(L10n.Generator.templateName.localized, text: $renameText)
            Button(L10n.save.localized) { confirmRename() }
            Button(L10n.cancel.localized, role: .cancel) {}
        }
    }

    // MARK: - Header / Footer

    private var header: some View {
        HStack {
            Text(L10n.Generator.title.localized).font(.system(size: 17, weight: .bold))
            Spacer()
            Button(action: { dismiss() }) {
                Image(systemName: "xmark").font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
                    .frame(width: 22, height: 22)
                    .background(Circle().fill(Color(NSColor.controlBackgroundColor)))
            }.buttonStyle(.plain).handCursor()
        }.padding(.horizontal, 20).padding(.top, 18).padding(.bottom, 12)
    }

    private var footer: some View {
        HStack(spacing: 10) {
            Spacer()
            Button(L10n.cancel.localized) { dismiss() }.keyboardShortcut(.escape).handCursor()
            Button(action: primaryAction) {
                Label(primaryTitle, systemImage: mode == .inline ? "square.and.arrow.down" : "doc.on.doc")
            }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).handCursor()
        }.padding(.horizontal, 20).padding(.vertical, 14)
    }

    private var primaryTitle: String {
        mode == .inline ? L10n.Generator.usePassword.localized : L10n.Generator.copyPassword.localized
    }
    private func primaryAction() {
        if mode == .inline { onUse?(generated); dismiss() }
        else { appState.copyToClipboard(generated) }
    }

    // MARK: - Template picker

    private var templatePicker: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(L10n.Generator.templateLabel.localized).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
            Button(action: { showTemplateMenu.toggle() }) {
                HStack(spacing: 10) {
                    Text(selectedTemplate?.displayName ?? L10n.Generator.templateLabel.localized)
                        .font(.system(size: 14, weight: .medium)).foregroundColor(.primary).lineLimit(1)
                    Spacer()
                    Image(systemName: "chevron.down").font(.system(size: 11)).foregroundColor(.secondary)
                }
                .padding(.horizontal, 12).frame(height: 38)
                .background(RoundedRectangle(cornerRadius: 8).fill(Color(NSColor.controlBackgroundColor)))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color(NSColor.separatorColor), lineWidth: 1))
                .contentShape(Rectangle())
            }.buttonStyle(.plain).handCursor()
            .popover(isPresented: $showTemplateMenu, arrowEdge: .bottom) { templateMenu }

            if let t = selectedTemplate {
                Text(t.summary).font(.system(size: 11)).foregroundColor(.secondary)
            }
        }
    }

    private var templateMenu: some View {
        VStack(spacing: 0) {
            ForEach(appState.passwordTemplates) { t in templateMenuRow(t) }
            if !appState.passwordTemplates.isEmpty { Divider().padding(.vertical, 4) }
            menuAction(icon: "plus", text: L10n.Generator.saveCurrentAsNew.localized) {
                showTemplateMenu = false; startSaveAsNew()
            }
            if let t = selectedTemplate {
                menuAction(icon: "pencil", text: L10n.Generator.renameTemplate.localized) {
                    showTemplateMenu = false; startRename(t)
                }
                menuAction(icon: "trash", text: L10n.delete.localized) {
                    showTemplateMenu = false; deleteSelected()
                }
            }
        }
        .padding(.vertical, 6).frame(width: 340)
    }

    private func templateMenuRow(_ t: PasswordTemplate) -> some View {
        let sel = selectedTemplateId == t.id
        return Button(action: { applyTemplate(t); showTemplateMenu = false }) {
            HStack(spacing: 10) {
                Text(t.displayName).font(.system(size: 13, weight: .medium))
                Spacer()
                Image(systemName: "checkmark").font(.system(size: 11, weight: .bold)).foregroundColor(.accentColor).opacity(sel ? 1 : 0)
            }
            .padding(.horizontal, 14).padding(.vertical, 6)
            .frame(maxWidth: .infinity)
            .background(sel ? Color.accentColor.opacity(0.08) : Color.clear)
            .contentShape(Rectangle())
        }.buttonStyle(.plain).handCursor()
    }

    private func menuAction(icon: String, text: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: icon).font(.system(size: 13)).foregroundColor(.secondary).frame(width: 18)
                Text(text).font(.system(size: 13))
                Spacer()
            }
            .padding(.horizontal, 14).padding(.vertical, 6).frame(maxWidth: .infinity).contentShape(Rectangle())
        }.buttonStyle(.plain).handCursor()
    }

    // MARK: - Banners

    private var appliedBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "info.circle").foregroundColor(.accentColor)
            Text(L10n.Generator.appliedBanner.localized).font(.system(size: 12)).foregroundColor(.primary)
            Spacer()
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.accentColor.opacity(0.10)))
    }

    private var differsBanner: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundColor(.orange)
                Text(L10n.Generator.differsTitle.localized).font(.system(size: 13, weight: .semibold))
            }
            Text(L10n.Generator.differsBody.localized).font(.system(size: 11)).foregroundColor(.secondary)
            HStack(spacing: 8) {
                Button(L10n.Generator.updateTemplate.localized) { updateSelected() }
                    .buttonStyle(.borderedProminent).controlSize(.small).handCursor()
                Button(L10n.Generator.saveAsNew.localized) { startSaveAsNew() }
                    .buttonStyle(.bordered).controlSize(.small).handCursor()
                Button(L10n.Generator.reset.localized) { resetToSelected() }
                    .buttonStyle(.bordered).controlSize(.small).handCursor()
                Spacer()
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.orange.opacity(0.12)))
    }

    // MARK: - Length / Charset / Result

    private var lengthSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(L10n.Generator.length.localized).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
            HStack(spacing: 12) {
                Slider(value: $length, in: 6...64, step: 1)
                Stepper(value: $length, in: 6...64) {
                    Text("\(Int(length))").font(.system(size: 13, weight: .bold, design: .monospaced))
                        .frame(width: 28, alignment: .trailing)
                }.fixedSize()
            }
            .onChange(of: length) { _ in regenerate() }
        }
    }

    private var charsetSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(L10n.Generator.charset.localized).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
            HStack(spacing: 14) {
                Toggle("A-Z", isOn: $uppercase)
                Toggle("a-z", isOn: $lowercase)
                Toggle("0-9", isOn: $digits)
                Toggle("!@#$%^&*", isOn: $symbols)
                Spacer()
            }
            .toggleStyle(.checkbox).font(.system(size: 13)).handCursor()
            .onChange(of: uppercase) { _ in regenerate() }
            .onChange(of: lowercase) { _ in regenerate() }
            .onChange(of: digits) { _ in regenerate() }
            .onChange(of: symbols) { _ in regenerate() }
            Toggle(L10n.Generator.excludeAmbiguous.localized, isOn: $excludeAmbiguous)
                .toggleStyle(.checkbox).font(.system(size: 12)).handCursor()
                .onChange(of: excludeAmbiguous) { _ in regenerate() }
        }
    }

    private var resultSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L10n.Generator.generatedLabel.localized).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
            HStack(spacing: 8) {
                Text(generated).font(.system(size: 14, weight: .medium, design: .monospaced))
                    .textSelection(.enabled).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                Button(action: regenerate) {
                    Image(systemName: "arrow.clockwise").font(.system(size: 13)).foregroundColor(.accentColor)
                }.buttonStyle(.plain).frame(width: 26, height: 24).contentShape(Rectangle()).handCursor()
                    .help(L10n.Generator.refresh.localized)
            }
            .padding(12).background(Color(NSColor.controlBackgroundColor)).cornerRadius(8)

            let strength = PasswordStrength.evaluate(generated)
            HStack(spacing: 8) {
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 2).fill(Color.secondary.opacity(0.15)).frame(height: 4)
                        RoundedRectangle(cornerRadius: 2).fill(strengthColor(strength))
                            .frame(width: geo.size.width * strength.fraction, height: 4)
                            .animation(.easeInOut(duration: 0.3), value: strength.fraction)
                    }
                }.frame(height: 4)
                Text(strength.label).font(.system(size: 11, weight: .medium)).foregroundColor(strengthColor(strength))
            }
        }
    }

    // MARK: - Actions

    private func regenerate() {
        generated = CryptoService.generatePassword(length: Int(length), uppercase: uppercase,
            lowercase: lowercase, digits: digits, symbols: symbols, excludeAmbiguous: excludeAmbiguous)
    }

    private func loadInitialTemplate() {
        if let t = appState.template(id: appState.lastTemplateId) {
            loadSettings(from: t)
        } else if let first = appState.passwordTemplates.first {
            loadSettings(from: first)
        } else {
            regenerate()
        }
    }

    /// Load a template's settings into the controls without touching shared state.
    /// Safe to call from onAppear (no @Published mutation during the view update).
    private func loadSettings(from t: PasswordTemplate) {
        length = Double(t.length); uppercase = t.uppercase; lowercase = t.lowercase
        digits = t.digits; symbols = t.symbols; excludeAmbiguous = t.excludeAmbiguous
        selectedTemplateId = t.id
        regenerate()
    }

    /// User-driven selection: load settings and remember the choice (writes lastTemplateId).
    private func applyTemplate(_ t: PasswordTemplate) {
        loadSettings(from: t)
        appState.lastTemplateId = t.id
    }

    private func resetToSelected() {
        if let t = selectedTemplate { loadSettings(from: t) }
    }

    private func updateSelected() {
        guard let t = selectedTemplate else { return }
        var u = t
        u.length = Int(length); u.uppercase = uppercase; u.lowercase = lowercase
        u.digits = digits; u.symbols = symbols; u.excludeAmbiguous = excludeAmbiguous
        appState.updateTemplate(u)
    }

    private func startSaveAsNew() {
        newName = L10n.Generator.newTemplateNamePrefix.localized
        showNamePrompt = true
    }

    private func confirmSaveAsNew() {
        let name = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { return }
        var t = currentSettings
        t.id = UUID().uuidString
        t.name = name
        appState.addTemplate(t)              // appends + selects (lastTemplateId)
        selectedTemplateId = appState.lastTemplateId
        newName = ""
    }

    private func startRename(_ t: PasswordTemplate) {
        renameText = t.displayName
        showRenamePrompt = true
    }

    private func confirmRename() {
        let name = renameText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, var t = selectedTemplate else { return }
        t.name = name
        t.builtinKey = nil   // a renamed template keeps its user-given name regardless of language
        appState.updateTemplate(t)
        renameText = ""
    }

    private func deleteSelected() {
        guard let t = selectedTemplate else { return }
        appState.deleteTemplate(t.id)
        if let first = appState.passwordTemplates.first { applyTemplate(first) }
        else { selectedTemplateId = nil }
    }

    private func strengthColor(_ s: PasswordStrength) -> Color {
        switch s.score { case 1: return .red; case 2: return .orange; case 3: return .yellow; case 4: return .green; default: return .secondary }
    }
}

