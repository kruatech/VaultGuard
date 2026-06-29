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
                    // Banner sits with the picker it relates to, so the "differs" actions
                    // (update / save-as-new / reset) aren't buried below the result.
                    if selectedTemplate != nil {
                        if matchesSelected { appliedBanner } else { differsBanner }
                    }
                    lengthSection
                    charsetSection
                    resultSection
                }.padding(VGSpacing.xxxl)
            }
            Divider()
            footer
        }
        .frame(width: 480, height: 540)
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
            Text(L10n.Generator.title.localized).font(VGFont.title)
            Spacer()
            Button(action: { dismiss() }) {
                Image(systemName: "xmark").font(VGFont.bodyEmphasis).foregroundColor(VGColor.secondary)
                    .frame(width: 26, height: 26)
                    .background(VGColor.surface.opacity(0.6)).clipShape(Circle())
            }.buttonStyle(.plain).handCursor()
        }
        .padding(.horizontal, VGSpacing.xxxl).padding(.top, VGSpacing.xxxl).padding(.bottom, VGSpacing.xl)
    }

    private var footer: some View {
        HStack(spacing: VGSpacing.l) {
            Spacer()
            Button(L10n.cancel.localized) { dismiss() }.keyboardShortcut(.escape).handCursor()
            Button(action: primaryAction) {
                Label(primaryTitle, systemImage: mode == .inline ? "square.and.arrow.down" : "doc.on.doc")
            }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).handCursor()
        }
        .padding(.horizontal, VGSpacing.xxxl).padding(.vertical, VGSpacing.xl)
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
        VStack(alignment: .leading, spacing: VGSpacing.s) {
            Text(L10n.Generator.templateLabel.localized).font(VGFont.labelEmphasis).foregroundColor(VGColor.secondary)
            Button(action: { showTemplateMenu.toggle() }) {
                HStack(spacing: VGSpacing.l) {
                    Text(selectedTemplate?.displayName ?? L10n.Generator.templateLabel.localized)
                        .font(VGFont.headlineMedium).foregroundColor(VGColor.primary).lineLimit(1)
                    Spacer()
                    Image(systemName: "chevron.down").font(VGFont.caption).foregroundColor(VGColor.secondary)
                }
                .padding(.horizontal, 12).frame(height: 38)
                .background(RoundedRectangle(cornerRadius: VGRadius.medium).fill(VGColor.surface))
                .overlay(RoundedRectangle(cornerRadius: VGRadius.medium).strokeBorder(VGColor.separator, lineWidth: 1))
                .contentShape(Rectangle())
            }.buttonStyle(.plain).handCursor()
            .popover(isPresented: $showTemplateMenu, arrowEdge: .bottom) { templateMenu }

            if let t = selectedTemplate {
                Text(t.summary).font(VGFont.caption).foregroundColor(VGColor.secondary)
            }
        }
    }

    private var templateMenu: some View {
        VStack(spacing: 0) {
            ForEach(appState.passwordTemplates) { t in templateMenuRow(t) }
            if !appState.passwordTemplates.isEmpty { Divider().padding(.vertical, VGSpacing.xs) }
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
        .padding(.vertical, VGSpacing.s).frame(width: 340)
    }

    private func templateMenuRow(_ t: PasswordTemplate) -> some View {
        let sel = selectedTemplateId == t.id
        return Button(action: { applyTemplate(t); showTemplateMenu = false }) {
            HStack(spacing: VGSpacing.l) {
                Text(t.displayName).font(VGFont.bodyMedium)
                Spacer()
                Image(systemName: "checkmark").font(VGFont.captionBold).foregroundColor(VGColor.accent).opacity(sel ? 1 : 0)
            }
            .padding(.horizontal, VGSpacing.xl).padding(.vertical, VGSpacing.s)
            .frame(maxWidth: .infinity)
            .background(sel ? VGColor.accent.opacity(0.08) : Color.clear)
            .contentShape(Rectangle())
        }.buttonStyle(.plain).handCursor()
    }

    private func menuAction(icon: String, text: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: VGSpacing.l) {
                Image(systemName: icon).font(VGFont.body).foregroundColor(VGColor.secondary).frame(width: 18)
                Text(text).font(VGFont.body)
                Spacer()
            }
            .padding(.horizontal, VGSpacing.xl).padding(.vertical, VGSpacing.s).frame(maxWidth: .infinity).contentShape(Rectangle())
        }.buttonStyle(.plain).handCursor()
    }

    // MARK: - Banners

    private var appliedBanner: some View {
        HStack(spacing: VGSpacing.m) {
            Image(systemName: "info.circle").foregroundColor(VGColor.accent)
            Text(L10n.Generator.appliedBanner.localized).font(VGFont.label).foregroundColor(VGColor.primary)
            Spacer()
        }
        .padding(VGSpacing.l)
        .background(RoundedRectangle(cornerRadius: VGRadius.medium).fill(VGColor.accent.opacity(0.10)))
    }

    private var differsBanner: some View {
        VStack(alignment: .leading, spacing: VGSpacing.m) {
            HStack(spacing: VGSpacing.m) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundColor(VGColor.warning)
                Text(L10n.Generator.differsTitle.localized).font(VGFont.bodyEmphasis)
            }
            Text(L10n.Generator.differsBody.localized).font(VGFont.caption).foregroundColor(VGColor.secondary)
            HStack(spacing: VGSpacing.m) {
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
        .background(RoundedRectangle(cornerRadius: VGRadius.medium).fill(VGColor.warning.opacity(0.12)))
    }

    // MARK: - Length / Charset / Result

    private var lengthSection: some View {
        VStack(alignment: .leading, spacing: VGSpacing.s) {
            Text(L10n.Generator.length.localized).font(VGFont.labelEmphasis).foregroundColor(VGColor.secondary)
            HStack(spacing: VGSpacing.l) {
                Slider(value: $length, in: 6...64, step: 1)
                Stepper(value: $length, in: 6...64) {
                    Text("\(Int(length))").font(VGFont.bodyMonoBold)
                        .frame(width: 28, alignment: .trailing)
                }.fixedSize()
            }
            .onChange(of: length) { _, _ in regenerate() }
        }
    }

    private var charsetSection: some View {
        VStack(alignment: .leading, spacing: VGSpacing.l) {
            Text(L10n.Generator.charset.localized).font(VGFont.labelEmphasis).foregroundColor(VGColor.secondary)
            HStack(spacing: VGSpacing.xl) {
                Toggle("A-Z", isOn: $uppercase)
                Toggle("a-z", isOn: $lowercase)
                Toggle("0-9", isOn: $digits)
                Toggle("!@#$%^&*", isOn: $symbols)
                Spacer()
            }
            .toggleStyle(.checkbox).font(VGFont.body).handCursor()
            .onChange(of: uppercase) { _, _ in regenerate() }
            .onChange(of: lowercase) { _, _ in regenerate() }
            .onChange(of: digits) { _, _ in regenerate() }
            .onChange(of: symbols) { _, _ in regenerate() }
            Toggle(L10n.Generator.excludeAmbiguous.localized, isOn: $excludeAmbiguous)
                .toggleStyle(.checkbox).font(VGFont.label).handCursor()
                .onChange(of: excludeAmbiguous) { _, _ in regenerate() }
        }
    }

    private var resultSection: some View {
        VStack(alignment: .leading, spacing: VGSpacing.m) {
            Text(L10n.Generator.generatedLabel.localized).font(VGFont.labelEmphasis).foregroundColor(VGColor.secondary)
            HStack(spacing: VGSpacing.m) {
                Text(generated).font(VGFont.passwordMono)
                    .textSelection(.enabled).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                Button(action: regenerate) {
                    Image(systemName: "arrow.clockwise").font(VGFont.body).foregroundColor(VGColor.accent)
                }.buttonStyle(.plain).frame(width: 26, height: 24).contentShape(Rectangle()).handCursor()
                    .help(L10n.Generator.refresh.localized)
            }
            .padding(12).background(VGColor.surface).cornerRadius(VGRadius.medium)

            let strength = PasswordStrength.evaluate(generated)
            HStack(spacing: VGSpacing.m) {
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 2).fill(VGColor.secondary.opacity(0.15)).frame(height: 4)
                        RoundedRectangle(cornerRadius: 2).fill(strengthColor(strength))
                            .frame(width: geo.size.width * strength.fraction, height: 4)
                            .animation(.easeInOut(duration: 0.3), value: strength.fraction)
                    }
                }.frame(height: 4)
                Text(strength.label).font(VGFont.captionMedium).foregroundColor(strengthColor(strength))
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
        switch s.score {
        case 1: return VGColor.danger
        case 2: return VGColor.warning
        case 3: return .yellow
        case 4: return VGColor.success
        default: return VGColor.secondary
        }
    }
}
