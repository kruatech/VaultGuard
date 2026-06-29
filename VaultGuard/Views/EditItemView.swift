import SwiftUI
import AppKit
import CoreImage
import UniformTypeIdentifiers

struct EditItemView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss

    let cipher: VaultCipher?

    @State private var name = ""
    @State private var type: CipherType = .login
    @State private var folderId: String? = nil
    @State private var username = ""
    @State private var password = ""
    @State private var isPasswordVisible = false
    @State private var url = ""
    @State private var totpEnabled = false
    @State private var totpSecret = ""
    @State private var totpImportError: String? = nil
    @State private var ready = false   // change-tracking enabled only after initial load
    @State private var notes = ""
    @State private var favorite = false
    @State private var customFields: [CipherField] = []
    @FocusState private var focusedCustomField: CustomFieldFocus?

    /// Identifies which custom-field input has focus (a row's id + which column).
    private enum CustomFieldFocus: Hashable { case name(UUID), value(UUID) }
    @State private var keepassIcon: KeePassIconRef? = nil
    @State private var iconExpanded = false
    // Card
    @State private var cardholderName = ""
    @State private var cardNumber = ""
    @State private var cardExpMonth = ""
    @State private var cardExpYear = ""
    @State private var cardCode = ""
    @State private var cardBrand = ""
    // Identity
    @State private var idTitle = ""
    @State private var idFirstName = ""
    @State private var idMiddleName = ""
    @State private var idLastName = ""
    @State private var idUsername = ""
    @State private var idCompany = ""
    @State private var idEmail = ""
    @State private var idPhone = ""
    @State private var idSsn = ""
    @State private var idPassport = ""
    @State private var idLicense = ""
    @State private var idAddress1 = ""
    @State private var idAddress2 = ""
    @State private var idAddress3 = ""
    @State private var idCity = ""
    @State private var idState = ""
    @State private var idPostalCode = ""
    @State private var idCountry = ""

    @State private var hasUnsavedChanges = false
    @State private var showDiscardConfirm = false

    // Drag & Drop
    @State private var isDragOver = false

    private var isNew: Bool { cipher == nil }

    /// Single source of truth for dirtiness: any change to any editable field changes
    /// this string, so one `.onChange` covers every field (no per-field bookkeeping to
    /// forget). UI-only state (e.g. password visibility) is intentionally excluded.
    private var dirtySnapshot: String {
        let base = [name, "\(type)", folderId ?? "", "\(favorite)", notes].joined(separator: "\u{1}")
        let login = [username, password, "\(totpEnabled)", totpSecret, url].joined(separator: "\u{1}")
        let card = [cardholderName, cardNumber, cardExpMonth, cardExpYear, cardCode, cardBrand].joined(separator: "\u{1}")
        let ident = [idTitle, idFirstName, idMiddleName, idLastName, idUsername, idCompany, idEmail, idPhone,
                     idSsn, idPassport, idLicense, idAddress1, idAddress2, idAddress3, idCity, idState,
                     idPostalCode, idCountry].joined(separator: "\u{1}")
        let custom = customFields.map { "\($0.name)\u{1}\($0.value)\u{1}\($0.type)" }.joined(separator: "\u{2}")
        let icon: String = { switch keepassIcon { case .standard(let i): return "s\(i)"; case .custom(let d): return "c\(d.count)"; case nil: return "" } }()
        return [base, login, card, ident, custom, icon].joined(separator: "\u{1F}")
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(isNew ? L10n.Editor.newItem.localized : L10n.Editor.editing.localized)
                    .font(VGFont.title)
                Spacer()
                Button(action: { attemptDismiss() }) {
                    Image(systemName: "xmark").font(VGFont.bodyEmphasis).foregroundColor(VGColor.secondary)
                        .frame(width: 26, height: 26).background(VGColor.surface.opacity(0.6)).clipShape(Circle())
                }
                .buttonStyle(.plain).handCursor()
            }
            .padding(.horizontal, VGSpacing.huge).padding(.top, VGSpacing.xxxl).padding(.bottom, VGSpacing.xl)

            Divider()

            Form {
                Section(L10n.Editor.basicInfo.localized) {
                    if appState.activeVaultKind != .keepass {
                        Picker(L10n.Editor.typeLabel.localized, selection: $type) {
                            ForEach(CipherType.allCases) { t in Text(t.localizedName).tag(t) }
                        }
                        .pickerStyle(.menu)
                    }
                    TextField(L10n.Editor.nameLabel.localized, text: $name,
                              prompt: Text(L10n.Editor.namePlaceholder.localized))
                    Picker(L10n.Editor.folderLabel.localized, selection: $folderId) {
                        Text(L10n.noFolder.localized).tag(String?.none)
                        ForEach(appState.folders) { folder in
                            Text(folder.name).tag(Optional(folder.id))
                        }
                    }
                    .pickerStyle(.menu)
                }

                switch type {
                case .login: loginSections
                case .card: cardSection
                case .secureNote: EmptyView()
                case .identity: identitySections
                }

                Section(L10n.Editor.notesLabel.localized) {
                    TextEditor(text: $notes)
                        .font(VGFont.body).frame(minHeight: 80)
                        .scrollContentBackground(.hidden)
                }

                customFieldsSection

                if appState.activeVaultKind != .keepass {
                    Section(L10n.Editor.advanced.localized) {
                        Toggle(L10n.Editor.favorite.localized, isOn: $favorite).toggleStyle(.checkbox).handCursor()
                    }
                }
            }
            .formStyle(.grouped)
            .onChange(of: dirtySnapshot) { _, _ in markChanged() }

            Divider()

            HStack {
                Spacer()
                Button(L10n.cancel.localized) { attemptDismiss() }.keyboardShortcut(.escape)
                Button(isNew ? L10n.create.localized : L10n.save.localized) { save() }
                    .buttonStyle(.borderedProminent).disabled(name.isEmpty).keyboardShortcut(.return)
            }
            .padding(.horizontal, VGSpacing.huge).padding(.vertical, VGSpacing.xl)
        }
        .frame(minWidth: 540, maxWidth: 540, minHeight: 500, maxHeight: 700)
        .onAppear { loadCipher() }
        .confirmationDialog(L10n.Editor.unsavedTitle.localized, isPresented: $showDiscardConfirm, titleVisibility: .visible) {
            Button(L10n.Editor.discardChanges.localized, role: .destructive) { dismiss() }
            Button(L10n.Editor.continueEditing.localized, role: .cancel) {}
        } message: { Text(L10n.Editor.unsavedMessage.localized) }
    }

    private func attemptDismiss() { if hasUnsavedChanges { showDiscardConfirm = true } else { dismiss() } }

    /// Mark the form dirty, but ignore the change storm fired while `loadCipher` populates @State.
    private func markChanged() { if ready { hasUnsavedChanges = true } }

    // MARK: - Login sections

    @ViewBuilder private var loginSections: some View {
        Section(L10n.Editor.credentials.localized) {
            TextField(L10n.Editor.loginLabel.localized, text: $username, prompt: Text("user@example.com"))
            HStack(spacing: VGSpacing.s) {
                Text(L10n.Editor.passwordLabel.localized)
                    .frame(width: 100, alignment: .leading)
                passwordControl
            }
        }
        Section(L10n.Editor.links.localized) {
            TextField(L10n.Editor.urlLabel.localized, text: $url, prompt: Text("https://…"))
        }
        iconSection
        Section("TOTP") {
            Toggle(L10n.Editor.totpToggle.localized, isOn: $totpEnabled).toggleStyle(.checkbox).handCursor()
            if totpEnabled {
                totpControl
                if let err = totpImportError {
                    Text(err).font(VGFont.caption).foregroundColor(VGColor.danger)
                }
            }
        }
    }

    private var passwordControl: some View {
        fieldBox {
            ZStack {
                TextField("", text: $password, prompt: Text(L10n.Editor.passwordPlaceholder.localized))
                    .textFieldStyle(.plain).font(VGFont.bodyMono).lineLimit(1).multilineTextAlignment(.leading)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .opacity(isPasswordVisible ? 1 : 0)
                    .allowsHitTesting(isPasswordVisible)
                SecureField("", text: $password, prompt: Text(L10n.Editor.passwordPlaceholder.localized))
                    .textFieldStyle(.plain).font(VGFont.bodyMono).lineLimit(1).multilineTextAlignment(.leading)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .opacity(isPasswordVisible ? 0 : 1)
                    .allowsHitTesting(!isPasswordVisible)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Button(action: { isPasswordVisible.toggle() }) {
                Image(systemName: isPasswordVisible ? "eye.slash" : "eye").font(VGFont.body).foregroundColor(VGColor.secondary)
            }.buttonStyle(.plain).frame(width: 22, height: 20).contentShape(Rectangle()).handCursor()
                .help((isPasswordVisible ? L10n.Editor.hide : L10n.Editor.show).localized)
            Button(action: { password = appState.generateFromLastTemplate(); isPasswordVisible = true }) {
                Image(systemName: "arrow.triangle.2.circlepath").font(VGFont.body).foregroundColor(VGColor.secondary)
            }.buttonStyle(.plain).frame(width: 22, height: 20).contentShape(Rectangle()).handCursor()
                .help(L10n.Editor.generate.localized)
            Menu {
                ForEach(appState.passwordTemplates) { t in templateMenuButton(t) }
            } label: {
                Image(systemName: "chevron.down").font(VGFont.caption).foregroundColor(VGColor.secondary)
            }
            .menuStyle(.borderlessButton).menuIndicator(.hidden)
            .frame(width: 18).contentShape(Rectangle()).handCursor()
            .help(L10n.Editor.chooseTemplate.localized)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .frame(minWidth: 0)
    }

    private var totpControl: some View {
        fieldBox {
            TextField("", text: $totpSecret, prompt: Text("JBSWY3DPEHPK3PXP")).textFieldStyle(.plain).font(VGFont.bodyMono).lineLimit(1).multilineTextAlignment(.leading)
            totpImportButtons
        }
        .frame(maxWidth: .infinity)
        .overlay(RoundedRectangle(cornerRadius: VGRadius.medium)
            .strokeBorder(isDragOver ? VGColor.accent : Color.clear, lineWidth: 2))
        .onDrop(of: [UTType.image, UTType.fileURL, UTType.url, UTType.text], isTargeted: $isDragOver) { providers in
            handleTOTPDrop(providers)
        }
    }

    // MARK: - Card section

    @ViewBuilder private var cardSection: some View {
        Section(L10n.Editor.cardData.localized) {
            TextField(L10n.Detail.cardHolder.localized, text: $cardholderName)
            TextField(L10n.Detail.cardNumber.localized, text: $cardNumber, prompt: Text("4242 4242 4242 4242"))
                .font(VGFont.bodyMono)
            LabeledContent(L10n.Detail.cardExpiry.localized) {
                HStack(spacing: VGSpacing.xs) {
                    TextField("", text: $cardExpMonth, prompt: Text("MM"))
                        .textFieldStyle(.roundedBorder).frame(width: 48).multilineTextAlignment(.center)
                    Text("/").foregroundColor(VGColor.secondary)
                    TextField("", text: $cardExpYear, prompt: Text("YY"))
                        .textFieldStyle(.roundedBorder).frame(width: 48).multilineTextAlignment(.center)
                }
            }
            SecureField(L10n.Detail.cardCvv.localized, text: $cardCode).font(VGFont.bodyMono)
            TextField(L10n.Editor.cardBrand.localized, text: $cardBrand,
                      prompt: Text(L10n.Editor.cardBrandPlaceholder.localized))
        }
    }

    // MARK: - Identity sections

    @ViewBuilder private var identitySections: some View {
        Section(L10n.Editor.personalData.localized) {
            TextField(L10n.Identity.title.localized, text: $idTitle, prompt: Text("Mr., Mrs., Dr."))
            TextField(L10n.Identity.firstName.localized, text: $idFirstName)
            TextField(L10n.Identity.middleName.localized, text: $idMiddleName)
            TextField(L10n.Identity.lastName.localized, text: $idLastName)
            TextField(L10n.Identity.username.localized, text: $idUsername)
            TextField(L10n.Identity.company.localized, text: $idCompany)
        }
        Section(L10n.Editor.contacts.localized) {
            TextField(L10n.Identity.email.localized, text: $idEmail, prompt: Text("user@example.com"))
            TextField(L10n.Identity.phone.localized, text: $idPhone, prompt: Text(L10n.Identity.phonePlaceholder.localized))
        }
        Section(L10n.Editor.addressSection.localized) {
            TextField(L10n.Identity.address1.localized, text: $idAddress1)
            TextField(L10n.Identity.address2.localized, text: $idAddress2)
            TextField(L10n.Identity.address3.localized, text: $idAddress3)
            TextField(L10n.Identity.city.localized, text: $idCity)
            TextField(L10n.Identity.state.localized, text: $idState)
            TextField(L10n.Identity.postalCode.localized, text: $idPostalCode)
            TextField(L10n.Identity.country.localized, text: $idCountry)
        }
        Section {
            TextField(L10n.Identity.ssn.localized, text: $idSsn).font(VGFont.bodyMono)
            TextField(L10n.Identity.passport.localized, text: $idPassport).font(VGFont.bodyMono)
            TextField(L10n.Identity.license.localized, text: $idLicense).font(VGFont.bodyMono)
        }
    }

    // MARK: - Custom fields

    private func fieldTypeName(_ t: FieldType) -> String {
        switch t {
        case .hidden:  return L10n.Editor.fieldHidden.localized
        case .boolean: return L10n.Editor.fieldBoolean.localized
        default:       return L10n.Editor.fieldText.localized
        }
    }

    private var customFieldsSection: some View {
        Section(L10n.Editor.customFieldsLabel.localized) {
            ForEach($customFields) { $field in
                HStack(alignment: .center, spacing: VGSpacing.s) {
                    fieldBox {
                        VGTextField(text: $field.name, placeholder: L10n.Editor.fieldName.localized)
                            .frame(maxWidth: .infinity)
                            .focused($focusedCustomField, equals: .name(field.id))
                    }
                    .frame(width: 120)
                    .contentShape(Rectangle())
                    .onTapGesture { focusedCustomField = .name(field.id) }
                    if field.type == .boolean {
                        fieldBox {
                            Menu {
                                Button("misc.yes".localized) { field.value = "true" }
                                Button("misc.no".localized) { field.value = "false" }
                            } label: {
                                HStack(spacing: VGSpacing.xs) {
                                    Spacer(minLength: 0)
                                    Text(field.value == "true" ? "misc.yes".localized : "misc.no".localized)
                                        .font(VGFont.body).foregroundColor(VGColor.primary)
                                    Image(systemName: "chevron.up.chevron.down").font(VGFont.caption2).foregroundColor(VGColor.secondary)
                                }
                                .frame(maxWidth: .infinity)
                                .contentShape(Rectangle())
                            }
                            .menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden)
                            .frame(maxWidth: .infinity)
                            .handCursor()
                        }
                        .frame(maxWidth: .infinity)
                    } else {
                        fieldBox {
                            VGTextField(text: $field.value, placeholder: L10n.Editor.fieldValue.localized)
                                .frame(maxWidth: .infinity)
                                .focused($focusedCustomField, equals: .value(field.id))
                        }
                        .frame(maxWidth: .infinity)
                        .contentShape(Rectangle())
                        .onTapGesture { focusedCustomField = .value(field.id) }
                    }
                    Menu {
                        Button(L10n.Editor.fieldText.localized) { $field.type.wrappedValue = .text }
                        Button(L10n.Editor.fieldHidden.localized) { $field.type.wrappedValue = .hidden }
                        Button(L10n.Editor.fieldBoolean.localized) { $field.type.wrappedValue = .boolean }
                    } label: {
                        HStack(spacing: VGSpacing.xs) {
                            Text(fieldTypeName(field.type)).font(VGFont.body).foregroundColor(VGColor.primary)
                            Spacer(minLength: 0)
                            Image(systemName: "chevron.up.chevron.down").font(VGFont.caption2).foregroundColor(VGColor.secondary)
                        }
                        .frame(width: 60)
                        .contentShape(Rectangle())
                    }
                    .menuStyle(.button).buttonStyle(.plain).menuIndicator(.hidden)
                    .handCursor()
                    Button(action: { customFields.removeAll(where: { $0.id == field.id }) }) {
                        Image(systemName: "xmark").foregroundColor(VGColor.secondary)
                    }.buttonStyle(.plain).frame(width: 20).handCursor()
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            Button(action: { customFields.append(CipherField()) }) {
                Label(L10n.Editor.addField.localized, systemImage: "plus")
                    .font(VGFont.labelEmphasis).foregroundColor(VGColor.accent)
            }.buttonStyle(.plain).handCursor()
        }
    }

    /// A full-width field container that mimics a bordered field but lets icon buttons
    /// sit *inside* on the trailing edge (so the input spans the full width).
    @ViewBuilder private func fieldBox<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        HStack(spacing: VGSpacing.xs) { content() }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, VGSpacing.s)
            .frame(height: 30, alignment: .center)
            .clipped()
            .background(RoundedRectangle(cornerRadius: VGRadius.medium).fill(VGColor.field))
            .overlay(RoundedRectangle(cornerRadius: VGRadius.medium).strokeBorder(VGColor.separator, lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: VGRadius.medium))
    }

    private func templateMenuButton(_ t: PasswordTemplate) -> some View {
        Button(action: {
            appState.lastTemplateId = t.id
            password = CryptoService.generate(from: t)
            isPasswordVisible = true
        }) {
            if appState.lastTemplateId == t.id {
                Label(t.displayName, systemImage: "checkmark")
            } else {
                Text(t.displayName)
            }
        }
    }

    private var totpImportButtons: some View {
        HStack(spacing: 1) {
            Button(action: { pasteTOTPFromClipboard() }) {
                Image(systemName: "qrcode").font(VGFont.body).foregroundColor(VGColor.secondary)
            }.buttonStyle(.plain).frame(width: 20, height: 20).contentShape(Rectangle()).handCursor()
                .help(L10n.Editor.pasteFromClipboard.localized)
            Button(action: { loadTOTPQRFromFile() }) {
                Image(systemName: "folder").font(VGFont.body).foregroundColor(VGColor.secondary)
            }.buttonStyle(.plain).frame(width: 20, height: 20).contentShape(Rectangle()).handCursor()
                .help(L10n.Editor.loadQRFromFile.localized)
        }
    }

    // MARK: - TOTP QR import

    /// Extract the Base32 `secret` from an `otpauth://` URI (nil if not otpauth or no secret).
    private func otpauthSecret(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.lowercased().hasPrefix("otpauth://"), let comps = URLComponents(string: s) else { return nil }
        let secret = (comps.queryItems ?? []).first { $0.name.lowercased() == "secret" }?.value
        if let secret = secret, !secret.isEmpty { return secret }
        return nil
    }

    /// Prefer the bare Base32 secret so the field reads like a normal key.
    /// Falls back to the raw payload (raw Base32 or `steam://`).
    private func setTOTP(from payload: String) {
        let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        totpSecret = otpauthSecret(trimmed) ?? trimmed
        totpEnabled = true
        totpImportError = nil
    }

    private func decodeQR(from ci: CIImage) -> String? {
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: CIContext(),
                                  options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        for feature in detector?.features(in: ci) ?? [] {
            if let qr = feature as? CIQRCodeFeature, let s = qr.messageString, !s.isEmpty { return s }
        }
        return nil
    }

    private func importQR(image: NSImage) {
        guard let tiff = image.tiffRepresentation, let ci = CIImage(data: tiff) else {
            totpImportError = L10n.Editor.qrNotReadImage.localized; return
        }
        if let payload = decodeQR(from: ci) { setTOTP(from: payload) }
        else { totpImportError = L10n.Editor.qrNotRecognized.localized }
    }

    private func pasteTOTPFromClipboard() {
        let pb = NSPasteboard.general
        guard let imgs = pb.readObjects(forClasses: [NSImage.self], options: nil) as? [NSImage], let img = imgs.first else {
            totpImportError = L10n.Editor.qrNoImageClipboard.localized; return
        }
        importQR(image: img)
    }

    private func loadTOTPQRFromFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image, .png, .jpeg, .tiff]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        if let ci = CIImage(contentsOf: url), let payload = decodeQR(from: ci) { setTOTP(from: payload) }
        else { totpImportError = L10n.Editor.qrNotInFile.localized }
    }

    private func handleTOTPDrop(_ providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first else { return false }
        if provider.canLoadObject(ofClass: NSImage.self) {
            _ = provider.loadObject(ofClass: NSImage.self) { obj, _ in
                if let img = obj as? NSImage { DispatchQueue.main.async { self.importQR(image: img) } }
            }
            return true
        }
        if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url = url else { return }
                DispatchQueue.main.async {
                    if let ci = CIImage(contentsOf: url), let p = self.decodeQR(from: ci) { self.setTOTP(from: p) }
                    else { self.totpImportError = L10n.Editor.qrNotInFile.localized }
                }
            }
            return true
        }
        if provider.canLoadObject(ofClass: String.self) {
            _ = provider.loadObject(ofClass: String.self) { str, _ in
                if let s = str { DispatchQueue.main.async { self.setTOTP(from: s) } }
            }
            return true
        }
        return false
    }

    // MARK: - KeePass icon picker

    @ViewBuilder private var iconSection: some View {
        if appState.activeVaultKind == .keepass {
            Section {
                HStack(spacing: VGSpacing.s) {
                    Text("editor.icon".localized).font(VGFont.body).foregroundColor(VGColor.primary)
                    Spacer()
                    Image(systemName: iconExpanded ? "chevron.down" : "chevron.right")
                        .font(VGFont.caption).foregroundColor(VGColor.secondary)
                }
                .contentShape(Rectangle())
                .onTapGesture { withAnimation { iconExpanded.toggle() } }
                .handCursor()
                if iconExpanded { iconGrid }
            }
        }
    }

    private var iconGrid: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 34), spacing: VGSpacing.s)], spacing: VGSpacing.s) {
            ForEach(0..<69, id: \.self) { idx in iconCell(idx) }
        }
        .padding(.vertical, VGSpacing.xs)
    }

    private func iconCell(_ idx: Int) -> some View {
        let selected = (keepassIcon == KeePassIconRef.standard(idx))
        return Button(action: { keepassIcon = .standard(idx) }) {
            Image(systemName: KeePassIconRef.sfSymbol(forStandard: idx))
                .font(VGFont.body)
                .foregroundColor(selected ? VGColor.onAccent : VGColor.secondary)
                .frame(width: 32, height: 32)
                .background(RoundedRectangle(cornerRadius: VGRadius.small)
                    .fill(selected ? VGColor.accent : VGColor.surface))
        }
        .buttonStyle(.plain).handCursor()
    }

    // MARK: - Load / Save

    private func loadCipher() {
        defer { DispatchQueue.main.async { ready = true } }
        guard let c = cipher else {
            if let t = appState.newItemPrefillType { type = t }
            folderId = appState.newItemPrefillFolderId
            favorite = appState.newItemPrefillFavorite
            isPasswordVisible = false
            return
        }
        isPasswordVisible = false
        name = c.name; type = c.type; folderId = c.folderId; favorite = c.favorite
        notes = c.notes ?? ""; customFields = c.fields ?? []
        keepassIcon = c.keepassIcon
        if let l = c.login {
            username = l.username ?? ""; password = l.password ?? ""; url = l.uris?.first?.uri ?? ""
            totpEnabled = !(l.totp?.isEmpty ?? true); totpSecret = l.totp.map { otpauthSecret($0) ?? $0 } ?? ""
        }
        if let card = c.card {
            cardholderName = card.cardholderName ?? ""; cardNumber = card.number ?? ""
            cardExpMonth = card.expMonth ?? ""; cardExpYear = card.expYear ?? ""
            cardCode = card.code ?? ""; cardBrand = card.brand ?? ""
        }
        if let id = c.identity {
            idTitle = id.title ?? ""; idFirstName = id.firstName ?? ""; idMiddleName = id.middleName ?? ""
            idLastName = id.lastName ?? ""; idUsername = id.username ?? ""; idCompany = id.company ?? ""
            idEmail = id.email ?? ""; idPhone = id.phone ?? ""; idSsn = id.ssn ?? ""
            idPassport = id.passportNumber ?? ""; idLicense = id.licenseNumber ?? ""
            idAddress1 = id.address1 ?? ""; idAddress2 = id.address2 ?? ""; idAddress3 = id.address3 ?? ""
            idCity = id.city ?? ""; idState = id.state ?? ""; idPostalCode = id.postalCode ?? ""
            idCountry = id.country ?? ""
        }
        hasUnsavedChanges = false
    }

    private func save() {
        var newCipher = cipher ?? VaultCipher(id: UUID().uuidString, type: type, name: name, favorite: favorite)
        newCipher.name = name; newCipher.type = type; newCipher.folderId = folderId; newCipher.favorite = favorite
        newCipher.notes = notes.isEmpty ? nil : notes
        newCipher.fields = customFields.filter { !$0.name.isEmpty }
        newCipher.keepassIcon = keepassIcon

        switch type {
        case .login:
            newCipher.login = CipherLogin(username: username.isEmpty ? nil : username, password: password.isEmpty ? nil : password,
                totp: totpEnabled && !totpSecret.isEmpty ? totpSecret : nil,
                uris: url.isEmpty ? nil : [CipherUri(uri: url, match: nil)])
            newCipher.card = nil; newCipher.secureNote = nil; newCipher.identity = nil
        case .card:
            newCipher.card = CipherCard(cardholderName: cardholderName.isEmpty ? nil : cardholderName,
                brand: cardBrand.isEmpty ? nil : cardBrand, number: cardNumber.isEmpty ? nil : cardNumber,
                expMonth: cardExpMonth.isEmpty ? nil : cardExpMonth, expYear: cardExpYear.isEmpty ? nil : cardExpYear,
                code: cardCode.isEmpty ? nil : cardCode)
            newCipher.login = nil; newCipher.secureNote = nil; newCipher.identity = nil
        case .secureNote:
            newCipher.secureNote = CipherSecureNote(type: 0)
            newCipher.login = nil; newCipher.card = nil; newCipher.identity = nil
        case .identity:
            newCipher.identity = CipherIdentity(
                title: idTitle.isEmpty ? nil : idTitle, firstName: idFirstName.isEmpty ? nil : idFirstName,
                middleName: idMiddleName.isEmpty ? nil : idMiddleName, lastName: idLastName.isEmpty ? nil : idLastName,
                company: idCompany.isEmpty ? nil : idCompany, email: idEmail.isEmpty ? nil : idEmail,
                phone: idPhone.isEmpty ? nil : idPhone, ssn: idSsn.isEmpty ? nil : idSsn,
                username: idUsername.isEmpty ? nil : idUsername, passportNumber: idPassport.isEmpty ? nil : idPassport,
                licenseNumber: idLicense.isEmpty ? nil : idLicense,
                address1: idAddress1.isEmpty ? nil : idAddress1, address2: idAddress2.isEmpty ? nil : idAddress2,
                address3: idAddress3.isEmpty ? nil : idAddress3, city: idCity.isEmpty ? nil : idCity,
                state: idState.isEmpty ? nil : idState, postalCode: idPostalCode.isEmpty ? nil : idPostalCode,
                country: idCountry.isEmpty ? nil : idCountry)
            newCipher.login = nil; newCipher.card = nil; newCipher.secureNote = nil
        }

        Task { await appState.saveCipher(newCipher, isNew: isNew); dismiss() }
    }
}
