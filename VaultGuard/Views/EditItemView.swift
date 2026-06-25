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

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(isNew ? L10n.Editor.newItem.localized : L10n.Editor.editing.localized)
                    .font(.system(size: 17, weight: .bold))
                Spacer()
                Button(action: { attemptDismiss() }) {
                    Image(systemName: "xmark").font(.system(size: 13, weight: .semibold)).foregroundColor(.secondary)
                        .frame(width: 26, height: 26).background(Color(NSColor.controlBackgroundColor).opacity(0.6)).clipShape(Circle())
                }
                .buttonStyle(.plain).handCursor()
            }
            .padding(.horizontal, 24).padding(.top, 20).padding(.bottom, 12)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    FormField(L10n.Editor.nameLabel.localized) {
                        TextField(L10n.Editor.namePlaceholder.localized, text: $name)
                            .textFieldStyle(.roundedBorder)
                            .onChange(of: name) { _ in markChanged() }
                    }

                    HStack(alignment: .top, spacing: 10) {
                        FormField(L10n.Editor.typeLabel.localized) {
                            Menu {
                                ForEach(CipherType.allCases) { t in
                                    Button(action: { type = t; markChanged() }) {
                                        HStack { Text(t.localizedName); if type == t { Image(systemName: "checkmark") } }
                                    }
                                }
                            } label: { dropdownLabel(type.localizedName) }
                            .menuStyle(.borderlessButton).menuIndicator(.hidden).handCursor()
                        }
                        FormField(L10n.Editor.folderLabel.localized) {
                            Menu {
                                Button(action: { folderId = nil; markChanged() }) {
                                    HStack { Text(L10n.noFolder.localized); if folderId == nil { Image(systemName: "checkmark") } }
                                }
                                ForEach(appState.folders) { folder in
                                    Button(action: { folderId = folder.id; markChanged() }) {
                                        HStack { Text(folder.name); if folderId == folder.id { Image(systemName: "checkmark") } }
                                    }
                                }
                            } label: { dropdownLabel(appState.folders.first(where: { $0.id == folderId })?.name ?? L10n.noFolder.localized) }
                            .menuStyle(.borderlessButton).menuIndicator(.hidden).handCursor()
                        }
                    }

                    switch type {
                    case .login: loginFields
                    case .card: cardFields
                    case .secureNote: EmptyView()
                    case .identity: identityFields
                    }

                    FormField(L10n.Editor.notesLabel.localized) {
                        TextEditor(text: $notes)
                            .font(.system(size: 13)).frame(minHeight: 60).padding(4)
                            .background(Color(NSColor.controlBackgroundColor)).cornerRadius(6)
                            .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.2)))
                            .onChange(of: notes) { _ in markChanged() }
                    }

                    Divider()
                    customFieldsSection
                    Divider()

                    Toggle(L10n.Editor.favorite.localized, isOn: $favorite).toggleStyle(.checkbox).handCursor()
                }
                .padding(24)
            }

            Divider()

            HStack {
                Spacer()
                Button(L10n.cancel.localized) { attemptDismiss() }.keyboardShortcut(.escape)
                Button(isNew ? L10n.create.localized : L10n.save.localized) { save() }
                    .buttonStyle(.borderedProminent).disabled(name.isEmpty).keyboardShortcut(.return)
            }
            .padding(.horizontal, 24).padding(.vertical, 14)
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

    // MARK: - TOTP QR import

    /// Extract the Base32 `secret` from an `otpauth://` URI (nil if not otpauth or no secret).
    private func otpauthSecret(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.lowercased().hasPrefix("otpauth://"), let comps = URLComponents(string: s) else { return nil }
        let secret = (comps.queryItems ?? []).first { $0.name.lowercased() == "secret" }?.value
        if let secret = secret, !secret.isEmpty { return secret }
        return nil
    }

    /// A full-width field container that mimics `.roundedBorder` but lets icon
    /// buttons sit *inside* on the trailing edge (so the input spans the full width).
    @ViewBuilder private func fieldBox<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        HStack(spacing: 4) { content() }
            .padding(.horizontal, 6).frame(height: 24)
            .frame(maxWidth: .infinity)
            .background(RoundedRectangle(cornerRadius: 6).fill(Color(NSColor.textBackgroundColor)))
            .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Color(NSColor.separatorColor), lineWidth: 1))
    }

    /// Full-width dropdown styled like a text field (label = current value + chevron).
    private func dropdownLabel(_ text: String) -> some View {
        HStack(spacing: 6) {
            Text(text).font(.system(size: 13)).lineLimit(1).foregroundColor(.primary)
            Spacer()
            Image(systemName: "chevron.up.chevron.down").font(.system(size: 10)).foregroundColor(.secondary)
        }
        .padding(.horizontal, 8).frame(height: 24).frame(maxWidth: .infinity)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(NSColor.controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Color(NSColor.separatorColor), lineWidth: 1))
        .contentShape(Rectangle())
    }

    private func templateMenuButton(_ t: PasswordTemplate) -> some View {
        Button(action: {
            appState.lastTemplateId = t.id
            password = CryptoService.generate(from: t)
            isPasswordVisible = true
            markChanged()
        }) {
            // Text only; the selected item shows a checkmark (native menu selection mark).
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
                Image(systemName: "qrcode").font(.system(size: 13)).foregroundColor(.secondary)
            }.buttonStyle(.plain).frame(width: 20, height: 20).contentShape(Rectangle()).handCursor()
                .help(L10n.Editor.pasteFromClipboard.localized)
            Button(action: { loadTOTPQRFromFile() }) {
                Image(systemName: "folder").font(.system(size: 13)).foregroundColor(.secondary)
            }.buttonStyle(.plain).frame(width: 20, height: 20).contentShape(Rectangle()).handCursor()
                .help(L10n.Editor.loadQRFromFile.localized)
        }
    }

    /// Prefer the bare Base32 secret so the field reads like a normal key.
    /// Falls back to the raw payload (raw Base32 or `steam://`).
    private func setTOTP(from payload: String) {
        let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        totpSecret = otpauthSecret(trimmed) ?? trimmed
        totpEnabled = true
        markChanged()
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
        // Expect an image in the clipboard; validate it actually contains a QR code.
        guard let imgs = pb.readObjects(forClasses: [NSImage.self], options: nil) as? [NSImage], let img = imgs.first else {
            totpImportError = L10n.Editor.qrNoImageClipboard.localized; return
        }
        importQR(image: img)   // sets qrNotRecognized if the image has no valid QR
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

    // MARK: - Login Fields

    private var loginFields: some View {
        VStack(alignment: .leading, spacing: 16) {
            FormField(L10n.Editor.loginLabel.localized) {
                TextField("user@example.com", text: $username).textFieldStyle(.roundedBorder)
                    .onChange(of: username) { _ in markChanged() }
            }
            FormField(L10n.Editor.passwordLabel.localized) {
                fieldBox {
                    Group {
                        if isPasswordVisible {
                            TextField("", text: $password)
                                .textFieldStyle(.plain).font(.system(size: 13, design: .monospaced))
                                .onChange(of: password) { _ in markChanged() }
                        } else {
                            SecureField("", text: $password)
                                .textFieldStyle(.plain).font(.system(size: 13, design: .monospaced))
                                .onChange(of: password) { _ in markChanged() }
                        }
                    }

                    Button(action: { isPasswordVisible.toggle() }) {
                        Image(systemName: isPasswordVisible ? "eye.slash" : "eye").font(.system(size: 13)).foregroundColor(.secondary)
                    }.buttonStyle(.plain).frame(width: 22, height: 20).contentShape(Rectangle()).handCursor()
                    .help((isPasswordVisible ? L10n.Editor.hide : L10n.Editor.show).localized)

                    Button(action: { password = appState.generateFromLastTemplate(); isPasswordVisible = true; markChanged() }) {
                        Image(systemName: "arrow.triangle.2.circlepath").font(.system(size: 13)).foregroundColor(.secondary)
                    }.buttonStyle(.plain).frame(width: 22, height: 20).contentShape(Rectangle()).handCursor()
                    .help(L10n.Editor.generate.localized)

                    Menu {
                        ForEach(appState.passwordTemplates) { t in templateMenuButton(t) }
                    } label: {
                        Image(systemName: "chevron.down").font(.system(size: 11)).foregroundColor(.secondary)
                    }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden)
                    .frame(width: 18).contentShape(Rectangle()).handCursor()
                    .help(L10n.Editor.chooseTemplate.localized)
                }
            }
            FormField(L10n.Editor.urlLabel.localized) {
                TextField("https://...", text: $url).textFieldStyle(.roundedBorder)
                    .onChange(of: url) { _ in markChanged() }
            }
            Toggle(isOn: $totpEnabled) {
                Label(L10n.Editor.totpToggle.localized, systemImage: "lock.shield").font(.system(size: 13))
            }.toggleStyle(.checkbox).handCursor()
            if totpEnabled {
                FormField(L10n.Editor.totpSecretLabel.localized) {
                    VStack(alignment: .leading, spacing: 6) {
                        fieldBox {
                            TextField("JBSWY3DPEHPK3PXP", text: $totpSecret).textFieldStyle(.plain)
                                .font(.system(size: 13, design: .monospaced))
                                .onChange(of: totpSecret) { _ in markChanged(); totpImportError = nil }
                            totpImportButtons
                        }
                        if let err = totpImportError {
                            Text(err).font(.system(size: 11)).foregroundColor(.red)
                        }
                    }
                    .padding(2)
                    .overlay(RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(isDragOver ? Color.accentColor : Color.clear, lineWidth: 2))
                    .onDrop(of: [UTType.image, UTType.fileURL, UTType.url, UTType.text], isTargeted: $isDragOver) { providers in
                        handleTOTPDrop(providers)
                    }
                }
            }
        }
    }

    // MARK: - Card Fields

    private var cardFields: some View {
        VStack(alignment: .leading, spacing: 16) {
            FormField(L10n.Detail.cardHolder.localized) {
                TextField("", text: $cardholderName).textFieldStyle(.roundedBorder)
            }
            FormField(L10n.Detail.cardNumber.localized) {
                TextField("4242 4242 4242 4242", text: $cardNumber).textFieldStyle(.roundedBorder)
                    .font(.system(size: 13, design: .monospaced))
            }
            HStack(spacing: 10) {
                FormField(L10n.Detail.cardExpiry.localized) {
                    HStack(spacing: 4) {
                        TextField("MM", text: $cardExpMonth).textFieldStyle(.roundedBorder).frame(width: 50)
                        Text("/").foregroundColor(.secondary)
                        TextField("YY", text: $cardExpYear).textFieldStyle(.roundedBorder).frame(width: 50)
                    }
                }
                FormField(L10n.Detail.cardCvv.localized) {
                    SecureField("", text: $cardCode).textFieldStyle(.roundedBorder)
                        .font(.system(size: 13, design: .monospaced))
                }
            }
            FormField("Brand") {
                TextField("Visa, Mastercard...", text: $cardBrand).textFieldStyle(.roundedBorder)
            }
        }
    }

    // MARK: - Identity Fields (NEW — full form)

    private var identityFields: some View {
        VStack(alignment: .leading, spacing: 16) {
            FormField(L10n.Identity.title.localized) {
                TextField("Mr., Mrs., Dr.", text: $idTitle).textFieldStyle(.roundedBorder)
                    .onChange(of: idTitle) { _ in markChanged() }
            }
            HStack(spacing: 10) {
                FormField(L10n.Identity.firstName.localized) {
                    TextField("", text: $idFirstName).textFieldStyle(.roundedBorder)
                        .onChange(of: idFirstName) { _ in markChanged() }
                }
                FormField(L10n.Identity.middleName.localized) {
                    TextField("", text: $idMiddleName).textFieldStyle(.roundedBorder)
                        .onChange(of: idMiddleName) { _ in markChanged() }
                }
                FormField(L10n.Identity.lastName.localized) {
                    TextField("", text: $idLastName).textFieldStyle(.roundedBorder)
                        .onChange(of: idLastName) { _ in markChanged() }
                }
            }
            FormField(L10n.Identity.username.localized) {
                TextField("", text: $idUsername).textFieldStyle(.roundedBorder)
                    .onChange(of: idUsername) { _ in markChanged() }
            }
            FormField(L10n.Identity.company.localized) {
                TextField("", text: $idCompany).textFieldStyle(.roundedBorder)
                    .onChange(of: idCompany) { _ in markChanged() }
            }
            HStack(spacing: 10) {
                FormField(L10n.Identity.email.localized) {
                    TextField("user@example.com", text: $idEmail).textFieldStyle(.roundedBorder)
                        .onChange(of: idEmail) { _ in markChanged() }
                }
                FormField(L10n.Identity.phone.localized) {
                    TextField(L10n.Identity.phonePlaceholder.localized, text: $idPhone).textFieldStyle(.roundedBorder)
                        .onChange(of: idPhone) { _ in markChanged() }
                }
            }

            Divider()

            FormField(L10n.Identity.address1.localized) {
                TextField("", text: $idAddress1).textFieldStyle(.roundedBorder)
                    .onChange(of: idAddress1) { _ in markChanged() }
            }
            FormField(L10n.Identity.address2.localized) {
                TextField("", text: $idAddress2).textFieldStyle(.roundedBorder)
                    .onChange(of: idAddress2) { _ in markChanged() }
            }
            FormField(L10n.Identity.address3.localized) {
                TextField("", text: $idAddress3).textFieldStyle(.roundedBorder)
                    .onChange(of: idAddress3) { _ in markChanged() }
            }
            HStack(spacing: 10) {
                FormField(L10n.Identity.city.localized) {
                    TextField("", text: $idCity).textFieldStyle(.roundedBorder)
                        .onChange(of: idCity) { _ in markChanged() }
                }
                FormField(L10n.Identity.state.localized) {
                    TextField("", text: $idState).textFieldStyle(.roundedBorder)
                        .onChange(of: idState) { _ in markChanged() }
                }
            }
            HStack(spacing: 10) {
                FormField(L10n.Identity.postalCode.localized) {
                    TextField("", text: $idPostalCode).textFieldStyle(.roundedBorder)
                        .onChange(of: idPostalCode) { _ in markChanged() }
                }
                FormField(L10n.Identity.country.localized) {
                    TextField("", text: $idCountry).textFieldStyle(.roundedBorder)
                        .onChange(of: idCountry) { _ in markChanged() }
                }
            }

            Divider()

            HStack(spacing: 10) {
                FormField(L10n.Identity.ssn.localized) {
                    TextField("", text: $idSsn).textFieldStyle(.roundedBorder)
                        .font(.system(size: 13, design: .monospaced))
                        .onChange(of: idSsn) { _ in markChanged() }
                }
                FormField(L10n.Identity.passport.localized) {
                    TextField("", text: $idPassport).textFieldStyle(.roundedBorder)
                        .font(.system(size: 13, design: .monospaced))
                        .onChange(of: idPassport) { _ in markChanged() }
                }
            }
            FormField(L10n.Identity.license.localized) {
                TextField("", text: $idLicense).textFieldStyle(.roundedBorder)
                    .font(.system(size: 13, design: .monospaced))
                    .onChange(of: idLicense) { _ in markChanged() }
            }
        }
    }

    // MARK: - Custom Fields

    private var customFieldsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label(L10n.Editor.customFieldsLabel.localized, systemImage: "square.stack.3d.up")
                    .font(.system(size: 13, weight: .semibold))
                Spacer()
            }
            VStack(spacing: 6) {
                ForEach($customFields) { $field in
                    HStack(spacing: 6) {
                        TextField(L10n.Editor.fieldName.localized, text: $field.name).textFieldStyle(.roundedBorder).frame(minWidth: 100)
                        if field.type == .boolean {
                            Picker("", selection: $field.value) {
                                Text("misc.yes".localized).tag("true"); Text("misc.no".localized).tag("false")
                            }.frame(maxWidth: .infinity)
                        } else {
                            TextField(L10n.Editor.fieldValue.localized, text: $field.value).textFieldStyle(.roundedBorder)
                        }
                        Picker("", selection: $field.type) {
                            Text(L10n.Editor.fieldText.localized).tag(FieldType.text)
                            Text(L10n.Editor.fieldHidden.localized).tag(FieldType.hidden)
                            Text(L10n.Editor.fieldBoolean.localized).tag(FieldType.boolean)
                        }.frame(width: 100)
                        Button(action: { customFields.removeAll(where: { $0.id == field.id }) }) {
                            Image(systemName: "xmark").foregroundColor(.secondary)
                        }.buttonStyle(.plain).handCursor()
                    }
                    .padding(8).background(Color(NSColor.controlBackgroundColor)).cornerRadius(6)
                }
            }
            Button(action: { customFields.append(CipherField()); markChanged() }) {
                Label(L10n.Editor.addField.localized, systemImage: "plus")
                    .font(.system(size: 12, weight: .semibold)).foregroundColor(.accentColor)
            }.buttonStyle(.plain).handCursor()
        }
    }

    // MARK: - Load / Save

    private func loadCipher() {
        // Enable change-tracking only after the initial @State population settles,
        // so the onChange storm from loading does not mark the form dirty.
        defer { DispatchQueue.main.async { ready = true } }
        guard let c = cipher else {
            // New item: prefill type/folder/favorite from the section we created it in,
            // and start with the password field visible (we are about to type/generate it).
            if let t = appState.newItemPrefillType { type = t }
            folderId = appState.newItemPrefillFolderId
            favorite = appState.newItemPrefillFavorite
            // Manual entry stays hidden by default (shoulder-surfing safety); the user can
            // reveal it with the eye. Generation explicitly reveals it elsewhere.
            isPasswordVisible = false
            return
        }
        // Existing item: password stays hidden until the eye is tapped.
        isPasswordVisible = false
        name = c.name; type = c.type; folderId = c.folderId; favorite = c.favorite
        notes = c.notes ?? ""; customFields = c.fields ?? []
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

struct FormField<Content: View>: View {
    let label: String; @ViewBuilder let content: Content
    init(_ label: String, @ViewBuilder content: () -> Content) { self.label = label; self.content = content() }
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.system(size: 12, weight: .semibold)).foregroundColor(.secondary)
            content
        }
    }
}

