import Combine
import SwiftUI
import AppKit
import PDFKit

struct DetailView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        if let cipher = appState.selectedCipher {
            CipherDetailView(cipher: cipher).id(cipher.id)
        } else {
            VStack(spacing: 10) {
                Image(systemName: "lock.fill").font(VGFont.emptyGlyphLarge).foregroundColor(VGColor.quaternary)
                Text(L10n.Detail.selectItem.localized).font(VGFont.title2).foregroundColor(VGColor.secondary)
                Text(L10n.Detail.orCreateNew.localized).font(VGFont.body).foregroundColor(VGColor.tertiary)
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

struct CipherDetailView: View {
    @EnvironmentObject var appState: AppState
    let cipher: VaultCipher

    @State private var showPassword = false
    @State private var showSecretFields: Set<String> = []
    @State private var fieldsExpanded = false
    @State private var attachmentsExpanded = false
    @State private var previewingAttachment: CipherAttachment?
    @State private var previewData: Data?
    @State private var loadingAttachmentId: String?
    @State private var attachmentToDelete: CipherAttachment?
    @State private var isDragOver = false
    @State private var showPermanentDeleteConfirm = false

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if let username = cipher.login?.username, !username.isEmpty {
                        FieldRow(label: L10n.Detail.username.localized, value: username, mono: true) { appState.copyToClipboard(username) }
                    }
                    if let password = cipher.login?.password, !password.isEmpty { passwordSection(password) }
                    if let card = cipher.card { cardSection(card) }
                    if let identity = cipher.identity { identitySection(identity) }
                    if let totp = cipher.login?.totp, !totp.isEmpty { TOTPSectionView(secret: totp, cipher: cipher) }
                    if let url = cipher.displayUrl { urlSection(url) }

                    HStack(spacing: 6) {
                        if appState.activeVaultKind != .keepass {
                            TagBadge(text: cipher.type.localizedName, color: .accentColor)
                        }
                        if let folderId = cipher.folderId, let folder = appState.folders.first(where: { $0.id == folderId }) {
                            TagBadge(text: folder.name, color: .purple)
                        }
                        if cipher.organizationId != nil { TagBadge(text: L10n.Sidebar.organization.localized, color: .orange) }
                    }

                    if let notes = cipher.notes, !notes.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            SectionLabel(L10n.Detail.notes.localized)
                            Text(notes).font(VGFont.body).foregroundColor(VGColor.secondary).padding(10)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(VGColor.surface).cornerRadius(VGRadius.medium).textSelection(.enabled)
                        }
                    }

                    customFieldsSection
                    attachmentsSection

                    // Drag & Drop zone
                    fileDropZone

                    metaSection
                }.padding(24)
            }
        }
        .confirmationDialog(L10n.Detail.deleteAttachmentConfirm.localized,
                            isPresented: Binding(get: { attachmentToDelete != nil },
                                                 set: { if !$0 { attachmentToDelete = nil } }),
                            titleVisibility: .visible) {
            Button(L10n.delete.localized, role: .destructive) {
                if let att = attachmentToDelete {
                    Task { await appState.deleteAttachment(cipher: cipher, attachment: att) }
                }
                attachmentToDelete = nil
            }
            Button(L10n.cancel.localized, role: .cancel) { attachmentToDelete = nil }
        }
        .confirmationDialog(L10n.Detail.deleteForeverConfirm.localized,
                            isPresented: $showPermanentDeleteConfirm,
                            titleVisibility: .visible) {
            Button(L10n.Detail.deleteForever.localized, role: .destructive) {
                Task { await appState.permanentlyDeleteKeePassCipher(cipher) }
            }
            Button(L10n.cancel.localized, role: .cancel) { }
        }
        .sheet(item: $previewingAttachment) { attachment in
            AttachmentPreviewSheet(attachment: attachment, data: previewData,
                onDismiss: { previewingAttachment = nil; previewData = nil },
                onSave: { Task { await appState.downloadAttachment(cipher: cipher, attachment: attachment) } })
        }
        .sheet(item: $appState.pendingReprompt) { req in
            RepromptSheet(request: req).environmentObject(appState)
        }
    }

    // MARK: - File Drop Zone

    private var fileDropZone: some View {
        VStack(spacing: 8) {
            if appState.isUploadingAttachments {
                VStack(spacing: 8) {
                    ProgressView(value: appState.attachmentUploadProgress)
                    Text(L10n.DragDrop.uploading.localized).font(VGFont.label).foregroundColor(VGColor.secondary)
                }
                .padding(16)
                .background(VGColor.surface).cornerRadius(VGRadius.large)
            } else {
                VStack(spacing: 6) {
                    Image(systemName: "arrow.down.doc.fill")
                        .font(VGFont.glyphLight)
                        .foregroundColor(isDragOver ? .accentColor : VGColor.tertiary)
                    Text(isDragOver ? L10n.DragDrop.dropFiles.localized : L10n.DragDrop.dropOrChoose.localized)
                        .font(VGFont.label)
                        .foregroundColor(isDragOver ? .accentColor : VGColor.tertiary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 20)
                .background(
                    RoundedRectangle(cornerRadius: VGRadius.large)
                        .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [6, 3]))
                        .foregroundColor(isDragOver ? .accentColor : Color.secondary.opacity(0.3))
                )
                .background(isDragOver ? Color.accentColor.opacity(0.05) : Color.clear)
                .cornerRadius(VGRadius.large)
                .contentShape(Rectangle())
                .onTapGesture { chooseFilesToAttach() }
                .handCursor()
                .onDrop(of: [.fileURL], isTargeted: $isDragOver) { providers in
                    handleDrop(providers: providers)
                    return true
                }
            }
        }
    }

    private func handleDrop(providers: [NSItemProvider]) {
        var urls: [URL] = []
        let group = DispatchGroup()

        for provider in providers {
            group.enter()
            provider.loadItem(forTypeIdentifier: "public.file-url", options: nil) { item, _ in
                defer { group.leave() }
                if let data = item as? Data, let url = URL(dataRepresentation: data, relativeTo: nil) {
                    urls.append(url)
                }
            }
        }

        group.notify(queue: .main) {
            guard !urls.isEmpty else { return }
            Task { await appState.uploadDroppedFiles(urls: urls, toCipher: cipher) }
        }
    }

    private func chooseFilesToAttach() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        guard panel.runModal() == .OK, !panel.urls.isEmpty else { return }
        let urls = panel.urls
        Task { await appState.uploadDroppedFiles(urls: urls, toCipher: cipher) }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 14) {
            CipherAvatar(cipher: cipher, size: 44, glyph: 22, corner: 12, initialsFont: VGFont.largeTitle)
            VStack(alignment: .leading, spacing: 2) {
                Text(cipher.name).font(VGFont.largeTitle)
                if let host = cipher.hostname {
                    Button(action: { if let url = cipher.displayUrl.flatMap({ URL(string: $0) }) { NSWorkspace.shared.open(url) } }) {
                        HStack(spacing: 3) {
                            Image(systemName: "arrow.up.right.square").font(VGFont.caption)
                            Text(host)
                        }.font(VGFont.label).foregroundColor(VGColor.accent)
                    }.buttonStyle(.plain).handCursor()
                }
            }
            Spacer()
            HStack(spacing: 4) {
                if appState.activeVaultKind == .keepass, cipher.deletedDate != nil {
                    DetailActionButton(icon: "arrow.uturn.backward") {
                        Task { await appState.restoreKeePassCipher(cipher) }
                    }.help(L10n.Detail.restore.localized)
                    DetailActionButton(icon: "trash", danger: true) {
                        showPermanentDeleteConfirm = true
                    }.help(L10n.Detail.deleteForever.localized)
                } else {
                    DetailActionButton(icon: "square.and.pencil") { appState.guardReprompt(cipher) { appState.editingCipher = cipher; appState.showEditSheet = true } }
                }
            }
        }.padding(.horizontal, 24).padding(.vertical, 16)
    }

    // MARK: - Password

    private func passwordSection(_ password: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            SectionLabel(L10n.Detail.password.localized)
            HStack(spacing: 8) {
                Text(showPassword ? password : "••••••••••••••••").font(VGFont.bodyMono)
                    .foregroundColor(showPassword ? .primary : .secondary).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button(action: { appState.guardReprompt(cipher) { showPassword.toggle() } }) { Image(systemName: showPassword ? "eye.slash" : "eye").font(VGFont.body).foregroundColor(VGColor.secondary) }.buttonStyle(.plain).handCursor().help((showPassword ? L10n.Editor.hide : L10n.Editor.show).localized)
                Button(action: { appState.guardReprompt(cipher) { appState.copyToClipboard(password) } }) { Image(systemName: "doc.on.doc").font(VGFont.body).foregroundColor(VGColor.secondary) }.buttonStyle(.plain).handCursor().help(L10n.copy.localized)
            }.padding(10).background(VGColor.surface).cornerRadius(VGRadius.medium)

            let strength = PasswordStrength.evaluate(password)
            HStack(spacing: 8) {
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 2).fill(Color.secondary.opacity(0.15)).frame(height: 4)
                        RoundedRectangle(cornerRadius: 2).fill(strengthColor(strength)).frame(width: geo.size.width * strength.fraction, height: 4)
                    }
                }.frame(height: 4)
                Text(strength.label).font(VGFont.captionMedium).foregroundColor(strengthColor(strength))
            }
        }
    }

    private func strengthColor(_ s: PasswordStrength) -> Color {
        switch s.score { case 1: return VGColor.danger; case 2: return VGColor.warning; case 3: return .yellow; case 4: return VGColor.success; default: return VGColor.secondary }
    }

    // MARK: - Card

    private func cardSection(_ card: CipherCard) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if let name = card.cardholderName, !name.isEmpty { FieldRow(label: L10n.Detail.cardHolder.localized, value: name) { appState.copyToClipboard(name) } }
            if let number = card.number, !number.isEmpty { FieldRow(label: L10n.Detail.cardNumber.localized, value: number, mono: true) { appState.guardReprompt(cipher) { appState.copyToClipboard(number) } } }
            HStack(spacing: 16) {
                if let m = card.expMonth, let y = card.expYear { FieldRow(label: L10n.Detail.cardExpiry.localized, value: "\(m)/\(y)", mono: true) { appState.copyToClipboard("\(m)/\(y)") } }
                if let code = card.code, !code.isEmpty { FieldRow(label: L10n.Detail.cardCvv.localized, value: "•••", mono: true) { appState.guardReprompt(cipher) { appState.copyToClipboard(code) } } }
            }
        }
    }

    // MARK: - Identity

    private func identitySection(_ identity: CipherIdentity) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if !identity.fullName.isEmpty { FieldRow(label: L10n.Identity.fullName.localized, value: identity.fullName) { appState.copyToClipboard(identity.fullName) } }
            if let company = identity.company, !company.isEmpty { FieldRow(label: L10n.Identity.company.localized, value: company) { appState.copyToClipboard(company) } }
            if let email = identity.email, !email.isEmpty { FieldRow(label: L10n.Identity.email.localized, value: email) { appState.copyToClipboard(email) } }
            if let phone = identity.phone, !phone.isEmpty { FieldRow(label: L10n.Identity.phone.localized, value: phone) { appState.copyToClipboard(phone) } }
            if let username = identity.username, !username.isEmpty { FieldRow(label: L10n.Identity.username.localized, value: username, mono: true) { appState.copyToClipboard(username) } }
            if !identity.fullAddress.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    SectionLabel(L10n.Identity.address1.localized)
                    HStack(spacing: 8) {
                        Text(identity.fullAddress).font(VGFont.body).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                        Button(action: { appState.copyToClipboard(identity.fullAddress) }) {
                            Image(systemName: "doc.on.doc").font(VGFont.body).foregroundColor(VGColor.secondary)
                        }.buttonStyle(.plain).handCursor().help(L10n.copy.localized)
                    }.padding(10).background(VGColor.surface).cornerRadius(VGRadius.medium)
                }
            }
            if let ssn = identity.ssn, !ssn.isEmpty { FieldRow(label: L10n.Identity.ssn.localized, value: ssn, mono: true) { appState.guardReprompt(cipher) { appState.copyToClipboard(ssn) } } }
            if let passport = identity.passportNumber, !passport.isEmpty { FieldRow(label: L10n.Identity.passport.localized, value: passport, mono: true) { appState.guardReprompt(cipher) { appState.copyToClipboard(passport) } } }
            if let license = identity.licenseNumber, !license.isEmpty { FieldRow(label: L10n.Identity.license.localized, value: license, mono: true) { appState.guardReprompt(cipher) { appState.copyToClipboard(license) } } }
        }
    }

    // MARK: - URL

    private func urlSection(_ url: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            SectionLabel(L10n.Detail.url.localized)
            HStack(spacing: 8) {
                Text(url).font(VGFont.body).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                Button(action: { if let u = URL(string: url) { NSWorkspace.shared.open(u) } }) {
                    Image(systemName: "arrow.up.right.square").font(VGFont.body).foregroundColor(VGColor.secondary)
                }.buttonStyle(.plain).handCursor().help(L10n.Items.openUrl.localized)
                Button(action: { appState.copyToClipboard(url) }) {
                    Image(systemName: "doc.on.doc").font(VGFont.body).foregroundColor(VGColor.secondary)
                }.buttonStyle(.plain).handCursor().help(L10n.copy.localized)
            }.padding(10).background(VGColor.surface).cornerRadius(VGRadius.medium)
        }
    }

    // MARK: - Custom Fields

    @ViewBuilder
    private var customFieldsSection: some View {
        if let fields = cipher.fields, !fields.isEmpty {
            DisclosureGroup(isExpanded: $fieldsExpanded) {
                VStack(spacing: 6) { ForEach(fields) { field in customFieldRow(field) } }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "square.stack.3d.up").font(VGFont.label)
                    Text(fieldsExpanded ? L10n.Detail.customFields.localized : "\(L10n.Detail.customFields.localized) · \(fields.count)").font(VGFont.labelEmphasis)
                }.foregroundColor(VGColor.secondary)
                .contentShape(Rectangle())
                .onTapGesture { withAnimation { fieldsExpanded.toggle() } }
                .handCursor()
            }
        }
    }

    private func customFieldRow(_ field: CipherField) -> some View {
        HStack(spacing: 8) {
            Text(field.name.uppercased()).font(VGFont.caption2Emphasis).foregroundColor(VGColor.tertiary).frame(minWidth: 60, alignment: .leading)
            if field.type == .boolean {
                Text(field.value == "true" ? "misc.yes".localized : "misc.no".localized).font(VGFont.labelEmphasis).foregroundColor(field.value == "true" ? VGColor.success : VGColor.secondary)
            } else if field.type == .hidden {
                let isVisible = showSecretFields.contains(field.id.uuidString)
                Text(isVisible ? field.value : "••••••••").font(VGFont.labelMono).foregroundColor(isVisible ? .primary : .secondary)
                Button(action: { appState.guardReprompt(cipher) { if isVisible { showSecretFields.remove(field.id.uuidString) } else { showSecretFields.insert(field.id.uuidString) } } }) {
                    Image(systemName: isVisible ? "eye.slash" : "eye").font(VGFont.caption).foregroundColor(VGColor.secondary)
                }.buttonStyle(.plain).handCursor().help((isVisible ? L10n.Editor.hide : L10n.Editor.show).localized)
            } else {
                Text(field.value).font(VGFont.labelMono).lineLimit(1)
            }
            Spacer()
            Button(action: {
                if field.type == .hidden { appState.guardReprompt(cipher) { appState.copyToClipboard(field.value) } }
                else { appState.copyToClipboard(field.value) }
            }) {
                Image(systemName: "doc.on.doc").font(VGFont.caption).foregroundColor(VGColor.secondary)
            }.buttonStyle(.plain).handCursor().help(L10n.copy.localized)
        }.padding(8).background(VGColor.surface).cornerRadius(VGRadius.small)
    }

    // MARK: - Attachments

    @ViewBuilder
    private var attachmentsSection: some View {
        if let attachments = cipher.attachments, !attachments.isEmpty {
            DisclosureGroup(isExpanded: $attachmentsExpanded) {
                VStack(spacing: 6) { ForEach(attachments) { att in attachmentRow(att) } }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "paperclip").font(VGFont.label)
                    Text(attachmentsExpanded ? L10n.Detail.attachments.localized : "\(L10n.Detail.attachments.localized) · \(attachments.count)").font(VGFont.labelEmphasis)
                }.foregroundColor(VGColor.secondary)
                .contentShape(Rectangle())
                .onTapGesture { withAnimation { attachmentsExpanded.toggle() } }
                .handCursor()
            }
        }
    }

    private func attachmentRow(_ att: CipherAttachment) -> some View {
        HStack(spacing: 10) {
            Group {
                if AppState.isPreviewable(fileName: att.fileName) {
                    // Icon + name + size act as a single clickable area that opens the preview.
                    Button(action: { appState.guardReprompt(cipher) { Task { await loadAndPreview(att) } } }) {
                        HStack(spacing: 10) {
                            attachmentIcon(att)
                            attachmentLabel(att)
                        }
                        .contentShape(Rectangle())
                    }.buttonStyle(.plain).handCursor()
                } else {
                    HStack(spacing: 10) {
                        attachmentIcon(att)
                        attachmentLabel(att)
                    }
                }
            }
            Spacer()
            if loadingAttachmentId == att.id { ProgressView().controlSize(.small) }
            else {
                if AppState.isPreviewable(fileName: att.fileName) {
                    Button(action: { appState.guardReprompt(cipher) { Task { await loadAndPreview(att) } } }) { Image(systemName: "eye").font(VGFont.body).foregroundColor(VGColor.accent) }.buttonStyle(.plain).handCursor().help(L10n.preview.localized)
                }
                Button(action: { appState.guardReprompt(cipher) { Task { await appState.downloadAttachment(cipher: cipher, attachment: att) } } }) { Image(systemName: "arrow.down.circle").font(VGFont.body).foregroundColor(VGColor.secondary) }.buttonStyle(.plain).handCursor().help(L10n.download.localized)
                Button(action: { attachmentToDelete = att }) { Image(systemName: "trash").font(VGFont.body).foregroundColor(VGColor.danger) }.buttonStyle(.plain).handCursor()
                    .help(L10n.delete.localized)
            }
        }.padding(8).background(VGColor.surface).cornerRadius(VGRadius.small)
    }

    private func attachmentIcon(_ att: CipherAttachment) -> some View {
        ZStack {
            RoundedRectangle(cornerRadius: VGRadius.small).fill(VGColor.surface).frame(width: 34, height: 34)
            Image(systemName: fileIcon(for: att.fileName)).font(VGFont.subheadline).foregroundColor(AppState.isPreviewable(fileName: att.fileName) ? .accentColor : .secondary)
        }
    }

    private func attachmentLabel(_ att: CipherAttachment) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(att.fileName ?? "misc.attachment".localized).font(VGFont.labelMedium).foregroundColor(VGColor.primary).lineLimit(1)
            Text(att.sizeName ?? "").font(VGFont.caption2).foregroundColor(VGColor.secondary)
        }
    }

    private func loadAndPreview(_ attachment: CipherAttachment) async {
        loadingAttachmentId = attachment.id
        if let data = await appState.loadAttachmentData(cipher: cipher, attachment: attachment) { previewData = data; previewingAttachment = attachment }
        loadingAttachmentId = nil
    }

    private func fileIcon(for fileName: String?) -> String {
        guard let name = fileName?.lowercased() else { return "doc.fill" }
        if name.hasSuffix(".pdf") { return "doc.richtext.fill" }
        if AppState.isImage(fileName: name) { return "photo.fill" }
        if name.hasSuffix(".txt") || name.hasSuffix(".md") { return "doc.text.fill" }
        if name.hasSuffix(".zip") || name.hasSuffix(".rar") || name.hasSuffix(".7z") { return "doc.zipper" }
        return "doc.fill"
    }

    // MARK: - Meta

    private var metaSection: some View {
        HStack(spacing: 20) {
            MetaItem(label: L10n.Detail.created.localized, value: cipher.creationDate?.displayString ?? "—")
            MetaItem(label: L10n.Detail.modified.localized, value: cipher.revisionDate?.displayString ?? "—")
            if cipher.login?.password != nil { MetaItem(label: L10n.Detail.passwordAge.localized, value: cipher.revisionDate?.daysAgoString ?? "—") }
        }.padding(.top, 12)
    }
}

// MARK: - Attachment Preview Sheet

struct AttachmentPreviewSheet: View {
    let attachment: CipherAttachment; let data: Data?; let onDismiss: () -> Void; let onSave: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(attachment.fileName ?? "misc.attachment".localized).font(VGFont.title3Bold).lineLimit(1)
                    if let size = attachment.sizeName { Text(size).font(VGFont.caption).foregroundColor(VGColor.secondary) }
                }
                Spacer()
                Button(action: onDismiss) { Image(systemName: "xmark").font(VGFont.bodyEmphasis).foregroundColor(VGColor.secondary).frame(width: 26, height: 26).background(VGColor.surface.opacity(0.6)).clipShape(Circle()) }.buttonStyle(.plain).handCursor().help(L10n.close.localized)
            }.padding(.horizontal, 20).padding(.top, 16).padding(.bottom, 10)
            Divider()
            if let data = data {
                if AppState.isImage(fileName: attachment.fileName) {
                    if let nsImage = NSImage(data: data) {
                        ZoomableImageView(image: nsImage)
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                            .background(VGColor.surface)
                    } else {
                        Text("misc.cannotOpenFile".localized).foregroundColor(VGColor.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
                            .background(VGColor.surface)
                    }
                } else if AppState.isPDF(fileName: attachment.fileName) {
                    PDFKitView(data: data).frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if AppState.isZip(fileName: attachment.fileName) {
                    ZipPreviewView(data: data).frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    VStack(spacing: 10) {
                        Image(systemName: "doc.questionmark").font(VGFont.emptyGlyphLarge).foregroundColor(VGColor.secondary)
                        Text("misc.previewUnavailable".localized).font(VGFont.bodyLarge).foregroundColor(VGColor.secondary)
                    }.frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            } else { ProgressView(L10n.loading.localized).frame(maxWidth: .infinity, maxHeight: .infinity) }
            Divider()
            HStack(spacing: VGSpacing.l) {
                Spacer()
                Button(L10n.close.localized) { onDismiss() }
                    .keyboardShortcut(.escape).handCursor()
                Button(action: onSave) {
                    Label(L10n.save.localized, systemImage: "arrow.down.circle")
                }.buttonStyle(.borderedProminent).handCursor()
            }
            .padding(.horizontal, VGSpacing.xxxl).padding(.vertical, VGSpacing.l)
        }.frame(minWidth: 600, maxWidth: 800, minHeight: 500, maxHeight: 700)
    }
}

/// Image preview backed by AppKit's NSScrollView. Built-in `allowsMagnification`
/// gives pinch-to-zoom centered on the cursor, and two-finger trackpad panning is
/// native. Double-click resets to fit. (No Cmd+scroll zoom, by request.)
struct ZoomableImageView: NSViewRepresentable {
    let image: NSImage

    func makeNSView(context: Context) -> NSScrollView {
        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = false
        scrollView.hasHorizontalScroller = false
        scrollView.allowsMagnification = true
        scrollView.minMagnification = 1.0
        scrollView.maxMagnification = 5.0
        scrollView.drawsBackground = false
        scrollView.borderType = .noBorder

        let imageView = NSImageView()
        imageView.image = image
        imageView.imageScaling = .scaleProportionallyUpOrDown
        imageView.imageAlignment = .alignCenter
        imageView.imageFrameStyle = .none
        // Fill the clip view and track its size changes (this is what was missing —
        // a one-shot frame set ran before the scroll view had a real size).
        imageView.autoresizingMask = [.width, .height]
        imageView.frame = scrollView.contentView.bounds
        scrollView.documentView = imageView

        let dbl = NSClickGestureRecognizer(target: context.coordinator, action: #selector(Coordinator.handleDoubleClick(_:)))
        dbl.numberOfClicksRequired = 2
        imageView.addGestureRecognizer(dbl)
        context.coordinator.scrollView = scrollView

        return scrollView
    }

    func updateNSView(_ nsView: NSScrollView, context: Context) {
        guard let iv = nsView.documentView as? NSImageView else { return }
        if iv.image !== image { iv.image = image }
        // Keep the document view matched to the visible area at 1x.
        if nsView.magnification == 1.0 {
            iv.frame = nsView.contentView.bounds
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator {
        weak var scrollView: NSScrollView?
        @objc func handleDoubleClick(_ sender: NSClickGestureRecognizer) {
            guard let sv = scrollView else { return }
            sv.animator().magnification = 1.0
        }
    }
}

struct PDFKitView: NSViewRepresentable {
    let data: Data
    func makeNSView(context: Context) -> PDFView {
        let pdfView = PDFView(); pdfView.autoScales = true; pdfView.displayMode = .singlePageContinuous
        pdfView.displayDirection = .vertical; pdfView.document = PDFDocument(data: data)
        pdfView.backgroundColor = NSColor.controlBackgroundColor; return pdfView
    }
    func updateNSView(_ nsView: PDFView, context: Context) {}
}

// MARK: - TOTP Section

struct TOTPSectionView: View {
    let secret: String
    let cipher: VaultCipher
    @EnvironmentObject var appState: AppState
    @State private var code = ""; @State private var remaining = 30; @State private var period = 30
    @State private var revealed = false   // reveal masked TOTP only after reprompt this view
    private let totp = TOTPService.shared
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
    private var totpColor: Color { remaining <= 5 ? VGColor.danger : VGColor.accent }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionLabel(L10n.Detail.totp.localized)
            HStack(spacing: 12) {
                Text((revealed || cipher.reprompt != 1) ? code : "••••••").font(VGFont.codeDisplay).foregroundColor(totpColor).tracking(3)
                Spacer()
                ZStack {
                    Circle().stroke(totpColor.opacity(0.15), lineWidth: 3)
                    Circle().trim(from: 0, to: Double(remaining) / Double(max(period, 1)))
                        .stroke(totpColor, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                        .rotationEffect(.degrees(-90)).scaleEffect(x: -1, y: 1)
                    Text("\(remaining)").font(VGFont.captionBold).foregroundColor(totpColor)
                }.frame(width: 34, height: 34)
            }.padding(12).background(totpColor.opacity(0.06)).cornerRadius(VGRadius.large)
            .overlay(RoundedRectangle(cornerRadius: VGRadius.large).stroke(totpColor.opacity(0.1), lineWidth: 1))
            .contentShape(Rectangle())
            .onTapGesture { appState.guardReprompt(cipher) { revealed = true; appState.copyToClipboard(code.replacingOccurrences(of: " ", with: "")) } }
            .handCursor()
        }
        .onAppear { period = totp.period(for: secret); update() }.onReceive(timer) { _ in update() }
    }
    private func update() { code = totp.formattedCode(secret: secret) ?? "--- ---"; remaining = totp.secondsRemaining(for: secret) }
}

// MARK: - Supporting Views

struct FieldRow: View {
    let label: String; let value: String; var mono: Bool = false; var onCopy: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            SectionLabel(label)
            HStack(spacing: 8) {
                Text(value).font(mono ? VGFont.bodyMono : VGFont.body).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                Button(action: onCopy) { Image(systemName: "doc.on.doc").font(VGFont.body).foregroundColor(VGColor.secondary) }.buttonStyle(.plain).handCursor().help(L10n.copy.localized)
            }.padding(10).background(VGColor.surface).cornerRadius(VGRadius.medium)
        }
    }
}

struct SectionLabel: View {
    let text: String; init(_ text: String) { self.text = text }
    var body: some View { Text(text.uppercased()).font(VGFont.caption2Emphasis).foregroundColor(VGColor.tertiary).tracking(0.5) }
}

struct TagBadge: View {
    let text: String; let color: Color
    var body: some View { Text(text).font(VGFont.captionMedium).foregroundColor(color).padding(.horizontal, 10).padding(.vertical, 4).background(color.opacity(0.1)).cornerRadius(VGRadius.small) }
}

struct MetaItem: View {
    let label: String; let value: String
    var body: some View {
        VStack(alignment: .leading, spacing: 2) { Text(label).font(VGFont.caption2).foregroundColor(VGColor.tertiary); Text(value).font(VGFont.captionMedium).foregroundColor(VGColor.secondary) }
    }
}

struct DetailActionButton: View {
    let icon: String; var danger: Bool = false; let action: () -> Void
    var body: some View {
        Button(action: action) {
            Image(systemName: icon).font(VGFont.bodyEmphasis).foregroundColor(danger ? VGColor.danger : VGColor.secondary)
                .frame(width: 28, height: 28)
                .background(VGColor.surface.opacity(0.6)).clipShape(Circle())
        }.buttonStyle(.plain).handCursor()
    }
}

// MARK: - Reprompt Sheet

struct RepromptSheet: View {
    @EnvironmentObject var appState: AppState
    let request: RepromptRequest
    @State private var password = ""
    @State private var error = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "lock.shield").font(VGFont.iconLarge).foregroundColor(VGColor.accent)
                VStack(alignment: .leading, spacing: 2) {
                    Text(L10n.Reprompt.title.localized).font(VGFont.title3Bold)
                    Text(request.cipherName).font(VGFont.label).foregroundColor(VGColor.secondary).lineLimit(1)
                }
            }
            Text(L10n.Reprompt.subtitle.localized).font(VGFont.label).foregroundColor(VGColor.secondary)
            SecureField(L10n.Reprompt.placeholder.localized, text: $password)
                .textFieldStyle(.roundedBorder)
                .onSubmit(verify)
            if error { Text(L10n.Reprompt.wrong.localized).font(VGFont.caption).foregroundColor(VGColor.danger) }
            HStack {
                Spacer()
                Button(L10n.cancel.localized) { appState.cancelReprompt() }.keyboardShortcut(.escape).handCursor()
                Button(L10n.Reprompt.verify.localized, action: verify)
                    .buttonStyle(.borderedProminent)
                    .disabled(password.isEmpty)
                    .handCursor()
            }
        }
        .padding(20)
        .frame(width: 360)
    }

    private func verify() {
        if !appState.submitReprompt(password) { error = true; password = "" }
    }
}
