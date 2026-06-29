import Foundation
import SwiftUI
import Combine

// MARK: - Supported Languages

enum AppLanguage: String, CaseIterable, Identifiable {
    case system = "system"
    case en = "en"
    case ru = "ru"
    // To add a new language:
    // 1. Add case here (e.g. case de = "de")
    // 2. Add displayName below
    // 3. Create Resources/<code>.lproj/Localizable.strings
    // 4. That's it — the picker and bundle logic handle the rest.

    var id: String { rawValue }

    /// Name shown in the picker — always in the target language
    var displayName: String {
        switch self {
        case .system: return L10n.Settings.languageSystem.localized
        case .en: return "English"
        case .ru: return "Русский"
        }
    }

    /// Resolve actual language code (for .system, derive from OS)
    var resolvedCode: String {
        if self == .system {
            let preferred = Locale.preferredLanguages.first ?? "en"
            let code = Locale(identifier: preferred).language.languageCode?.identifier ?? "en"
            return Self.allCases.contains(where: { $0.rawValue == code }) ? code : "en"
        }
        return rawValue
    }
}

// MARK: - Localization Manager

@MainActor
final class LocalizationManager: ObservableObject {
    static let shared = LocalizationManager()

    @Published var currentLanguage: AppLanguage {
        didSet {
            UserDefaults.standard.set(currentLanguage.rawValue, forKey: "appLanguage")
            updateBundle()
        }
    }

    /// The bundle to use for localized string lookups
    @Published private(set) var bundle: Bundle = .main
    /// Thread-safe access to current bundle without MainActor
    nonisolated static var resolvedBundle: Bundle {
        let saved = UserDefaults.standard.string(forKey: "appLanguage") ?? "system"
        let lang = AppLanguage(rawValue: saved) ?? .system
        let code = lang.resolvedCode
        if let path = Bundle.main.path(forResource: code, ofType: "lproj"),
           let b = Bundle(path: path) { return b }
        if let path = Bundle.main.path(forResource: "en", ofType: "lproj"),
           let b = Bundle(path: path) { return b }
        return .main
    }
    
    private init() {
        let saved = UserDefaults.standard.string(forKey: "appLanguage") ?? "system"
        currentLanguage = AppLanguage(rawValue: saved) ?? .system
        updateBundle()
    }

    private func updateBundle() {
        let code = currentLanguage.resolvedCode
        if let path = Bundle.main.path(forResource: code, ofType: "lproj"),
           let langBundle = Bundle(path: path) {
            bundle = langBundle
        } else {
            // Fallback to English
            if let path = Bundle.main.path(forResource: "en", ofType: "lproj"),
               let enBundle = Bundle(path: path) {
                bundle = enBundle
            } else {
                bundle = .main
            }
        }
    }
}

// MARK: - String Extension for Localization

extension String {
    var localized: String {
        let bundle = LocalizationManager.resolvedBundle
        return NSLocalizedString(self, bundle: bundle, comment: "")
    }

    func localized(_ args: CVarArg...) -> String {
        String(format: self.localized, arguments: args)
    }
}

// MARK: - Localization Keys (type-safe)

// Usage: L10n.auth.title.localized or just "auth.title".localized
// Keys are organized by screen/feature for easy navigation.

enum L10n {
    // MARK: Common
    static let cancel = "common.cancel"
    static let save = "common.save"
    static let delete = "common.delete"
    static let close = "common.close"
    static let edit = "common.edit"
    static let create = "common.create"
    static let copied = "common.copied"
    static let copy = "common.copy"
    static let download = "common.download"
    static let preview = "common.preview"
    static let saved = "common.saved"
    static let deleted = "common.deleted"
    static let error = "common.error"
    static let search = "common.search"
    static let noFolder = "common.noFolder"
    static let syncComplete = "common.syncComplete"
    static let syncError = "common.syncError"
    static let encryptionError = "common.encryptionError"
    static let moved = "common.moved"
    static let keePassReadOnly = "keepass.readOnly"
    static let keePassSaveBlockedAttachments = "keepass.saveBlockedAttachments"
    static let fileSaved = "common.fileSaved"
    static let loading = "common.loading"

    // MARK: Window
    enum Window {
        static let showMain = "window.showMain"
    }

    // MARK: Biometric
    enum Biometric {
        static let password = "biometric.password"
        static let generic = "biometric.generic"
        static let unlockReason = "biometric.unlockReason"
        static let enterPassword = "biometric.enterPassword"
        static let saveReason = "biometric.saveReason"
        static let cancelled = "biometric.cancelled"
        static let failed = "biometric.failed"
        static let unavailable = "biometric.unavailable"
    }

    // MARK: Keychain
    enum Keychain {
        static let saveError = "keychain.saveError"
        static let loadError = "keychain.loadError"
        static let deleteError = "keychain.deleteError"
    }

    // MARK: Reprompt
    enum Reprompt {
        static let title = "reprompt.title"
        static let subtitle = "reprompt.subtitle"
        static let placeholder = "reprompt.placeholder"
        static let verify = "reprompt.verify"
        static let wrong = "reprompt.wrong"
    }

    // MARK: Offline
    enum Offline {
        static let usingCache = "offline.usingCache"
    }

    // MARK: Auth
    enum Auth {
        static let title = "auth.title"
        static let subtitle = "auth.subtitle"
        static let serverLabel = "auth.serverLabel"
        static let serverPlaceholder = "auth.serverPlaceholder"
        static let emailLabel = "auth.emailLabel"
        static let emailPlaceholder = "auth.emailPlaceholder"
        static let masterPasswordLabel = "auth.masterPasswordLabel"
        static let masterPasswordPlaceholder = "auth.masterPasswordPlaceholder"
        static let serverHint = "auth.serverHint"
        static let biometricHint = "auth.biometricHint"
        static let biometricHintKeePass = "auth.biometricHintKeePass"
        static let orDivider = "auth.orDivider"
        static let rememberBiometric = "auth.rememberBiometric"
        static let rememberBiometricKeePass = "auth.rememberBiometricKeePass"
        static let kpPersistLabel = "auth.kpPersistLabel"
        static let kpPersistNone = "auth.kpPersistNone"
        static let kpPersistFile = "auth.kpPersistFile"
        static let kpRememberBase = "auth.kpRememberBase"
        static let kpUseBiometric = "auth.kpUseBiometric"
        static let kpPersistNoneHint = "auth.kpPersistNoneHint"
        static let kpPersistFileHint = "auth.kpPersistFileHint"
        static let kpPersistBiometricHint = "auth.kpPersistBiometricHint"
        static let unlockWith = "auth.unlockWith"
        static let useMasterPassword = "auth.useMasterPassword"
        static let loginButton = "auth.loginButton"
        static let loginOther = "auth.loginOther"
        static let addAccount = "auth.addAccount"
        static let currentAccount = "auth.currentAccount"
        static let connectionName = "auth.connectionName"
        static let connectionNamePlaceholder = "auth.connectionNamePlaceholder"
        static let encryptionNote = "auth.encryptionNote"
        static let twoFactorTitle = "auth.twoFactorTitle"
        static let twoFactorPrompt = "auth.twoFactorPrompt"
        static let twoFactorCode = "auth.twoFactorCode"
        static let twoFactorRemember = "auth.twoFactorRemember"
        static let twoFactorVerify = "auth.twoFactorVerify"
        static let twoFactorProviderLabel = "auth.twoFactorProviderLabel"
        static let twoFactorProviderAuthenticator = "auth.twoFactorProviderAuthenticator"
        static let twoFactorProviderEmail = "auth.twoFactorProviderEmail"
        static let twoFactorProviderYubiKey = "auth.twoFactorProviderYubiKey"
        static let twoFactorSendEmail = "auth.twoFactorSendEmail"
        static let twoFactorEmailSent = "auth.twoFactorEmailSent"
        static let twoFactorUnsupported = "auth.twoFactorUnsupported"

        // Storage type selection (Bitwarden server vs local KeePass .kdbx)
        static let storageLabel = "auth.storageLabel"
        static let storageBitwarden = "auth.storageBitwarden"
        static let storageKeePass = "auth.storageKeePass"
        static let kdbxFileLabel = "auth.kdbxFileLabel"
        static let kdbxChoose = "auth.kdbxChoose"
        static let keyfileLabel = "auth.keyfileLabel"
        static let keyfileChoose = "auth.keyfileChoose"
        static let keyfileNone = "auth.keyfileNone"
        static let kdbxNone = "auth.kdbxNone"
        static let chooseButton = "auth.chooseButton"
        static let openButton = "auth.openButton"
        static let createDatabaseButton = "auth.createDatabaseButton"
        static let kpPasswordHint = "auth.kpPasswordHint"
        static let bookmarkExpired = "auth.bookmarkExpired"
        static let keepassComingSoon = "auth.keepassComingSoon"
    }

    // MARK: Sidebar
    enum Send {
        static let subtitle = "send.subtitle"
        static let typeText = "send.typeText"
        static let typeFile = "send.typeFile"
        static let statusActive = "send.statusActive"
        static let statusDisabled = "send.statusDisabled"
        static let noExpiration = "send.noExpiration"
        static let expiresIn = "send.expiresIn"
        static let expired = "send.expired"
        static let autoDeletesIn = "send.autoDeletesIn"
        static let viewsMaxFmt = "send.viewsMaxFmt"
        static let durDays = "send.durDays"
        static let durHours = "send.durHours"
        static let durSoon = "send.durSoon"
        static let hour1 = "send.hour1"
        static let days2 = "send.days2"
        static let days14 = "send.days14"
        static let notesLabel = "send.notesLabel"
        static let title = "send.title"
        static let newText = "send.newText"
        static let newFile = "send.newFile"
        static let modeText = "send.modeText"
        static let modeFile = "send.modeFile"
        static let chooseFile = "send.chooseFile"
        static let maxAccess = "send.maxAccess"
        static let unlimited = "send.unlimited"
        static let hideEmail = "send.hideEmail"
        static let password = "send.password"
        static let nameLabel = "send.nameLabel"
        static let contentLabel = "send.contentLabel"
        static let hideText = "send.hideText"
        static let expiry = "send.expiry"
        static let createButton = "send.createButton"
        static let copyLink = "send.copyLink"
        static let copied = "send.copied"
        static let created = "send.created"
        static let updated = "send.updated"
        static let edit = "send.edit"
        static let disable = "send.disable"
        static let enable = "send.enable"
        static let disabledBadge = "send.disabledBadge"
        static let resetExpiry = "send.resetExpiry"
        static let active = "send.active"
        static let empty = "send.empty"
        static let deletes = "send.deletes"
        static let accessCount = "send.accessCount"
        static let days7 = "send.days7"
        static let days30 = "send.days30"
        static let days1 = "send.days1"
    }

    enum Sidebar {
        static let allItems = "sidebar.allItems"
        static let favorites = "sidebar.favorites"
        static let vault = "sidebar.vault"
        static let types = "sidebar.types"
        static let folders = "sidebar.folders"
        static let collections = "sidebar.collections"
        static let trash = "sidebar.trash"
        static let newFolder = "sidebar.newFolder"
        static let generator = "sidebar.generator"
        static let sends = "sidebar.sends"
        static let settings = "sidebar.settings"
        static let sync = "sidebar.sync"
        static let lock = "sidebar.lock"
        static let logout = "sidebar.logout"
        static let myVault = "sidebar.myVault"
        static let organization = "sidebar.organization"
    }

    // MARK: Items List
    enum Items {
        static let newItem = "items.newItem"
        static let sortName = "items.sortName"
        static let sortDate = "items.sortDate"
        static let notFound = "items.notFound"
        static let noResults = "items.noResults"
        static let emptyTitle = "items.emptyTitle"
        static let emptySubtitle = "items.emptySubtitle"
        static let emptyTrash = "items.emptyTrash"
        static let emptyFavorites = "items.emptyFavorites"
        static let emptyFavoritesSubtitle = "items.emptyFavoritesSubtitle"
        static let itemsCount = "items.count"
        static let copyPassword = "items.copyPassword"
        static let copyLogin = "items.copyLogin"
        static let openUrl = "items.openUrl"
        static let moveToFolder = "items.moveToFolder"
        static let addFavorite = "items.addFavorite"
        static let removeFavorite = "items.removeFavorite"
        static let duplicate = "items.duplicate"
        static let copySuffix = "items.copySuffix"
    }

    // MARK: Detail
    enum Detail {
        static let selectItem = "detail.selectItem"
        static let orCreateNew = "detail.orCreateNew"
        static let username = "detail.username"
        static let password = "detail.password"
        static let url = "detail.url"
        static let notes = "detail.notes"
        static let customFields = "detail.customFields"
        static let attachments = "detail.attachments"
        static let deleteAttachmentConfirm = "detail.deleteAttachmentConfirm"
        static let created = "detail.created"
        static let modified = "detail.modified"
        static let passwordAge = "detail.passwordAge"
        static let restore = "detail.restore"
        static let restored = "detail.restored"
        static let deleteForever = "detail.deleteForever"
        static let deleteForeverConfirm = "detail.deleteForeverConfirm"
        static let totp = "detail.totp"
        static let totpKey = "detail.totpKey"
        static let cardHolder = "detail.cardHolder"
        static let cardNumber = "detail.cardNumber"
        static let cardExpiry = "detail.cardExpiry"
        static let cardCvv = "detail.cardCvv"
        static let secureNote = "detail.secureNote"
        static let dropFilesHere = "detail.dropFilesHere"
    }

    // MARK: Identity
    enum Identity {
        static let fullName = "identity.fullName"
        static let firstName = "identity.firstName"
        static let middleName = "identity.middleName"
        static let lastName = "identity.lastName"
        static let title = "identity.title"
        static let company = "identity.company"
        static let email = "identity.email"
        static let phone = "identity.phone"
        static let phonePlaceholder = "identity.phonePlaceholder"
        static let ssn = "identity.ssn"
        static let passport = "identity.passport"
        static let license = "identity.license"
        static let address1 = "identity.address1"
        static let address2 = "identity.address2"
        static let address3 = "identity.address3"
        static let city = "identity.city"
        static let state = "identity.state"
        static let postalCode = "identity.postalCode"
        static let country = "identity.country"
        static let username = "identity.username"
    }

    // MARK: Editor
    enum Editor {
        static let newItem = "editor.newItem"
        static let editing = "editor.editing"
        static let nameLabel = "editor.nameLabel"
        static let namePlaceholder = "editor.namePlaceholder"
        static let typeLabel = "editor.typeLabel"
        static let folderLabel = "editor.folderLabel"
        static let loginLabel = "editor.loginLabel"
        static let passwordLabel = "editor.passwordLabel"
        static let passwordPlaceholder = "editor.passwordPlaceholder"
        static let urlLabel = "editor.urlLabel"
        static let totpToggle = "editor.totpToggle"
        static let totpSecretLabel = "editor.totpSecretLabel"
        static let totpHint = "editor.totpHint"
        static let notesLabel = "editor.notesLabel"
        static let favorite = "editor.favorite"
        static let customFieldsLabel = "editor.customFieldsLabel"
        static let addField = "editor.addField"
        static let fieldName = "editor.fieldName"
        static let fieldValue = "editor.fieldValue"
        static let fieldText = "editor.fieldText"
        static let fieldHidden = "editor.fieldHidden"
        static let fieldBoolean = "editor.fieldBoolean"
        static let generate = "editor.generate"
        static let show = "editor.show"
        static let hide = "editor.hide"
        static let pasteFromClipboard = "editor.pasteFromClipboard"
        static let loadQRFromFile = "editor.loadQRFromFile"
        static let qrNotReadImage = "editor.qrNotReadImage"
        static let qrNotRecognized = "editor.qrNotRecognized"
        static let qrClipboardEmpty = "editor.qrClipboardEmpty"
        static let qrNoImageClipboard = "editor.qrNoImageClipboard"
        static let qrNotInFile = "editor.qrNotInFile"
        static let defaultGenerator = "editor.defaultGenerator"
        static let chooseTemplate = "editor.chooseTemplate"
        static let unsavedTitle = "editor.unsavedTitle"
        static let unsavedMessage = "editor.unsavedMessage"
        static let discardChanges = "editor.discardChanges"
        static let continueEditing = "editor.continueEditing"
        static let basicInfo = "editor.basicInfo"
        static let credentials = "editor.credentials"
        static let links = "editor.links"
        static let cardData = "editor.cardData"
        static let personalData = "editor.personalData"
        static let addressSection = "editor.addressSection"
        static let contacts = "editor.contacts"
        static let advanced = "editor.advanced"
        static let cardBrand = "editor.cardBrand"
        static let cardBrandPlaceholder = "editor.cardBrandPlaceholder"
    }

    // MARK: Generator
    enum Generator {
        static let title = "generator.title"
        static let length = "generator.length"
        static let refresh = "generator.refresh"
        static let excludeAmbiguous = "generator.excludeAmbiguous"
        static let templates = "generator.templates"
        static let noTemplates = "generator.noTemplates"
        static let saveAsTemplate = "generator.saveAsTemplate"
        static let updateSelected = "generator.updateSelected"
        static let newTemplate = "generator.newTemplate"
        static let renameTemplate = "generator.renameTemplate"
        static let templateName = "generator.templateName"
        static let noSimilarShort = "generator.noSimilarShort"
        static let starterStandard = "generator.starterStandard"
        static let starterStrong30 = "generator.starterStrong30"
        static let starterAlnum12 = "generator.starterAlnum12"
        static let starterPin6 = "generator.starterPin6"
        static let templateLabel = "generator.templateLabel"
        static let builtinSection = "generator.builtinSection"
        static let mySection = "generator.mySection"
        static let saveCurrentAsNew = "generator.saveCurrentAsNew"
        static let appliedBanner = "generator.appliedBanner"
        static let differsTitle = "generator.differsTitle"
        static let differsBody = "generator.differsBody"
        static let updateTemplate = "generator.updateTemplate"
        static let saveAsNew = "generator.saveAsNew"
        static let reset = "generator.reset"
        static let usePassword = "generator.usePassword"
        static let copyPassword = "generator.copyPassword"
        static let charset = "generator.charset"
        static let generatedLabel = "generator.generatedLabel"
        static let newTemplateNamePrefix = "generator.newTemplateNamePrefix"
    }

    // MARK: Settings
    enum Settings {
        static let title = "settings.title"
        static let account = "settings.account"
        static let connectionName = "settings.connectionName"
        static let server = "settings.server"
        static let security = "settings.security"
        static let interface = "settings.interface"
        static let about = "settings.about"
        static let unlock = "settings.unlock"
        static let certificates = "settings.certificates"
        static let timeouts = "settings.timeouts"
        static let autofill = "settings.autofill"
        static let appearance = "settings.appearance"
        static let support = "settings.support"
        static let dataTab = "settings.dataTab"
        static let selfSigned = "settings.selfSigned"
        static let selfSignedHint = "settings.selfSignedHint"
        static let biometry = "settings.biometry"
        static let biometryUnavailable = "settings.biometryUnavailable"
        static let masterPasswordSaved = "settings.masterPasswordSaved"
        static let masterPassword = "settings.masterPassword"
        static let storedInKeychain = "settings.storedInKeychain"
        static let notSaved = "settings.notSaved"
        static let forget = "settings.forget"
        static let languageSystem = "settings.languageSystem"
        static let clipboardTimeout = "settings.clipboardTimeout"
        static let autoLock = "settings.autoLock"
        static let autoFillKeyTTL = "settings.autoFillKeyTTL"
        static let autoFillKeyTTLHint = "settings.autoFillKeyTTLHint"
        static let theme = "settings.theme"
        static let themeSystem = "settings.themeSystem"
        static let themeLight = "settings.themeLight"
        static let themeDark = "settings.themeDark"
        static let language = "settings.language"
        static let showFavicons = "settings.showFavicons"
        static let logoutButton = "settings.logoutButton"
        static let vaultguardDesc = "settings.vaultguardDesc"
        static let author = "settings.author"
        static let sourceCode = "settings.sourceCode"
        static let contact = "settings.contact"
        static let trustedCertificate = "settings.trustedCertificate"
        static let pinned = "settings.pinned"
    }

    // MARK: Cipher Types
    enum CipherTypes {
        static let logins = "cipherType.logins"
        static let secureNotes = "cipherType.secureNotes"
        static let cards = "cipherType.cards"
        static let identities = "cipherType.identities"
    }

    // MARK: Password Strength
    enum Strength {
        static let weak = "strength.weak"
        static let fair = "strength.fair"
        static let good = "strength.good"
        static let strong = "strength.strong"
    }

    // MARK: Folder
    enum Folder {
        static let newTitle = "folder.newTitle"
        static let renameTitle = "folder.renameTitle"
        static let namePlaceholder = "folder.namePlaceholder"
        static let deleteTitle = "folder.deleteTitle"
        static let deleteMessage = "folder.deleteMessage"
        static let created = "folder.created"
        static let renamed = "folder.renamed"
        static let deleted = "folder.deleted"
    }

    // MARK: Time
    enum Time {
        static let today = "time.today"
        static let yesterday = "time.yesterday"
        static let daysAgo = "time.daysAgo"
        static let seconds10 = "time.seconds10"
        static let seconds30 = "time.seconds30"
        static let seconds60 = "time.seconds60"
        static let minutes2 = "time.minutes2"
        static let minute1 = "time.minute1"
        static let minutes5 = "time.minutes5"
        static let minutes15 = "time.minutes15"
        static let hour1 = "time.hour1"
        static let hours4 = "time.hours4"
        static let hours8 = "time.hours8"
        static let never = "time.never"
    }

    // MARK: Drag & Drop
    enum Migration {
        static let exportComplete = "migration.exportComplete"
        static let exportButton = "migration.exportButton"
        static let exportTitle = "migration.exportTitle"
        static let exportHint = "migration.exportHint"
        static let newPassword = "migration.newPassword"
        static let confirmPassword = "migration.confirmPassword"
        static let passwordMismatch = "migration.passwordMismatch"
        static let importButton = "migration.importButton"
        static let importJSONButton = "migration.importJSONButton"
        static let importJSONHint = "migration.importJSONHint"
        static let importCSVButton = "migration.importCSVButton"
        static let importCSVHint = "migration.importCSVHint"
        static let importCompleteDedup = "migration.importCompleteDedup"
        static let importTitle = "migration.importTitle"
        static let importHint = "migration.importHint"
        static let importComplete = "migration.importComplete"
        static let importEmpty = "migration.importEmpty"
        static let chooseFile = "migration.chooseFile"
    }

    enum DragDrop {
        static let uploading = "dragdrop.uploading"
        static let uploadComplete = "dragdrop.uploadComplete"
        static let uploadFailed = "dragdrop.uploadFailed"
        static let dropFiles = "dragdrop.dropFiles"
        static let dropOrChoose = "dragdrop.dropOrChoose"
        static let processingFolder = "dragdrop.processingFolder"
    }

    // MARK: Delete Confirm
    enum DeleteConfirm {
        static let title = "deleteConfirm.title"
        static let message = "deleteConfirm.message"
    }

    enum CertTrust {
        static let titleUntrusted = "certTrust.titleUntrusted"
        static let titleChanged = "certTrust.titleChanged"
        static let bodySelfSigned = "certTrust.bodySelfSigned"
        static let bodyChanged = "certTrust.bodyChanged"
        static let trust = "certTrust.trust"
        static let trustAnyway = "certTrust.trustAnyway"
        static let cancelled = "certTrust.cancelled"
    }

    enum AutoFill {
        static let openApp = "autofill.openApp"
        static let tryAgain = "autofill.tryAgain"
        static let errNotConfigured = "autofill.errNotConfigured"
        static let errLocked = "autofill.errLocked"
        static let repromptReason = "autofill.repromptReason"
        static let errNoCache = "autofill.errNoCache"
        static let errDecode = "autofill.errDecode"
        static let errNoMatch = "autofill.errNoMatch"
    }

    enum Account {
        static let dataNotRemoved = "account.dataNotRemoved"
        static let removeAccount = "account.removeAccount"
        static let biometricNotEnabled = "account.biometricNotEnabled"
        static let biometricNotDisabled = "account.biometricNotDisabled"
        static let appGroupUnavailable = "account.appGroupUnavailable"
    }
}
