import Foundation

// MARK: - Domain Models

enum CipherType: Int, Codable, CaseIterable, Identifiable {
    case login = 1; case secureNote = 2; case card = 3; case identity = 4
    var id: Int { rawValue }
    var localizedName: String {
        switch self {
        case .login: return L10n.CipherTypes.logins.localized
        case .secureNote: return L10n.CipherTypes.secureNotes.localized
        case .card: return L10n.CipherTypes.cards.localized
        case .identity: return L10n.CipherTypes.identities.localized
        }
    }
    var name: String { localizedName }
    var icon: String {
        switch self { case .login: return "lock.fill"; case .secureNote: return "note.text"; case .card: return "creditcard.fill"; case .identity: return "person.text.rectangle.fill" }
    }
}

enum FieldType: Int, Codable { case text = 0; case hidden = 1; case boolean = 2 }

struct VaultFolder: Identifiable, Codable { let id: String; var name: String; var revisionDate: Date? }
struct VaultCollection: Identifiable { let id: String; var name: String; var organizationId: String? }
struct VaultOrganization: Identifiable { let id: String; let name: String }

struct CipherField: Identifiable, Codable {
    var id = UUID(); var name: String; var value: String; var type: FieldType
    enum CodingKeys: String, CodingKey { case name, value, type }
    init(name: String = "", value: String = "", type: FieldType = .text) { self.name = name; self.value = value; self.type = type }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        value = try c.decodeIfPresent(String.self, forKey: .value) ?? ""
        type = try c.decodeIfPresent(FieldType.self, forKey: .type) ?? .text
    }
}

struct CipherUri: Codable { var uri: String?; var match: Int? }
struct CipherLogin: Codable { var username: String?; var password: String?; var totp: String?; var uris: [CipherUri]? }
struct CipherCard: Codable { var cardholderName: String?; var brand: String?; var number: String?; var expMonth: String?; var expYear: String?; var code: String? }
struct CipherSecureNote: Codable { var type: Int? }
struct CipherAttachment: Identifiable, Codable { var id: String?; var fileName: String?; var size: String?; var sizeName: String?; var url: String?; var key: String? }

struct CipherIdentity: Codable {
    var title: String?; var firstName: String?; var middleName: String?; var lastName: String?
    var company: String?; var email: String?; var phone: String?; var ssn: String?
    var username: String?; var passportNumber: String?; var licenseNumber: String?
    var address1: String?; var address2: String?; var address3: String?
    var city: String?; var state: String?; var postalCode: String?; var country: String?

    var fullName: String {
        [title, firstName, middleName, lastName].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " ")
    }

    var fullAddress: String {
        var parts: [String] = []
        if let a1 = address1, !a1.isEmpty { parts.append(a1) }
        if let a2 = address2, !a2.isEmpty { parts.append(a2) }
        if let a3 = address3, !a3.isEmpty { parts.append(a3) }
        var cityLine: [String] = []
        if let c = city, !c.isEmpty { cityLine.append(c) }
        if let s = state, !s.isEmpty { cityLine.append(s) }
        if let p = postalCode, !p.isEmpty { cityLine.append(p) }
        if !cityLine.isEmpty { parts.append(cityLine.joined(separator: ", ")) }
        if let co = country, !co.isEmpty { parts.append(co) }
        return parts.joined(separator: "\n")
    }
}

struct VaultCipher: Identifiable, Codable {
    var id: String; var organizationId: String?; var folderId: String?; var collectionIds: [String]?
    var type: CipherType; var name: String; var notes: String?
    var login: CipherLogin?; var card: CipherCard?; var secureNote: CipherSecureNote?; var identity: CipherIdentity?
    var fields: [CipherField]?; var attachments: [CipherAttachment]?
    var favorite: Bool; var reprompt: Int?
    var creationDate: Date?; var revisionDate: Date?; var deletedDate: Date?

    var displayUsername: String {
        switch type {
        case .login: return login?.username ?? ""
        case .card:
            if let n = card?.number, n.count >= 4 { return "•••• \(String(n.suffix(4)))" }
            return card?.brand ?? ""
        case .secureNote: return L10n.Detail.secureNote.localized
        case .identity: return identity?.fullName ?? ""
        }
    }
    var displayUrl: String? { login?.uris?.first?.uri }
    var hostname: String? { guard let u = displayUrl, let url = URL(string: u) else { return nil }; return url.host }
    var initials: String { String(name.prefix(1)).uppercased() }
    var accentColorName: String {
        let c = ["blue","green","orange","purple","red"]
        return c[abs(name.unicodeScalars.reduce(0) { $0 + Int($1.value) }) % c.count]
    }
    var searchableText: String {
        var p = [name, displayUsername]
        if let h = hostname { p.append(h) }; if let n = notes { p.append(n) }
        // Include all URIs for search
        if let uris = login?.uris { for u in uris { if let uri = u.uri { p.append(uri) } } }
        if let id = identity {
            if let ph = id.phone { p.append(ph) }
            if let em = id.email { p.append(em) }
            if let co = id.company { p.append(co) }
        }
        if let f = fields { for field in f { p.append(field.name); if field.type != .hidden { p.append(field.value) } } }
        return p.joined(separator: " ").lowercased()
    }
}

// MARK: - FlexKey

struct FlexKey: CodingKey {
    var stringValue: String; var intValue: Int?
    init(_ s: String) { stringValue = s; intValue = nil }
    init?(stringValue: String) { self.stringValue = stringValue; intValue = nil }
    init?(intValue: Int) { stringValue = "\(intValue)"; self.intValue = intValue }
}

extension KeyedDecodingContainer where K == FlexKey {
    func flex<T: Decodable>(_ type: T.Type, _ key: String) -> T? {
        let p = key.prefix(1).uppercased() + key.dropFirst()
        return (try? decodeIfPresent(type, forKey: FlexKey(key))) ?? (try? decodeIfPresent(type, forKey: FlexKey(p)))
    }
    func flexString(_ k: String) -> String? { flex(String.self, k) }
    func flexInt(_ k: String) -> Int? { flex(Int.self, k) }
    func flexBool(_ k: String) -> Bool? { flex(Bool.self, k) }
}

// MARK: - API Response

struct PreloginResponse: Codable {
    let kdf: Int; let kdfIterations: Int; let kdfMemory: Int?; let kdfParallelism: Int?
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        kdf = c.flexInt("kdf") ?? 0; kdfIterations = c.flexInt("kdfIterations") ?? 600000
        kdfMemory = c.flexInt("kdfMemory"); kdfParallelism = c.flexInt("kdfParallelism")
    }
}

struct TokenResponse: Codable {
    let accessToken: String; let refreshToken: String?; let expiresIn: Int
    let tokenType: String; let key: String?; let privateKey: String?
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        accessToken = c.flexString("access_token") ?? c.flexString("accessToken") ?? ""
        refreshToken = c.flexString("refresh_token") ?? c.flexString("refreshToken")
        expiresIn = c.flexInt("expires_in") ?? c.flexInt("expiresIn") ?? 3600
        tokenType = c.flexString("token_type") ?? c.flexString("tokenType") ?? "Bearer"
        key = c.flexString("key"); privateKey = c.flexString("privateKey")
    }
}

// MARK: - Sync (same as before, abbreviated for brevity — kept intact)

struct SyncResponse: Codable {
    let profile: SyncProfile?; let folders: [SyncFolder]?; let ciphers: [SyncCipher]?; let collections: [SyncCollection]?
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        profile = c.flex(SyncProfile.self, "profile"); folders = c.flex([SyncFolder].self, "folders")
        ciphers = c.flex([SyncCipher].self, "ciphers"); collections = c.flex([SyncCollection].self, "collections")
    }
}

struct SyncProfile: Codable {
    let id: String?; let name: String?; let email: String?; let key: String?; let privateKey: String?
    let organizations: [SyncOrganization]?
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        id = c.flexString("id"); name = c.flexString("name"); email = c.flexString("email")
        key = c.flexString("key"); privateKey = c.flexString("privateKey")
        organizations = c.flex([SyncOrganization].self, "organizations")
    }
}

struct SyncOrganization: Codable {
    let id: String?; let name: String?; let key: String?; let enabled: Bool?; let status: Int?
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        id = c.flexString("id"); name = c.flexString("name"); key = c.flexString("key")
        enabled = c.flexBool("enabled"); status = c.flexInt("status")
    }
}

struct SyncFolder: Codable {
    let id: String?; let name: String?; let revisionDate: String?
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        id = c.flexString("id"); name = c.flexString("name"); revisionDate = c.flexString("revisionDate")
    }
}

struct SyncCipherData: Codable {
    let name: String?; let notes: String?; let username: String?; let password: String?
    let totp: String?; let uris: [SyncUri]?; let fields: [SyncField]?
    let cardholderName: String?; let brand: String?; let number: String?
    let expMonth: String?; let expYear: String?; let code: String?
    let title: String?; let firstName: String?; let middleName: String?; let lastName: String?
    let company: String?; let email: String?; let phone: String?; let ssn: String?
    let passportNumber: String?; let licenseNumber: String?
    let address1: String?; let address2: String?; let address3: String?
    let city: String?; let state: String?; let postalCode: String?; let country: String?
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        name = c.flexString("name"); notes = c.flexString("notes")
        username = c.flexString("username"); password = c.flexString("password")
        totp = c.flexString("totp"); uris = c.flex([SyncUri].self, "uris")
        fields = c.flex([SyncField].self, "fields")
        cardholderName = c.flexString("cardholderName"); brand = c.flexString("brand")
        number = c.flexString("number"); expMonth = c.flexString("expMonth")
        expYear = c.flexString("expYear"); code = c.flexString("code")
        title = c.flexString("title"); firstName = c.flexString("firstName")
        middleName = c.flexString("middleName"); lastName = c.flexString("lastName")
        company = c.flexString("company"); email = c.flexString("email")
        phone = c.flexString("phone"); ssn = c.flexString("ssn")
        passportNumber = c.flexString("passportNumber"); licenseNumber = c.flexString("licenseNumber")
        address1 = c.flexString("address1"); address2 = c.flexString("address2")
        address3 = c.flexString("address3"); city = c.flexString("city")
        state = c.flexString("state"); postalCode = c.flexString("postalCode")
        country = c.flexString("country")
    }
}

struct SyncCipher: Codable {
    let id: String?; let organizationId: String?; let folderId: String?
    let type: Int?; let name: String?; let notes: String?
    let login: SyncLogin?; let card: SyncCard?; let secureNote: SyncSecureNote?; let identity: SyncIdentity?
    let fields: [SyncField]?; let attachments: [SyncAttachment]?
    let favorite: Bool?; let reprompt: Int?
    let creationDate: String?; let revisionDate: String?; let deletedDate: String?
    let data: SyncCipherData?; let collectionIds: [String]?; let key: String?
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        id = c.flexString("id"); organizationId = c.flexString("organizationId"); folderId = c.flexString("folderId")
        type = c.flexInt("type"); name = c.flexString("name"); notes = c.flexString("notes")
        login = c.flex(SyncLogin.self, "login"); card = c.flex(SyncCard.self, "card")
        secureNote = c.flex(SyncSecureNote.self, "secureNote"); identity = c.flex(SyncIdentity.self, "identity")
        fields = c.flex([SyncField].self, "fields"); attachments = c.flex([SyncAttachment].self, "attachments")
        favorite = c.flexBool("favorite"); reprompt = c.flexInt("reprompt")
        creationDate = c.flexString("creationDate"); revisionDate = c.flexString("revisionDate")
        deletedDate = c.flexString("deletedDate"); data = c.flex(SyncCipherData.self, "data")
        collectionIds = c.flex([String].self, "collectionIds")
        key = c.flexString("key")
    }
}

struct SyncIdentity: Codable {
    let title: String?; let firstName: String?; let middleName: String?; let lastName: String?
    let company: String?; let email: String?; let phone: String?; let ssn: String?
    let username: String?; let passportNumber: String?; let licenseNumber: String?
    let address1: String?; let address2: String?; let address3: String?
    let city: String?; let state: String?; let postalCode: String?; let country: String?
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        title = c.flexString("title"); firstName = c.flexString("firstName")
        middleName = c.flexString("middleName"); lastName = c.flexString("lastName")
        company = c.flexString("company"); email = c.flexString("email")
        phone = c.flexString("phone"); ssn = c.flexString("ssn"); username = c.flexString("username")
        passportNumber = c.flexString("passportNumber"); licenseNumber = c.flexString("licenseNumber")
        address1 = c.flexString("address1"); address2 = c.flexString("address2"); address3 = c.flexString("address3")
        city = c.flexString("city"); state = c.flexString("state")
        postalCode = c.flexString("postalCode"); country = c.flexString("country")
    }
}

struct SyncLogin: Codable {
    let username: String?; let password: String?; let totp: String?; let uris: [SyncUri]?
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        username = c.flexString("username"); password = c.flexString("password")
        totp = c.flexString("totp"); uris = c.flex([SyncUri].self, "uris")
    }
}
struct SyncUri: Codable {
    let uri: String?; let match: Int?
    init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: FlexKey.self); uri = c.flexString("uri"); match = c.flexInt("match") }
}
struct SyncCard: Codable {
    let cardholderName: String?; let brand: String?; let number: String?; let expMonth: String?; let expYear: String?; let code: String?
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        cardholderName = c.flexString("cardholderName"); brand = c.flexString("brand"); number = c.flexString("number")
        expMonth = c.flexString("expMonth"); expYear = c.flexString("expYear"); code = c.flexString("code")
    }
}
struct SyncSecureNote: Codable {
    let type: Int?
    init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: FlexKey.self); type = c.flexInt("type") }
}
struct SyncField: Codable {
    let name: String?; let value: String?; let type: Int?
    init(from decoder: Decoder) throws { let c = try decoder.container(keyedBy: FlexKey.self); name = c.flexString("name"); value = c.flexString("value"); type = c.flexInt("type") }
}
struct SyncAttachment: Codable {
    let id: String?; let fileName: String?; let size: String?; let sizeName: String?; let url: String?; let key: String?
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        id = c.flexString("id"); fileName = c.flexString("fileName"); size = c.flexString("size")
        sizeName = c.flexString("sizeName"); url = c.flexString("url"); key = c.flexString("key")
    }
}
struct SyncCollection: Codable {
    let id: String?; let name: String?; let organizationId: String?
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        id = c.flexString("id"); name = c.flexString("name"); organizationId = c.flexString("organizationId")
    }
}

// MARK: - Requests

struct CipherRequest: Codable {
    let type: Int; let name: String; let notes: String?; let folderId: String?
    let favorite: Bool; let login: LoginRequest?; let card: CardRequest?
    let secureNote: SecureNoteRequest?; let identity: IdentityRequest?
    let fields: [FieldRequest]?; let reprompt: Int?
}
struct LoginRequest: Codable { let username: String?; let password: String?; let totp: String?; let uris: [UriRequest]? }
struct CardRequest: Codable { let cardholderName: String?; let brand: String?; let number: String?; let expMonth: String?; let expYear: String?; let code: String? }
struct SecureNoteRequest: Codable { let type: Int }
struct IdentityRequest: Codable {
    let title: String?; let firstName: String?; let middleName: String?; let lastName: String?
    let company: String?; let email: String?; let phone: String?; let ssn: String?
    let username: String?; let passportNumber: String?; let licenseNumber: String?
    let address1: String?; let address2: String?; let address3: String?
    let city: String?; let state: String?; let postalCode: String?; let country: String?
}
struct FieldRequest: Codable { let name: String?; let value: String?; let type: Int }
struct UriRequest: Codable { let uri: String?; let match: Int? }

// MARK: - Password Strength

struct PasswordStrength {
    let score: Int; let label: String; let color: String
    static func evaluate(_ pw: String) -> PasswordStrength {
        guard !pw.isEmpty else { return .init(score: 0, label: "—", color: "secondary") }
        var s = 0
        if pw.count >= 8 { s += 1 }; if pw.count >= 14 { s += 1 }; if pw.count >= 20 { s += 1 }
        if pw.range(of: "[a-z]", options: .regularExpression) != nil && pw.range(of: "[A-Z]", options: .regularExpression) != nil { s += 1 }
        if pw.range(of: "[0-9]", options: .regularExpression) != nil { s += 1 }
        if pw.range(of: "[^a-zA-Z0-9]", options: .regularExpression) != nil { s += 1 }
        switch s {
        case 0...2: return .init(score: 1, label: L10n.Strength.weak.localized, color: "red")
        case 3: return .init(score: 2, label: L10n.Strength.fair.localized, color: "orange")
        case 4: return .init(score: 3, label: L10n.Strength.good.localized, color: "yellow")
        default: return .init(score: 4, label: L10n.Strength.strong.localized, color: "green")
        }
    }
    var fraction: Double { [0: 0, 1: 0.25, 2: 0.5, 3: 0.75, 4: 0.92][score] ?? 0 }
}

// MARK: - Date

extension Date {
    var displayString: String {
        let f = DateFormatter()
        f.locale = Locale(identifier: AppLanguage(rawValue: UserDefaults.standard.string(forKey: "appLanguage") ?? "system")?.resolvedCode ?? "en")
        f.dateFormat = "d MMM yyyy"; return f.string(from: self)
    }
    var daysAgoString: String {
        let d = Calendar.current.dateComponents([.day], from: self, to: Date()).day ?? 0
        if d == 0 { return L10n.Time.today.localized }
        if d == 1 { return L10n.Time.yesterday.localized }
        return L10n.Time.daysAgo.localized(d)
    }
    static func fromISO(_ s: String?) -> Date? {
        guard let s else { return nil }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime]; return f.date(from: s)
    }
}
