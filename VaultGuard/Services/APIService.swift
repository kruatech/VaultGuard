import Foundation

actor APIService {
    private var baseURL: String = ""
    /// Resolved base for the API service (`/sync`, `/ciphers`, …).
    private var apiBaseURL: String = ""
    /// Resolved base for the identity service (`/connect/token`, `/accounts/prelogin`).
    private var identityBaseURL: String = ""

    /// Sent as `Bitwarden-Client-Version`; the official cloud rejects logins without it.
    /// Bump if the server ever requires a newer client.
    static let clientVersion = "2026.6.0"

    private var accessToken: String?
    private var refreshToken: String?
    private var tokenExpiry: Date?

    private var session: URLSession
    private let decoder: JSONDecoder

    init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        session = URLSession(configuration: config)
        decoder = JSONDecoder()
    }

    func configure(serverURL: String, allowSelfSigned: Bool = false) {
        var url = serverURL.trimmingCharacters(in: .whitespacesAndNewlines)
        // Default to https when the scheme is omitted (avoids nil URLs / 405 from the wrong host).
        let lower = url.lowercased()
        if !lower.hasPrefix("http://") && !lower.hasPrefix("https://") {
            url = "https://" + url
        }
        while url.hasSuffix("/") { url.removeLast() }
        self.baseURL = url

        // The official Bitwarden cloud serves API and identity on dedicated subdomains;
        // self-hosted Bitwarden / Vaultwarden serve them under one host at /api and /identity.
        let endpoints = Self.resolveEndpoints(for: url)
        self.apiBaseURL = endpoints.api
        self.identityBaseURL = endpoints.identity

        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        // Bitwarden cloud rejects logins without client-identification headers
        // ("No client version header found ...").
        config.httpAdditionalHeaders = [
            "Bitwarden-Client-Name": "desktop",
            "Bitwarden-Client-Version": Self.clientVersion,
            "Device-Type": "7",
        ]

        if allowSelfSigned, let host = URL(string: url)?.host {
            let delegate = PinnedCertDelegate(trustedHosts: [host])
            session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        } else {
            session = URLSession(configuration: config)
        }
    }

    /// Map a normalized server URL to its API and identity base URLs.
    /// Known Bitwarden cloud hosts use dedicated subdomains; everything else (self-hosted
    /// Bitwarden / Vaultwarden) is served under one host at `/api` and `/identity`.
    static func resolveEndpoints(for serverURL: String) -> (api: String, identity: String) {
        let host = (URL(string: serverURL)?.host
            ?? serverURL.replacingOccurrences(of: "https://", with: "")
                        .replacingOccurrences(of: "http://", with: "")
                        .components(separatedBy: "/").first
            ?? "").lowercased()

        switch host {
        case "bitwarden.com", "www.bitwarden.com", "vault.bitwarden.com":
            return ("https://api.bitwarden.com", "https://identity.bitwarden.com")
        case "bitwarden.eu", "www.bitwarden.eu", "vault.bitwarden.eu":
            return ("https://api.bitwarden.eu", "https://identity.bitwarden.eu")
        default:
            return ("\(serverURL)/api", "\(serverURL)/identity")
        }
    }

    func setTokens(access: String, refresh: String?, expiresIn: Int) {
        self.accessToken = access
        self.refreshToken = refresh
        self.tokenExpiry = Date().addingTimeInterval(TimeInterval(expiresIn))
    }

    func clearTokens() {
        accessToken = nil; refreshToken = nil; tokenExpiry = nil
    }

    var isAuthenticated: Bool { accessToken != nil }
    var currentAccessToken: String? { accessToken }
    var currentRefreshToken: String? { refreshToken }

    // MARK: - Auth Endpoints

    func prelogin(email: String) async throws -> PreloginResponse {
        let body: [String: Any] = ["email": email]
        do {
            // Older self-hosted servers serve prelogin from the API service.
            return try await post("\(apiBaseURL)/accounts/prelogin", body: body, auth: false)
        } catch let APIError.serverError(code, _) where code == 404 || code == 405 {
            // Newer Bitwarden and the official cloud serve prelogin from the identity service.
            return try await post("\(identityBaseURL)/accounts/prelogin", body: body, auth: false)
        }
    }

    func login(email: String, masterPasswordHash: String, deviceName: String = "VaultGuard macOS") async throws -> TokenResponse {
        let params = [
            "grant_type": "password",
            "username": email,
            "password": masterPasswordHash,
            "scope": "api offline_access",
            "client_id": "desktop",
            "deviceType": "7", // Bitwarden DeviceType.MacOsDesktop
            "deviceIdentifier": deviceIdentifier(),
            "deviceName": deviceName,
        ]
        do {
            return try await postForm("\(identityBaseURL)/connect/token", params: params)
        } catch let APIError.serverError(code, body) where code == 400 && APIError.isTwoFactorBody(body) {
            throw APIError.twoFactorRequired(providers: APIError.parseTwoFactorProviders(body))
        }
    }

    /// Ask the server to send a login 2FA code by email (provider 1).
    func sendTwoFactorEmailLogin(email: String, masterPasswordHash: String) async throws {
        let body: [String: Any] = [
            "email": email,
            "masterPasswordHash": masterPasswordHash,
            "deviceIdentifier": deviceIdentifier(),
        ]
        try await postExpectingNoContent("\(apiBaseURL)/two-factor/send-email-login", body: body, auth: false)
    }
    func login2FA(email: String, masterPasswordHash: String, twoFactorCode: String,
                  twoFactorProvider: Int = 0, rememberDevice: Bool = false,
                  deviceName: String = "VaultGuard macOS") async throws -> TokenResponse {
        let params = [
            "grant_type": "password",
            "username": email,
            "password": masterPasswordHash,
            "scope": "api offline_access",
            "client_id": "desktop",
            "deviceType": "7", // Bitwarden DeviceType.MacOsDesktop
            "deviceIdentifier": deviceIdentifier(),
            "deviceName": deviceName,
            "twoFactorToken": twoFactorCode,
            "twoFactorProvider": "\(twoFactorProvider)",
            "twoFactorRemember": rememberDevice ? "1" : "0",
        ]
        return try await postForm("\(identityBaseURL)/connect/token", params: params)
    }

    func refreshAccessToken() async throws -> TokenResponse {
        guard let rt = refreshToken else { throw APIError.noRefreshToken }
        let params = [
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "client_id": "desktop",
        ]
        let response: TokenResponse = try await postForm("\(identityBaseURL)/connect/token", params: params)
        setTokens(access: response.accessToken, refresh: response.refreshToken ?? rt, expiresIn: response.expiresIn)
        return response
    }

    // MARK: - Sync

    func sync() async throws -> SyncResponse {
        return try await get("\(apiBaseURL)/sync")
    }

    /// Raw sync bytes, used to persist an encrypted offline cache.
    func syncData() async throws -> Data {
        return try await getData("\(apiBaseURL)/sync")
    }

    /// Decode a (possibly cached) sync payload using the configured decoder.
    func decodeSync(_ data: Data) throws -> SyncResponse {
        return try decoder.decode(SyncResponse.self, from: data)
    }

    // MARK: - Ciphers CRUD

    func createCipher(_ request: CipherRequest) async throws -> SyncCipher {
        return try await postJSON("\(apiBaseURL)/ciphers", body: request)
    }

    func updateCipher(id: String, _ request: CipherRequest) async throws -> SyncCipher {
        return try await putJSON("\(apiBaseURL)/ciphers/\(id)", body: request)
    }

    func deleteCipher(id: String) async throws {
        try await delete("\(apiBaseURL)/ciphers/\(id)")
    }

    // MARK: - Attachments

    func deleteAttachment(cipherId: String, attachmentId: String) async throws {
        try await delete("\(apiBaseURL)/ciphers/\(cipherId)/attachment/\(attachmentId)")
    }

    func downloadAttachment(cipherId: String, attachmentId: String) async throws -> (Data, String?) {
        let urlStr = "\(apiBaseURL)/ciphers/\(cipherId)/attachment/\(attachmentId)"
        let info: AttachmentDownloadResponse = try await get(urlStr)
        guard let downloadUrl = info.url else {
            let data = try await getData(urlStr)
            return (data, nil)
        }
        let data = try await getData(downloadUrl)
        return (data, info.fileName)
    }

    /// Upload an already-encrypted attachment. The file data must already be in the
    /// `[type][iv][mac][ct]` buffer format and `encryptedKey` must be the file key
    /// wrapped with the cipher/org key. Tries the modern two-step v2 flow and falls
    /// back to the legacy single-step multipart endpoint on older servers.
    func uploadAttachment(cipherId: String, encryptedFileName: String, encryptedData: Data, encryptedKey: String) async throws {
        do {
            try await uploadAttachmentV2(cipherId: cipherId, encryptedFileName: encryptedFileName,
                                         encryptedData: encryptedData, encryptedKey: encryptedKey)
        } catch let APIError.serverError(code, _) where code == 404 || code == 405 {
            try await uploadAttachmentLegacy(cipherId: cipherId, encryptedFileName: encryptedFileName,
                                             encryptedData: encryptedData, encryptedKey: encryptedKey)
        }
    }

    private func uploadAttachmentV2(cipherId: String, encryptedFileName: String, encryptedData: Data, encryptedKey: String) async throws {
        let body: [String: Any] = [
            "key": encryptedKey,
            "fileName": encryptedFileName,
            "fileSize": encryptedData.count,
            "adminRequest": false,
        ]
        let info: AttachmentUploadResponse = try await post("\(apiBaseURL)/ciphers/\(cipherId)/attachment/v2", body: body)

        switch info.fileUploadType {
        case 1: // Azure blob storage
            guard let urlStr = info.url, let url = URL(string: urlStr) else { throw APIError.invalidResponse }
            var request = URLRequest(url: url)
            request.httpMethod = "PUT"
            request.setValue("BlockBlob", forHTTPHeaderField: "x-ms-blob-type")
            request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
            let (data, response) = try await session.upload(for: request, from: encryptedData)
            try validateResponse(response, data: data)
        default: // 0 = direct upload to this server
            let uploadURL = "\(apiBaseURL)/ciphers/\(cipherId)/attachment/\(info.attachmentId)"
            _ = try await uploadMultipart(url: uploadURL, encryptedFileName: encryptedFileName,
                                          encryptedData: encryptedData, encryptedKey: nil)
        }
    }

    private func uploadAttachmentLegacy(cipherId: String, encryptedFileName: String, encryptedData: Data, encryptedKey: String) async throws {
        let url = "\(apiBaseURL)/ciphers/\(cipherId)/attachment"
        _ = try await uploadMultipart(url: url, encryptedFileName: encryptedFileName,
                                      encryptedData: encryptedData, encryptedKey: encryptedKey)
    }

    private func uploadMultipart(url: String, encryptedFileName: String, encryptedData: Data, encryptedKey: String?) async throws -> Data {
        guard let requestURL = URL(string: url) else { throw APIError.invalidURL }
        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        try await ensureValidToken()
        if let token = accessToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }

        let boundary = "----VaultGuard-\(UUID().uuidString)"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")

        var bodyData = Data()
        func appendString(_ s: String) { bodyData.append(Data(s.utf8)) }

        if let key = encryptedKey {
            appendString("--\(boundary)\r\n")
            appendString("Content-Disposition: form-data; name=\"key\"\r\n\r\n")
            appendString("\(key)\r\n")
        }
        appendString("--\(boundary)\r\n")
        appendString("Content-Disposition: form-data; name=\"data\"; filename=\"\(multipartSafe(encryptedFileName))\"\r\n")
        appendString("Content-Type: application/octet-stream\r\n\r\n")
        bodyData.append(encryptedData)
        appendString("\r\n--\(boundary)--\r\n")

        let (responseData, response) = try await session.upload(for: request, from: bodyData)
        try validateResponse(response, data: responseData)
        return responseData
    }

    /// Encrypted filenames are base64 EncStrings; defensively strip characters that
    /// could break the multipart Content-Disposition header.
    private func multipartSafe(_ s: String) -> String {
        s.replacingOccurrences(of: "\"", with: "")
         .replacingOccurrences(of: "\r", with: "")
         .replacingOccurrences(of: "\n", with: "")
    }

    // MARK: - Folders

    func createFolder(name: String) async throws -> SyncFolder {
        let body = ["name": name]
        return try await postJSON("\(apiBaseURL)/folders", body: body)
    }

    func deleteFolder(id: String) async throws {
        try await delete("\(apiBaseURL)/folders/\(id)")
    }

    func updateFolder(id: String, name: String) async throws -> SyncFolder {
        let body = ["name": name]
        return try await putJSON("\(apiBaseURL)/folders/\(id)", body: body)
    }

    // MARK: - Sends

    func createSend(_ body: SendRequest) async throws -> SendResponse {
        return try await postJSON("\(apiBaseURL)/sends", body: body)
    }

    func getSends() async throws -> [SendResponse] {
        let list: SendListResponse = try await get("\(apiBaseURL)/sends")
        return list.data
    }

    func deleteSend(id: String) async throws {
        try await delete("\(apiBaseURL)/sends/\(id)")
    }

    /// Update an existing Send (edit fields, enable/disable). Type cannot change.
    func updateSend(id: String, _ body: SendRequest) async throws -> SendResponse {
        return try await putJSON("\(apiBaseURL)/sends/\(id)", body: body)
    }

    /// Step 1 of a file Send: create the Send + get upload target.
    func createFileSend(_ body: SendFileCreateRequest) async throws -> SendFileUploadResponse {
        return try await postJSON("\(apiBaseURL)/sends/file/v2", body: body)
    }

    /// Step 2 of a file Send: upload the encrypted bytes as the sole `data` part. The part's
    /// filename MUST be the full encrypted file name — Vaultwarden rejects a mismatch.
    func uploadSendFile(sendId: String, fileId: String, encryptedFileName: String, encryptedData: Data) async throws {
        guard let requestURL = URL(string: "\(apiBaseURL)/sends/\(sendId)/file/\(fileId)") else { throw APIError.invalidURL }
        try await ensureValidToken()
        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        let boundary = "----VaultGuard\(UUID().uuidString)"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        if let token = accessToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        var body = Data()
        body.append(Data("--\(boundary)\r\n".utf8))
        body.append(Data("Content-Disposition: form-data; name=\"data\"; filename=\"\(encryptedFileName)\"\r\n".utf8))
        body.append(Data("Content-Type: application/octet-stream\r\n\r\n".utf8))
        body.append(encryptedData)
        body.append(Data("\r\n--\(boundary)--\r\n".utf8))
        request.httpBody = body
        let (data, response) = try await session.data(for: request)
        try validateResponse(response, data: data)
    }

    /// Web-vault root for building Send share links. Self-hosted: server root (apiBaseURL minus
    /// "/api"). Public cloud: the vault domain.
    func sendShareBaseURL() -> String {
        if apiBaseURL.hasSuffix("/api") { return String(apiBaseURL.dropLast(4)) }
        if apiBaseURL == "https://api.bitwarden.com" { return "https://vault.bitwarden.com" }
        if apiBaseURL == "https://api.bitwarden.eu" { return "https://vault.bitwarden.eu" }
        return apiBaseURL
    }

    // MARK: - Private Helpers

    private func ensureValidToken() async throws {
        if let expiry = tokenExpiry, Date() > expiry.addingTimeInterval(-60) {
            _ = try await refreshAccessToken()
        }
    }

    private func get<T: Decodable>(_ url: String) async throws -> T {
        guard let requestURL = URL(string: url) else { throw APIError.invalidURL }
        var request = URLRequest(url: requestURL)
        request.httpMethod = "GET"
        try await ensureValidToken()
        if let token = accessToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        let (data, response) = try await session.data(for: request)
        try validateResponse(response, data: data)
        return try decoder.decode(T.self, from: data)
    }

    private func getData(_ url: String) async throws -> Data {
        guard let requestURL = URL(string: url) else { throw APIError.invalidURL }
        var request = URLRequest(url: requestURL)
        request.httpMethod = "GET"
        try await ensureValidToken()
        if let token = accessToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        let (data, response) = try await session.data(for: request)
        try validateResponse(response, data: data)
        return data
    }

    private func postExpectingNoContent(_ url: String, body: [String: Any], auth: Bool = true) async throws {
        guard let requestURL = URL(string: url) else { throw APIError.invalidURL }
        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if auth {
            try await ensureValidToken()
            if let token = accessToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: request)
        try validateResponse(response, data: data)
    }

    private func post<T: Decodable>(_ url: String, body: [String: Any], auth: Bool = true) async throws -> T {
        guard let requestURL = URL(string: url) else { throw APIError.invalidURL }
        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if auth {
            try await ensureValidToken()
            if let token = accessToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: request)
        try validateResponse(response, data: data)
        return try decoder.decode(T.self, from: data)
    }

    private func postForm<T: Decodable>(_ url: String, params: [String: String]) async throws -> T {
        guard let requestURL = URL(string: url) else { throw APIError.invalidURL }
        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        var formAllowed = CharacterSet.alphanumerics; formAllowed.insert(charactersIn: "-._~")
        let body = params.map {
            "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: formAllowed) ?? $0.value)"
        }.joined(separator: "&")
        request.httpBody = body.data(using: .utf8)
        let (data, response) = try await session.data(for: request)
        try validateResponse(response, data: data)
        return try decoder.decode(T.self, from: data)
    }

    private func postJSON<T: Decodable, B: Encodable>(_ url: String, body: B) async throws -> T {
        guard let requestURL = URL(string: url) else { throw APIError.invalidURL }
        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        try await ensureValidToken()
        if let token = accessToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        request.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await session.data(for: request)
        try validateResponse(response, data: data)
        return try decoder.decode(T.self, from: data)
    }

    private func putJSON<T: Decodable, B: Encodable>(_ url: String, body: B) async throws -> T {
        guard let requestURL = URL(string: url) else { throw APIError.invalidURL }
        var request = URLRequest(url: requestURL)
        request.httpMethod = "PUT"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        try await ensureValidToken()
        if let token = accessToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        request.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await session.data(for: request)
        try validateResponse(response, data: data)
        return try decoder.decode(T.self, from: data)
    }

    private func delete(_ url: String) async throws {
        guard let requestURL = URL(string: url) else { throw APIError.invalidURL }
        var request = URLRequest(url: requestURL)
        request.httpMethod = "DELETE"
        try await ensureValidToken()
        if let token = accessToken { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        let (data, response) = try await session.data(for: request)
        if let http = response as? HTTPURLResponse, http.statusCode >= 400 {
            try validateResponse(response, data: data)
        }
    }

    private func validateResponse(_ response: URLResponse, data: Data) throws {
        guard let http = response as? HTTPURLResponse else { throw APIError.invalidResponse }
        if http.statusCode >= 400 {
            // Keep only a bounded slice of the body: enough for OAuth/2FA control-flow
            // detection, but never dumping a large or sensitive payload into the error
            // (which could end up in logs). User-facing text is built in errorDescription.
            let raw = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw APIError.serverError(http.statusCode, String(raw.prefix(1000)))
        }
    }

    private func deviceIdentifier() -> String {
        let keychain = KeychainService.shared
        if let saved = keychain.deviceIdentifier { return saved }
        let id = UUID().uuidString; keychain.deviceIdentifier = id; return id
    }
}

// MARK: - Attachment Download Response

struct AttachmentDownloadResponse: Codable {
    let url: String?; let fileName: String?

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        url = (try? c.decode(String.self, forKey: FlexKey("Url"))) ?? (try? c.decode(String.self, forKey: FlexKey("url")))
        fileName = (try? c.decode(String.self, forKey: FlexKey("FileName"))) ?? (try? c.decode(String.self, forKey: FlexKey("fileName")))
    }
}

// MARK: - Attachment Upload (v2) Response

struct AttachmentUploadResponse: Decodable {
    let attachmentId: String
    let url: String?
    let fileUploadType: Int
    let cipherResponse: SyncCipher?

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: FlexKey.self)
        attachmentId = c.flexString("attachmentId") ?? c.flexString("id") ?? ""
        url = c.flexString("url")
        fileUploadType = c.flexInt("fileUploadType") ?? 0
        cipherResponse = c.flex(SyncCipher.self, "cipherResponse")
    }
}

// MARK: - Errors

enum APIError: LocalizedError {
    case invalidResponse
    case serverError(Int, String)
    case twoFactorRequired(providers: [Int])
    case noRefreshToken
    case notImplemented
    case invalidURL

    var errorDescription: String? {
        switch self {
        case .invalidResponse: return "No response from server"
        case .twoFactorRequired: return "Two-factor authentication required"
        case .serverError(let code, let msg):
            if code == 400 {
                if msg.contains("invalid_grant") || msg.contains("Username or password is incorrect") {
                    return "Invalid email or master password"
                }
                if msg.contains("TwoFactor") { return "Two-factor authentication required" }
                if let parsed = Self.parseErrorMessage(msg) { return parsed }
                return "Invalid credentials"
            }
            if code == 401 { return "Session expired. Please log in again." }
            if code == 403 { return "Access denied" }
            if code == 404 { return "Not found. Check server address." }
            if code == 429 { return "Too many attempts. Please wait." }
            if code >= 500 { return "Server error. Try again later." }
            if let parsed = Self.parseErrorMessage(msg) { return parsed }
            return "Connection error (\(code))"
        case .noRefreshToken: return "Session expired. Please log in again."
        case .notImplemented: return "Feature not yet supported"
        case .invalidURL: return "Invalid server URL"
        }
    }

    private static func parseErrorMessage(_ raw: String) -> String? {
        guard let data = raw.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        // OAuth-style error from identity/connect/token
        if let desc = json["error_description"] as? String, !desc.isEmpty { return desc }
        // Top-level message variants
        for key in ["message", "Message"] {
            if let msg = json[key] as? String, !msg.isEmpty { return msg }
        }
        // Nested ErrorModel / errorModel (Bitwarden uses capitalized keys)
        for key in ["ErrorModel", "errorModel"] {
            if let model = json[key] as? [String: Any] {
                for mk in ["Message", "message"] {
                    if let msg = model[mk] as? String, !msg.isEmpty { return msg }
                }
            }
        }
        return nil
    }

    /// True if a 400 body is a "two-factor required" challenge rather than a credential error.
    static func isTwoFactorBody(_ raw: String) -> Bool {
        raw.contains("TwoFactorProviders") || raw.contains("twoFactorProviders")
            || raw.contains("Two factor required") || raw.contains("TwoFactor required")
    }

    /// Provider ids offered by the server (Bitwarden TwoFactorProvider enum).
    static func parseTwoFactorProviders(_ raw: String) -> [Int] {
        guard let data = raw.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }
        for key in ["TwoFactorProviders2", "twoFactorProviders2"] {
            if let map = json[key] as? [String: Any] {
                let ids = map.keys.compactMap { Int($0) }
                if !ids.isEmpty { return ids.sorted() }
            }
        }
        for key in ["TwoFactorProviders", "twoFactorProviders"] {
            if let arr = json[key] as? [Any] {
                let ids = arr.compactMap { ($0 as? Int) ?? Int("\($0)") }
                if !ids.isEmpty { return ids.sorted() }
            }
        }
        return []
    }
}
