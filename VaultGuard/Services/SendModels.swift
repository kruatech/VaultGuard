import Foundation

/// Empty JSON body (`{}`) for endpoints that take no payload (e.g. remove-password).
struct EmptyBody: Encodable {}

/// Text payload of a Send (`text` is an EncString; `hidden` hides it behind a click on access).
struct SendTextRequest: Encodable {
    let text: String?
    let hidden: Bool
}

/// Body for `POST /api/sends`. All user content (`name`, `notes`, `text.text`) is already
/// encrypted (EncStrings); `key` is the 16-byte send key encrypted under the user key. Dates are
/// ISO-8601 strings. `type`: 0 = text, 1 = file (file unsupported here yet).
struct SendRequest: Encodable {
    let type: Int
    let name: String
    let notes: String?
    let key: String
    let maxAccessCount: Int?
    let expirationDate: String?
    let deletionDate: String
    let password: String?
    let disabled: Bool
    let hideEmail: Bool
    let text: SendTextRequest?
}

/// Server representation of a Send (encrypted fields stay encrypted until decrypted client-side).
struct SendResponse: Decodable {
    let id: String?
    let accessId: String?
    let accessUrl: String?
    let key: String?
    let name: String?
    let type: Int?
    let notes: String?
    let file: SendFileInfo?
    let text: SendTextInfo?
    let hideEmail: Bool?
    let maxAccessCount: Int?
    let accessCount: Int?
    let expirationDate: String?
    let deletionDate: String?
    let disabled: Bool?
    let revisionDate: String?
}

/// `GET /api/sends` returns a list wrapper.
struct SendListResponse: Decodable {
    let data: [SendResponse]
}

/// File sub-object inside a Send create body (v2): the encrypted file name.
struct SendFileMeta: Encodable {
    let fileName: String
}

/// Body for `POST /api/sends/file/v2` (step 1 of the two-step file upload). `fileLength` is the
/// size of the *encrypted* buffer; `file.fileName` is the encrypted file name.
struct SendFileCreateRequest: Encodable {
    let type: Int
    let name: String
    let notes: String?
    let key: String
    let fileLength: Int
    let file: SendFileMeta
    let maxAccessCount: Int?
    let expirationDate: String?
    let deletionDate: String
    let password: String?
    let disabled: Bool
    let hideEmail: Bool
}

/// File info inside a SendResponse (carries the server-assigned file `id` needed for upload).
struct SendFileInfo: Decodable {
    let id: String?
    let fileName: String?
    let size: String?
    let sizeName: String?
}

/// Text payload inside a SendResponse (encrypted text + hidden flag).
struct SendTextInfo: Decodable {
    let text: String?
    let hidden: Bool?
}

/// Response to `POST /api/sends/file/v2` (step 1): where/how to upload + the created Send.
struct SendFileUploadResponse: Decodable {
    let url: String?
    let fileUploadType: Int?
    let sendResponse: SendResponse
}

/// Decrypted, display-ready summary used by the Sends screen.
struct SendSummary: Identifiable {
    let id: String
    let accessId: String
    let name: String
    let shareURL: String
    let deletionDate: String?
    let accessCount: Int
    let maxAccessCount: Int?
    let disabled: Bool
    // Edit context (re-derive the crypto key from `encryptedKey` to re-encrypt on update):
    let type: Int            // 0 = text, 1 = file
    let encryptedKey: String // the send `key` field (send key under user key), reused on PUT
    let hideEmail: Bool
    let text: String?        // decrypted text (text sends), for the edit form
    let hidden: Bool         // text "hidden" flag
    let notes: String?       // decrypted private note (creator-only), for the edit form
    let sizeName: String?    // server-formatted file size (file sends), e.g. "1.28 MB"
    let expirationDate: String? // when the link stops working (distinct from deletionDate)
}
