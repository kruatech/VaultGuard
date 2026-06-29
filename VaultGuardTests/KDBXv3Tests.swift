import XCTest
import Foundation
import CryptoKit

/// KDBX 3.1 read path: AES-KDF (header rounds), StreamStartBytes verification, SHA-256
/// hashed-block payload, Salsa20 inner stream. Fixture is a real 3.1 file (cross-checked by
/// pykeepass reading it back).
final class KDBXv3Tests: XCTestCase {

    private let fixtureB64 =
        "A9mimmf7S7UBAAMAAhAAMcHy5r9xQ1C+WAUhavxa/wMEAAEAAAAEIADcwFCL7ZePwAJ5M8ORkVc5CyEjK6rykG2TOp/pnZLKGAUg" +
        "ADUdzapgAY6UzVggfLzGedQ0oYfxTiBTSHwX7L1ega8ABggAcBcAAAAAAAAHEADHK5U4GEc1ekUpnLe/aYsCCCAAAPXiT+u0igSl" +
        "qH2981jjKDHO9xJ75umAW/21UBr45zgJIAD87Cg6hDAP7aTxDSr24JUxm2TMnOKlgoUjSC3FwNs9wQoEAAIAAAAABAANCg0KUnbh" +
        "KfqTNSoTONsSaKmd8CDRwTysXunCDmvX24g2pB86gHgOkccjXMC85G29hmJU0CMnzyx7S8tGH8T42tu7mqVsx8DLYQrMFGDTKsyW" +
        "WhWMdL5SnT0N76QLsdiDwNaeRCrcSKXoNCKgBFwnc1jEVS8IK/U1F2F+i87tb6hArtSZiQq2zyBDTtwsy5+AerBihTW2+HygBhEN" +
        "+6RkYFyHUAowInQ+hnAXIhR+Ea8NXgWTr48gItQ8qH7Tv1bJZUTW3hEMuicQ6H2ChHJnntYiUPVSNzPOfpFPvJopo9dXxCM7CJ/k" +
        "fuFqOZIKfoUdECOZD9V+reuEkjQ7xv4QmIdrWRTbYr4Xjmx0SooaIxXEezO4bV5vmiiSrJf3nOi1sR/QMp6mlbYAa6kffgSUb5W0" +
        "L00X5uJmAA1P9Z9SUdK2pGxXXzd6HnnrqZFkm+4Wn9OhzNYD0t5XxEgeNkuG7Z3cN01G/MhwehseBi6v8RvtCPLUV6tqeRcR9zBC" +
        "yoITf18MbdjS+UYHNgETVGiP20Bi+gr1HcVwqCtCNCWsmwqKzsFNuNdhBg8daHcURIIdUvAQDP1Fl8Aj9oSY7mlFakwBB4uE2e6T" +
        "1M0ADYZzKS2vdXZvAKpsbQWOJ0wgrVOsjB3vP1khFO6lLhsu+96mMZHDaz66bP0wA9GNcnqUC5tCrR26BSNSoS1J4U3YiX6sgKi+" +
        "QXysXva4BCCdaY7mWp4MwmTl7Gby8iCpM3uNmGMI94yoxrfI7bIdHoBs5uMsr134jcd5Omdhz2GUijRPD0rmiMkD82MIZHhT95JT" +
        "rwMfDnPro49yws3yqQyE/uFbCOfWtMnUiJECHeF/XJNzT0lYS63gbbNiyXOm62YFw8m4tF6Rr8hnXNnmd0rRaXVGk0VXJfNHp4na" +
        "hVHS38NPtiwogAAztI5cqs9eJ9VEMqQD429EHCLrc7lRZj6xBUU0Hf9i9SDBsZy+VmRH4yiOymXlE51t8mU91gsv1HGJRcjBRIEv" +
        "ppxQbPxv2r7/TXMjlSaeVweZ0FYbch96oJDj8B2uxLAmgY0TTn/TEZm7oy7o0Wsj/x88xa9/nV9sx2QQd5FSGeKFuAiEiIDpolhd" +
        "Le0It5HiywWIWC656Gbwudz5+E9D2MWLRSsHKdg5foUG6CWz0ej7wLuOXG8zE833JYdBdRk0EDNY6MCBBH0nkLKQDhg5eRZwNRMj" +
        "iSWtoxeGN7jKkZ5af3TNmYKEa3pfZ8WYSxwyJ3OJpvTbVUgB7OhNWn8c9Z5pXBlzXG5H+JKVTRwcdHMs7fkuvUCw95fU1tEHG1xw" +
        "MZ6Knf3tQGtTqXG3EJzkLEg2go7HKMhEMFRiCaNBfOH7BCbhOfUg8uUGnobHXIqFNT/a7xcIM1AdmqsFm+3/xyMw+UbnkLM36g4A" +
        "I0VUJBeb/jwPCxXjyRI1gOX9AClk+E5/WGlTevH3DkfVK5i1TcsxEy4YEQl+XUnLkW9xtmz8c9tUpaMyRPE9tVUfz73lbUyafiwm" +
        "RFl2D2lyQzg="

    private var fixture: Data { Data(base64Encoded: fixtureB64)! }
    private func sha256Hex(_ d: Data) -> String { Data(SHA256.hash(data: d)).map { String(format: "%02x", $0) }.joined() }

    func testUnlockV3() throws {
        let db = try KDBXReader.unlock(data: fixture, password: "v3pass")
        XCTAssertEqual(db.innerStreamID, 2)            // Salsa20
        XCTAssertEqual(sha256Hex(db.xml),
                       "4bcec58011fd132cc1a7e9ff89856de1a9e9d1494679979e6ffecf32e419497e")
        let stream = try XCTUnwrap(KDBXProtectedStream(streamID: db.innerStreamID, key: db.innerStreamKey))
        XCTAssertEqual(stream.decrypt("BjJG7RMj0w=="), "secretA")
        XCTAssertEqual(stream.decrypt("iJSes0p8tw=="), "secretB")
    }

    func testV3WrongPassword() {
        XCTAssertThrowsError(try KDBXReader.unlock(data: fixture, password: "nope")) { error in
            guard case KDBXError.wrongCredentials = error else {
                return XCTFail("expected wrongCredentials, got \(error)")
            }
        }
    }

    func testV3Mapping() throws {
        let db = try KDBXReader.unlock(data: fixture, password: "v3pass")
        let stream = try XCTUnwrap(KDBXProtectedStream(streamID: db.innerStreamID, key: db.innerStreamKey))
        let vault = KDBXVaultMapper.map(xml: db.xml, stream: stream)

        XCTAssertEqual(vault.folders.first?.name, "Sites")
        let mail = try XCTUnwrap(vault.ciphers.first { $0.name == "Mail" })
        XCTAssertEqual(mail.login?.username, "carol")
        XCTAssertEqual(mail.login?.password, "secretA")
        XCTAssertEqual(mail.login?.uris?.first?.uri, "https://mail.x")
        XCTAssertEqual(mail.folderId, vault.folders.first?.id)

        let wifi = try XCTUnwrap(vault.ciphers.first { $0.name == "WiFi" })
        XCTAssertEqual(wifi.login?.password, "secretB")
        XCTAssertNil(wifi.folderId)
    }
}
