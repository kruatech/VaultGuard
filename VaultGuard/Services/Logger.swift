import Foundation
import os

/// Lightweight logging facade.
///
/// Rules:
/// - Messages are *static, non-sensitive* strings. Never pass secrets, key material,
///   plaintext vault contents, tokens, or raw error objects that may embed them.
/// - In Release builds the debug channels (`crypto`/`network`/`app`) compile to no-ops,
///   so nothing reaches the unified log in production.
/// - `privacy: .public` is intentional and SAFE here precisely because of the rule above:
///   only fixed literal strings are ever logged, and only in DEBUG. It is NOT a license to
///   pass dynamic/sensitive values — those must never reach these calls. The interpolated
///   value is redacted to `<private>` by default, and we opt out only for these constants
///   so DEBUG logs remain human-readable.
enum Log {
    private static let cryptoLogger = os.Logger(subsystem: subsystem, category: "crypto")
    private static let networkLogger = os.Logger(subsystem: subsystem, category: "network")
    private static let appLogger = os.Logger(subsystem: subsystem, category: "app")
    private static let faultLogger = os.Logger(subsystem: subsystem, category: "fault")

    private static var subsystem: String {
        Bundle.main.bundleIdentifier ?? "com.kruatech.vaultguard"
    }

    static func crypto(_ message: String) {
        #if DEBUG
        cryptoLogger.debug("\(message, privacy: .public)")
        #endif
    }

    static func network(_ message: String) {
        #if DEBUG
        networkLogger.debug("\(message, privacy: .public)")
        #endif
    }

    static func app(_ message: String) {
        #if DEBUG
        appLogger.debug("\(message, privacy: .public)")
        #endif
    }

    /// Always-on (Release included) channel for non-sensitive operational failures, e.g. a
    /// Keychain status code. NEVER pass secrets, key material, tokens, or values here.
    static func fault(_ message: String) {
        faultLogger.error("\(message, privacy: .public)")
    }
}
