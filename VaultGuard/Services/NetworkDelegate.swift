import Foundation
import CryptoKit
import Security

/// Trust policy for self-signed servers.
///
/// Replaces the old "trust any certificate for this host" behaviour with explicit
/// SHA-256 fingerprint pinning:
/// - a system-valid certificate is always accepted (no pinning needed);
/// - a self-signed certificate is accepted ONLY if its leaf fingerprint matches the one
///   the user explicitly trusted for that host;
/// - anything else fails closed. The seen fingerprint is recorded so the UI can show it
///   and ask the user to confirm (first connection) or warn that it changed.
final class CertTrustStore: @unchecked Sendable {
    static let shared = CertTrustStore()

    private let defaults = UserDefaults.standard
    private let pinnedKey = "trustedCertFingerprints"   // [host: sha256hex]
    private let lock = NSLock()
    private var lastSeen: [String: String] = [:]        // in-memory only: host -> sha256hex

    private func pinnedMap() -> [String: String] {
        (defaults.dictionary(forKey: pinnedKey) as? [String: String]) ?? [:]
    }
    private func writePinned(_ map: [String: String]) {
        defaults.set(map, forKey: pinnedKey)
    }

    /// The fingerprint the user trusted for `host`, if any.
    func pinnedFingerprint(host: String) -> String? { pinnedMap()[host.lowercased()] }

    func pin(host: String, fingerprint: String) {
        var m = pinnedMap(); m[host.lowercased()] = fingerprint; writePinned(m)
    }
    func unpin(host: String) {
        var m = pinnedMap(); m.removeValue(forKey: host.lowercased()); writePinned(m)
    }
    /// All trusted (host, fingerprint) pairs, for display/management in Settings.
    func allPinned() -> [(host: String, fingerprint: String)] {
        pinnedMap().map { (host: $0.key, fingerprint: $0.value) }.sorted { $0.host < $1.host }
    }

    /// Last untrusted fingerprint the delegate saw for `host` (set on a rejected handshake).
    func seenFingerprint(host: String) -> String? {
        lock.lock(); defer { lock.unlock() }; return lastSeen[host.lowercased()]
    }
    func recordSeen(host: String, fingerprint: String) {
        lock.lock(); lastSeen[host.lowercased()] = fingerprint; lock.unlock()
    }
    func clearSeen(host: String) {
        lock.lock(); lastSeen.removeValue(forKey: host.lowercased()); lock.unlock()
    }

    /// SHA-256 of a certificate's DER bytes, formatted as uppercase colon-separated hex.
    static func fingerprint(of certificate: SecCertificate) -> String {
        let der = SecCertificateCopyData(certificate) as Data
        return SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":")
    }
}

/// URLSession delegate enforcing the policy above for the configured self-signed host(s).
final class PinnedCertDelegate: NSObject, URLSessionDelegate {
    private let trustedHosts: Set<String>
    private let store: CertTrustStore

    init(trustedHosts: Set<String>, store: CertTrustStore = .shared) {
        self.trustedHosts = Set(trustedHosts.map { $0.lowercased() })
        self.store = store
        super.init()
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        let host = challenge.protectionSpace.host.lowercased()

        // 1) System-valid certificate: accept via the default handling, no pinning involved.
        var error: CFError?
        if SecTrustEvaluateWithError(serverTrust, &error) {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // 2) Untrusted (self-signed). Only this session's configured host may be pinned.
        guard trustedHosts.contains(host), let leaf = leafCertificate(serverTrust) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        let fingerprint = CertTrustStore.fingerprint(of: leaf)

        // 3) Matches the user-trusted fingerprint → accept.
        if store.pinnedFingerprint(host: host) == fingerprint {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
            return
        }

        // 4) Unknown or changed fingerprint → record for the UI and fail closed.
        store.recordSeen(host: host, fingerprint: fingerprint)
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    private func leafCertificate(_ trust: SecTrust) -> SecCertificate? {
        (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first
    }
}
