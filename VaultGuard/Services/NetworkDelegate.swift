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
    private let seenKey = "lastSeenCertFingerprints"    // [host: sha256hex]

    /// nil when a value is stored that is not a `[String: String]`.
    ///
    /// The distinction matters because every mutation here is read-modify-write. Collapsing
    /// an unreadable map into an empty one meant that trusting a new host would drop every
    /// certificate the user had already approved — they would be asked to re-approve servers
    /// they had, which is exactly the prompt a person learns to click through.
    private func pinnedMapOrNil() -> [String: String]? {
        guard let stored = defaults.object(forKey: pinnedKey) else { return [:] }  // nothing yet
        return stored as? [String: String]
    }

    private func pinnedMap() -> [String: String] { pinnedMapOrNil() ?? [:] }

    private func writePinned(_ map: [String: String]) {
        defaults.set(map, forKey: pinnedKey)
    }

    /// The fingerprint the user trusted for `host`, if any.
    func pinnedFingerprint(host: String) -> String? { pinnedMap()[host.lowercased()] }

    func pin(host: String, fingerprint: String) {
        guard var m = pinnedMapOrNil() else {
            Log.fault("pin skipped: the trusted-certificate map could not be read")
            return
        }
        m[host.lowercased()] = fingerprint
        writePinned(m)
    }

    func unpin(host: String) {
        guard var m = pinnedMapOrNil() else {
            Log.fault("unpin skipped: the trusted-certificate map could not be read")
            return
        }
        m.removeValue(forKey: host.lowercased())
        writePinned(m)
    }
    /// All trusted (host, fingerprint) pairs, for display/management in Settings.
    func allPinned() -> [(host: String, fingerprint: String)] {
        pinnedMap().map { (host: $0.key, fingerprint: $0.value) }.sorted { $0.host < $1.host }
    }

    /// Same read-modify-write hazard as the pinned map, with less at stake: losing a seen
    /// fingerprint only means the trust prompt has to be triggered again by a fresh handshake.
    private func seenMapOrNil() -> [String: String]? {
        guard let stored = defaults.object(forKey: seenKey) else { return [:] }
        return stored as? [String: String]
    }

    private func seenMap() -> [String: String] { seenMapOrNil() ?? [:] }

    /// Last untrusted fingerprint the delegate saw for `host` (set on a rejected handshake).
    ///
    /// Persisted, not in-memory: the fingerprint is recorded during the handshake that the
    /// delegate then rejects, and the UI reads it afterwards to ask the user whether to trust
    /// the certificate. Keeping it in memory meant that after a relaunch the first handshake
    /// failed, the app restarted before the user answered, and the prompt could never be shown
    /// again — the host became unreachable with no way to trust it. A leaf certificate
    /// fingerprint is public data, so UserDefaults is the same storage the pinned map uses.
    func seenFingerprint(host: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        return seenMap()[host.lowercased()]
    }
    func recordSeen(host: String, fingerprint: String) {
        lock.lock(); defer { lock.unlock() }
        guard var m = seenMapOrNil() else { return }
        m[host.lowercased()] = fingerprint
        defaults.set(m, forKey: seenKey)
    }
    func clearSeen(host: String) {
        lock.lock(); defer { lock.unlock() }
        guard var m = seenMapOrNil() else { return }
        m.removeValue(forKey: host.lowercased())
        defaults.set(m, forKey: seenKey)
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
