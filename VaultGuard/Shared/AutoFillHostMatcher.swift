import Foundation

/// Decides whether a stored credential belongs to the site asking for it.
///
/// Standalone rather than a member of `AutoFillVault`: that type lives in the extension and
/// pulls in the keychain and the cache, while this is a pure string comparison. Splitting it
/// out lets the unit-test target compile it alone — and of everything in the AutoFill path,
/// this is what most needs tests. Getting it wrong does not produce an error message; it
/// produces the user's password typed into somebody else's login form.
enum AutoFillHostMatcher {

    /// Normalized host from a full URL or a bare-host identifier; nil if unparseable.
    ///
    /// Only http(s) and bare hosts have a host in the sense this matcher uses. A non-web
    /// scheme (`androidapp://com.example.app`, `iosapp://`, `file://`) used to be treated as a
    /// bare host and got "https://" glued in front of it, which yielded the scheme itself as
    /// the host — so every `androidapp://` entry shared the host "androidapp" and unrelated
    /// apps matched each other. Such identifiers fail closed instead.
    static func host(from identifier: String) -> String? {
        var s = identifier.trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty else { return nil }
        let lower = s.lowercased()
        if let sep = lower.range(of: "://") {
            let scheme = lower[lower.startIndex..<sep.lowerBound]
            let looksLikeScheme = !scheme.isEmpty && scheme.allSatisfy {
                $0.isLetter || $0.isNumber || $0 == "+" || $0 == "-" || $0 == "."
            }
            if looksLikeScheme {
                guard scheme == "http" || scheme == "https" else { return nil }
            } else {
                s = "https://" + s
            }
        } else {
            s = "https://" + s
        }
        guard let host = URL(string: s)?.host else { return nil }
        return normalizeHost(host)
    }

    static func normalizeHost(_ host: String) -> String {
        var h = host.lowercased()
        while h.hasSuffix(".") { h.removeLast() }
        return h
    }

    /// Exact host match, or one host is a subdomain of the other on a label boundary.
    ///
    /// The label boundary is the whole point. A plain `hasSuffix` would accept
    /// `evil-example.com` for `example.com`, because the stored host is a suffix of the
    /// requested one as raw text. Requiring the dot means only a real subdomain matches.
    static func hostMatches(credentialHost: String, requestHost: String) -> Bool {
        if credentialHost == requestHost { return true }
        if requestHost.hasSuffix("." + credentialHost) { return true }
        if credentialHost.hasSuffix("." + requestHost) { return true }
        return false
    }
}
