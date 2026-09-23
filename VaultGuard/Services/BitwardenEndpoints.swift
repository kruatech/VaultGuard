import Foundation

/// Maps a server URL to the API and identity base URLs to talk to.
///
/// Deliberately standalone rather than a member of `APIService`: this is a pure string
/// transform with no dependencies, while `APIService` pulls in the keychain, the account
/// manager and the URLSession stack. Keeping it separate lets the unit-test target compile it
/// on its own — and `resolveEndpoints` is exactly the kind of table that wants tests, since a
/// mistake there sends credentials to the wrong host.
enum BitwardenEndpoints {

    /// Bitwarden cloud regions, keyed by every host that reaches them. Adding a region or an
    /// alias is a table entry rather than a new branch.
    static let knownCloudHosts: [String: (api: String, identity: String)] = {
        var map: [String: (api: String, identity: String)] = [:]
        // (region domain, hosts that resolve to it)
        let regions: [(domain: String, hosts: [String])] = [
            ("bitwarden.com", ["bitwarden.com", "www.bitwarden.com", "vault.bitwarden.com"]),
            ("bitwarden.eu",  ["bitwarden.eu",  "www.bitwarden.eu",  "vault.bitwarden.eu"]),
        ]
        for region in regions {
            let endpoints = ("https://api.\(region.domain)", "https://identity.\(region.domain)")
            for host in region.hosts { map[host] = endpoints }
        }
        return map
    }()

    /// Known Bitwarden cloud hosts use dedicated subdomains; everything else (self-hosted
    /// Bitwarden / Vaultwarden) is served under one host at `/api` and `/identity`.
    ///
    /// The lookup is on the parsed host, never on a substring of the URL: `bitwarden.com.evil`
    /// must not be handed the real Bitwarden endpoints.
    static func resolve(for serverURL: String) -> (api: String, identity: String) {
        let host = (URL(string: serverURL)?.host
            ?? serverURL.replacingOccurrences(of: "https://", with: "")
                        .replacingOccurrences(of: "http://", with: "")
                        .components(separatedBy: "/").first
            ?? "").lowercased()

        if let cloud = knownCloudHosts[host] { return cloud }
        return ("\(serverURL)/api", "\(serverURL)/identity")
    }
}
