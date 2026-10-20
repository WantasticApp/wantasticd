import Foundation

public struct ConsoleLogin: Sendable {
    public let baseURL: URL

    public init(baseURL: URL) throws {
        guard let scheme = baseURL.scheme?.lowercased(), scheme == "https",
              baseURL.host != nil else {
            throw WantasticError.invalidConsoleURL
        }
        self.baseURL = baseURL
    }

}

/// Web content shown inside the desktop client must use TLS and cannot embed
/// credentials in the URL. This allows ordinary HTTPS sign-in redirects while
/// excluding script URLs, local files, and cleartext content.
public enum SecureWebNavigationPolicy {
    public static func allows(_ url: URL?) -> Bool {
        guard let url,
              url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty,
              url.user == nil, url.password == nil else { return false }
        return true
    }
}
