import Darwin
import Foundation

/// Builds a handler URL only for a service explicitly discovered on a literal
/// IP. This avoids shell interpolation, hostname lookups, and credential leaks.
public enum ServiceActionURL {
    public static func make(address: String, service: NetworkService) -> URL? {
        guard service.isOpen, (1...65_535).contains(service.port), isIPAddress(address) else { return nil }

        let scheme: String
        switch service.kind {
        case .web:
            guard ServiceClassifier.kind(for: service.port) == .web else { return nil }
            scheme = [443, 8443].contains(service.port) ? "https" : "http"
        case .remoteDesktop:
            guard ServiceClassifier.kind(for: service.port) == .remoteDesktop else { return nil }
            scheme = "rdp"
        case .secureShell:
            guard ServiceClassifier.kind(for: service.port) == .secureShell else { return nil }
            scheme = "ssh"
        case .other:
            return nil
        }

        let host = address.contains(":") ? "[\(address)]" : address
        if service.kind == .remoteDesktop {
            // Microsoft's macOS Remote Desktop handler accepts an RDP
            // attribute query, not the generic rdp://host:port authority form.
            // Escape the attribute's colons so Foundation accepts the URL;
            // the RDP client decodes the URI attribute value on dispatch.
            return URL(string: "rdp://full%20address=s%3A\(host)%3A\(service.port)")
        }
        let path = scheme == "http" || scheme == "https" ? "/" : ""
        return URL(string: "\(scheme)://\(host):\(service.port)\(path)")
    }

    private static func isIPAddress(_ value: String) -> Bool {
        var ipv4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 { return true }
        var ipv6 = in6_addr()
        return value.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1
    }
}
