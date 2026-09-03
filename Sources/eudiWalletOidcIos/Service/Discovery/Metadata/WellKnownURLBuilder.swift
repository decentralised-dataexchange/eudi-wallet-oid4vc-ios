//
//  WellKnownURLBuilder.swift
//  eudiWalletOidcIos
//

import Foundation

/// Which of the two well-known URL layouts produced a document.
public enum WellKnownForm {
    /// The spec form: the well-known string inserted between the host and the path
    /// (OpenID4VCI 1.0 section 12.2.2, RFC 8414 section 3).
    case insertion
    /// The non-spec form: the well-known string appended to the identifier.
    case suffix
}

/// Turns an issuer or authorization server identifier into the URLs its metadata might live at.
///
/// Section 12.2.2 defines exactly one form: the well-known string is **inserted between the host
/// component and the path component**, so `https://issuer.example.com/tenant` publishes at
/// `https://issuer.example.com/.well-known/openid-credential-issuer/tenant`. RFC 8414 section 3
/// says the same for authorization server metadata.
///
/// The suffix form -- appending the well-known string -- is **not** in either specification, but a
/// large share of deployed issuers serve only that, so it is kept as a fallback behind
/// ``DiscoveryPolicy/allowSuffixWellKnownFallback``.
enum WellKnownURLBuilder {

    static let openIdCredentialIssuer = ".well-known/openid-credential-issuer"
    static let oauthAuthorizationServer = ".well-known/oauth-authorization-server"
    static let openIdConfiguration = ".well-known/openid-configuration"

    private static let knownSuffixes = [
        openIdCredentialIssuer, oauthAuthorizationServer, openIdConfiguration,
    ]

    /// The bare identifier behind `input`, with any well-known segment and trailing slash removed.
    ///
    /// Callers pass a full well-known URL as often as a bare identifier. Removing the segment with
    /// its leading slash normalises both layouts, because the segment sits in the middle of the
    /// insertion form and at the end of the suffix form.
    static func identifier(from input: String?) -> String? {
        guard var value = input?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
            return nil
        }
        for suffix in knownSuffixes {
            value = value.replacingOccurrences(of: "/\(suffix)", with: "")
        }
        while value.hasSuffix("/") { value.removeLast() }
        return value.isEmpty ? nil : value
    }

    /// The scheme of `identifier`, or `nil` when it is not a parseable absolute URL.
    static func scheme(of identifier: String?) -> String? {
        guard let identifier, let components = URLComponents(string: identifier) else { return nil }
        return components.scheme?.lowercased()
    }

    /// The spec form: `wellKnown` inserted between the host and the path.
    static func insertionForm(_ identifier: String, wellKnown: String) -> String? {
        guard var components = URLComponents(string: identifier),
              let scheme = components.scheme, !scheme.isEmpty,
              let host = components.host, !host.isEmpty
        else { return nil }

        var path = components.path
        while path.hasPrefix("/") { path.removeFirst() }
        while path.hasSuffix("/") { path.removeLast() }

        components.path = path.isEmpty ? "/\(wellKnown)" : "/\(wellKnown)/\(path)"
        components.query = nil
        components.fragment = nil
        return components.url?.absoluteString
    }

    /// The non-spec fallback form: `wellKnown` appended to `identifier`.
    static func suffixForm(_ identifier: String, wellKnown: String) -> String {
        var base = identifier
        while base.hasSuffix("/") { base.removeLast() }
        return "\(base)/\(wellKnown)"
    }

    /// The URLs to try for `wellKnown`, spec form first.
    ///
    /// The two forms coincide when the identifier has no path, so the result is de-duplicated and
    /// may hold a single entry.
    static func candidates(
        for identifier: String,
        wellKnown: String,
        policy: DiscoveryPolicy
    ) -> [String] {
        var urls: [String] = []
        if let insertion = insertionForm(identifier, wellKnown: wellKnown) { urls.append(insertion) }
        if policy.allowSuffixWellKnownFallback {
            let suffix = suffixForm(identifier, wellKnown: wellKnown)
            if !urls.contains(suffix) { urls.append(suffix) }
        }
        return urls
    }
}
