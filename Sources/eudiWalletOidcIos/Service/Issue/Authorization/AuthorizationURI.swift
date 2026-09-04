//
//  AuthorizationURI.swift
//
//  Reading and building authorization URLs.
//

import Foundation

/// Reading and building authorization URLs.
///
/// Encoding matches the rest of the SDK: `UIApplicationUtils.percentEscape`, the RFC 3986
/// unreserved set with space as `%20`, applied through `percentEncodedQueryItems` so Foundation
/// does not re-encode what is already escaped.
///
/// Mirrors `AuthorizationUri` in the Android SDK.
enum AuthorizationURI {

    /// First occurrence of `name` in the query string, decoded, or `nil`.
    static func queryParameter(_ url: String?, _ name: String) -> String? {
        guard let url, !url.isEmpty else { return nil }
        guard let components = URLComponents(string: url) else { return nil }
        guard let item = components.queryItems?.first(where: { $0.name == name }) else { return nil }
        // `queryItems` already percent-decodes. Decoding again mangled any value that legitimately
        // contains a percent sign followed by two hex digits.
        return item.value
    }

    /// `base` with `parameters` appended as a query string. Blank values are skipped.
    static func appending(_ parameters: [String: String?], to base: String) -> String {
        guard var components = URLComponents(string: base) else { return base }
        let items = parameters
            .compactMapValues { $0 }
            .filter { !$0.value.isEmpty }
            .sorted { $0.key < $1.key }
            .map { UIApplicationUtils.shared.encodedQueryItem($0.key, $0.value) }
        guard !items.isEmpty else { return base }
        components.percentEncodedQueryItems = (components.percentEncodedQueryItems ?? []) + items
        return components.url?.absoluteString ?? base
    }
}
