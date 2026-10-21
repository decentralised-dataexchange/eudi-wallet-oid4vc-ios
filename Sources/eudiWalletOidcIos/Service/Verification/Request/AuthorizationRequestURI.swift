//
//  AuthorizationRequestURI.swift
//  eudiWalletOidcIos
//

import Foundation

/// Query string handling for authorization request links.
///
/// Read through `URLComponents`, as the SDK always has, so `+` stays `+` and percent escapes are
/// decoded. A string `URL` cannot parse falls back to the hand parser in `RequestUriMethod`.
enum AuthorizationRequestURI {

    /// The value of `name` in the query string, decoded, or nil when absent. When a name repeats,
    /// the last occurrence wins.
    static func queryParam(_ data: String?, _ name: String) -> String? {
        guard let data, !data.isEmpty else { return nil }
        if let url = URL(string: data), let components = URLComponents(url: url, resolvingAgainstBaseURL: true) {
            return components.queryItems?.last { $0.name == name }.map { $0.value ?? "" }
        }
        return RequestUriMethod.queryParameter(data, name)
    }

    /// True when `name` appears in the query string, even with an empty value.
    static func hasQueryParam(_ data: String?, _ name: String) -> Bool {
        queryParam(data, name) != nil
    }

    /// True when `name` appears with a value that is not blank.
    static func hasValue(_ data: String?, _ name: String) -> Bool {
        !(queryParam(data, name)?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
    }
}
