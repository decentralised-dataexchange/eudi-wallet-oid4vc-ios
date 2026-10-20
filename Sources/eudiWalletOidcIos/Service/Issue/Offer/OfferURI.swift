//
//  OfferURI.swift
//  eudiWalletOidcIos
//

import Foundation

/// Query-string handling for offer links.
///
/// Offer links use custom schemes (`openid-credential-offer://`, `openid://`) whose contents
/// `URLComponents` will parse but not always in the way a caller expects, so the query is read
/// directly from the string. Percent-decoding matches `URL.queryParameters`, and `+` means space.
enum OfferURI {

    /// First occurrence of `name` in the query string, decoded, or `nil`.
    static func queryParameter(_ name: String, in data: String?) -> String? {
        guard let data, !data.isEmpty else { return nil }

        let withoutFragment = data.components(separatedBy: "#").first ?? data
        guard let separatorIndex = withoutFragment.firstIndex(of: "?") else { return nil }
        let query = String(withoutFragment[withoutFragment.index(after: separatorIndex)...])
        guard !query.isEmpty else { return nil }

        for pair in query.components(separatedBy: "&") where !pair.isEmpty {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard decode(String(parts[0])) == name else { continue }
            return parts.count > 1 ? decode(String(parts[1])) : ""
        }
        return nil
    }

    /// Scheme of `data`, lowercased, or `nil` when it has none.
    static func scheme(of data: String?) -> String? {
        guard let data, !data.isEmpty,
              let separatorIndex = data.firstIndex(of: ":"), separatorIndex != data.startIndex
        else { return nil }

        let scheme = String(data[data.startIndex..<separatorIndex])
        // A scheme is ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) -- RFC 3986.
        guard let first = scheme.first, first.isLetter else { return nil }
        guard scheme.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "+" || $0 == "-" || $0 == "." })
        else { return nil }
        return scheme.lowercased()
    }

    private static func decode(_ value: String) -> String {
        // Malformed percent-escapes are common in issuer links; keep the raw value rather than
        // discarding an otherwise usable offer.
        value.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? value
    }
}
