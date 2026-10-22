//
//  ResponseMode.swift
//  eudiWalletOidcIos
//

import Foundation

/// The `response_mode` of a request, OpenID4VP 1.0 sections 8.2, 8.3 and Appendix A, plus the EWC
/// interactive authorization modes.
enum ResponseMode: Equatable {
    case directPost
    case directPostJWT
    case dcApi
    case dcApiJWT
    case iarPost
    case iarPostJWT
    case unsupported(String)

    /// The modes this SDK knows, or nil for an absent or unknown one.
    init?(from string: String) {
        guard !string.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        let mode = Self.parse(string)
        if case .unsupported = mode { return nil }
        self = mode
    }

    /// Absent means `direct_post`, as the previous API assumed.
    static func of(_ request: PresentationRequest) -> ResponseMode {
        parse(request.responseMode)
    }

    static func parse(_ value: String?) -> ResponseMode {
        switch value?.trimmingCharacters(in: .whitespaces) {
        case nil, "": return .directPost
        case "direct_post": return .directPost
        case "direct_post.jwt": return .directPostJWT
        case "dc_api": return .dcApi
        case "dc_api.jwt": return .dcApiJWT
        case "iar-post": return .iarPost
        case "iar-post.jwt": return .iarPostJWT
        case let other?: return .unsupported(other)
        }
    }

    /// The response travels as a JWE in the `response` parameter (section 8.3).
    var encrypted: Bool { self == .directPostJWT || self == .dcApiJWT || self == .iarPostJWT }

    /// The host, not this SDK, carries the response to the verifier.
    var deliveredByHost: Bool { self == .dcApi || self == .dcApiJWT }

    /// The EWC interactive authorization request: the response is wrapped with the `auth_session`.
    var interactiveAuthorization: Bool { self == .iarPost || self == .iarPostJWT }
}
