//
//  TokenGrant.swift
//

import Foundation

/// Which grant the token request uses, and the values that grant needs.
///
/// The credential offer decides this, not the caller and not the server -- which is why this is an
/// enum rather than a registry like the authorization transports.
///
/// It replaces four loose parameters (`code`, `codeVerifier`, `isPreAuthorisedCodeFlow`,
/// `userPin`) in which illegal states were representable. Section 6.1 says `tx_code` "MUST only be
/// used if the grant_type is `urn:ietf:params:oauth:grant-type:pre-authorized_code`"; here that
/// rule cannot be broken.
///
/// Mirrors `TokenGrant` in the Android SDK.
public enum TokenGrant {

    /// The code from an authorization request (section 6.1, RFC 6749 section 4.1.3).
    ///
    /// - Parameter redirectUri: **must be the value the authorization request actually sent** --
    ///   read it from ``AuthorizationRequestInfo/redirectUri`` rather than re-deriving it. RFC 6749
    ///   section 4.1.3 requires the two to be identical.
    case authorizationCode(code: String, codeVerifier: String?, redirectUri: String? = nil)

    /// The code the credential offer carried, for issuance the user never authorized in a browser.
    ///
    /// - Parameter txCode: the Transaction Code the user typed. Whether one is *needed* is a
    ///   property of the offer -- see ``IssuanceSession/requiresTransactionCode`` -- not of whether
    ///   the caller happens to have one.
    case preAuthorized(code: String, txCode: String? = nil)

    public static let authorizationCodeGrantType = "authorization_code"
    public static let preAuthorizedGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

    /// The wire value of `grant_type`.
    public var grantType: String {
        switch self {
        case .authorizationCode: return Self.authorizationCodeGrantType
        case .preAuthorized: return Self.preAuthorizedGrantType
        }
    }

    var code: String {
        switch self {
        case let .authorizationCode(code, _, _): return code
        case let .preAuthorized(code, _): return code
        }
    }
}
