//
//  TokenRequestPolicy.swift
//

import Foundation

/// What the SDK sends and accepts when making a token request.
///
/// ``standard`` preserves the SDK's existing behaviour; ``strict`` is OpenID4VCI 1.0 as written.
/// Mirrors `TokenRequestPolicy` in the Android SDK.
public struct TokenRequestPolicy {

    /// Send `resource`, RFC 8707, naming the Credential Issuer.
    ///
    /// Section 6.1 recommends it when the issuer metadata declares `authorization_servers`.
    /// **Off by default**, unlike the authorization request's equivalent: there, section 5.1.3
    /// obliges the server to ignore parameters it does not recognise, and the token endpoint has no
    /// such rule -- RFC 8707 section 2 lets a server reject an unknown target with `invalid_target`.
    public var sendResourceParameter: Bool

    /// Send `authorization_details`, and with it `locations`.
    ///
    /// Section 6.1.1 permits it and section 6.2 makes the response's `authorization_details`
    /// REQUIRED when it is used. **Off by default** for the same reason: it changes a request that
    /// works today.
    public var sendAuthorizationDetails: Bool

    /// Retry once when the authorization server demands a DPoP nonce (RFC 9449 section 8).
    public var retryOnDPoPNonce: Bool

    public init(
        sendResourceParameter: Bool = false,
        sendAuthorizationDetails: Bool = false,
        retryOnDPoPNonce: Bool = true
    ) {
        self.sendResourceParameter = sendResourceParameter
        self.sendAuthorizationDetails = sendAuthorizationDetails
        self.retryOnDPoPNonce = retryOnDPoPNonce
    }

    public static let standard = TokenRequestPolicy()

    /// OpenID4VCI 1.0 as written: everything the specification recommends, sent.
    public static let strict = TokenRequestPolicy(
        sendResourceParameter: true,
        sendAuthorizationDetails: true
    )
}
