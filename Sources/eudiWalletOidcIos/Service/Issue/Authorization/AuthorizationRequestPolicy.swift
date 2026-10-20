//
//  AuthorizationRequestPolicy.swift
//
//  What the SDK sends and accepts when making an authorization request.
//

import Foundation

/// What the SDK sends and accepts when making an authorization request.
///
/// ``standard`` preserves the SDK's existing behaviour; ``strict`` is OpenID4VCI 1.0 as written.
///
/// Note on what is *not* configurable: `authorization_details` and `scope` are always sent
/// together. Sections 5.1.1 and 5.1.2 present them as two alternative ways of identifying the
/// requested credential, but sending both is what this SDK has always done and what deployed
/// servers expect. There was a flag for it that no code ever read, which is worse than no flag.
/// Mirrors `AuthorizationRequestPolicy` in the Android SDK.
public struct AuthorizationRequestPolicy {

    /// Send `client_metadata`. Not an OpenID4VCI authorization request parameter; it is carried for
    /// servers that use it to learn the wallet's supported VP formats before asking for a
    /// presentation mid-issuance.
    public var sendClientMetadata: Bool

    /// Allow the IAR profile extension when the authorization server advertises its endpoint.
    public var allowInteractiveAuthorization: Bool

    /// Send a `resource` parameter, RFC 8707, naming the Credential Issuer.
    ///
    /// Sections 5.1.2 and 6.1: "If the Credential Issuer metadata contains an
    /// `authorization_servers` property, it is RECOMMENDED to use a `resource` parameter [RFC8707]
    /// whose value is the Credential Issuer's identifier value", so an authorization server serving
    /// several issuers can tell them apart. Sent only under that condition.
    ///
    /// On by default: it *adds* a parameter, and section 5.1.3 requires the authorization server to
    /// "ignore any unrecognized parameters".
    public var sendResourceParameter: Bool

    /// Take `scope` from the credential configuration the offer names, per section 5.1.2, instead
    /// of always sending a bare `openid`.
    ///
    /// **Off by default**, unlike ``sendResourceParameter``, because it *changes* a parameter the
    /// authorization server acts on rather than adding one it must ignore. `authorization_details`
    /// already identifies the credential, so this buys little and risks a server that rejects
    /// scopes it did not expect. Turn it on once there is a live issuer to try it against.
    public var useCredentialScopes: Bool

    public init(
        sendClientMetadata: Bool = true,
        allowInteractiveAuthorization: Bool = true,
        sendResourceParameter: Bool = true,
        useCredentialScopes: Bool = false
    ) {
        self.sendClientMetadata = sendClientMetadata
        self.allowInteractiveAuthorization = allowInteractiveAuthorization
        self.sendResourceParameter = sendResourceParameter
        self.useCredentialScopes = useCredentialScopes
    }

    /// The SDK's existing behaviour.
    public static let standard = AuthorizationRequestPolicy()

    /// OpenID4VCI 1.0 only: no profile extensions, no non-spec parameters.
    public static let strict = AuthorizationRequestPolicy(
        sendClientMetadata: false,
        allowInteractiveAuthorization: false,
        useCredentialScopes: true
    )
}
