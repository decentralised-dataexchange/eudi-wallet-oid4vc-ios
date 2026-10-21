//
//  PresentationRequestPolicy.swift
//  eudiWalletOidcIos
//

import Foundation

/// What the SDK will accept when resolving a presentation request.
///
/// Kept in one place so a rule can be tightened or relaxed without touching the resolution logic.
/// `default` preserves the SDK's existing behaviour; `strict` is OpenID4VP 1.0 as written.
public struct PresentationRequestPolicy {

    /// Accept pre-1.0 requests: `presentation_definition`, `presentation_definition_uri` and
    /// `client_metadata_uri`. Set false to require a `dcql_query`.
    public var allowDraftRequests: Bool

    /// Accept a request object with `alg: none` for a client identifier prefix other than
    /// `redirect_uri`. OpenID4VP 1.0 section 5.9 says a `redirect_uri` request MUST NOT be signed,
    /// so that prefix is exempt whatever this says. For every other prefix the signature is what
    /// identifies the verifier, so an unsigned object is refused by default.
    public var allowUnsignedRequestObjects: Bool

    /// Refuse a request carrying both `request` and `request_uri`. RFC 9101 section 5: if either
    /// parameter is present in the authorization request, the other MUST NOT be.
    public var rejectAmbiguousRequests: Bool

    public init(allowDraftRequests: Bool = true,
                allowUnsignedRequestObjects: Bool = false,
                rejectAmbiguousRequests: Bool = true) {
        self.allowDraftRequests = allowDraftRequests
        self.allowUnsignedRequestObjects = allowUnsignedRequestObjects
        self.rejectAmbiguousRequests = rejectAmbiguousRequests
    }

    /// The SDK's existing behaviour.
    public static let `default` = PresentationRequestPolicy()

    /// OpenID4VP 1.0 as written: DCQL only, no draft parameters.
    public static let strict = PresentationRequestPolicy(allowDraftRequests: false)
}
