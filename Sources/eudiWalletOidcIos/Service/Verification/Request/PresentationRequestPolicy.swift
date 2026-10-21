//
//  PresentationRequestPolicy.swift
//  eudiWalletOidcIos
//

import Foundation
import Security

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

    /// Whether a request that fails the rules of its client identifier prefix (section 5.9.3) is
    /// refused, only reported, or not checked at all.
    public var clientVerification: ClientVerification

    /// Accept a `client_id` with no prefix, or with one this SDK does not know, as a pre-registered
    /// client (section 5.9.2). Such a request carries no authentication; the host's trust list is
    /// what vouches for the client.
    public var allowPreRegisteredClients: Bool

    /// Roots the `x5c` chain of an `x509_san_dns` or `x509_hash` request must end in. Empty means
    /// the chain is checked for consistency only and reported as not anchored, leaving the trust
    /// decision to the host.
    public var trustAnchors: [SecCertificate]

    /// Public keys, as JWK dictionaries, of the parties trusted to issue verifier attestation JWTs.
    /// An attestation signed by one of them is anchored. Without a match, a self-consistent
    /// attestation (its `iss` is a DID that resolves to the signing key) is verified but not anchored.
    public var verifierAttestationIssuerKeys: [[String: Any]]

    /// Refuse a verified client whose key is not anchored: an x509 chain that ends in none of
    /// `trustAnchors`, or an attestation from none of `verifierAttestationIssuerKeys`. Off by
    /// default because the host's trust list makes that decision today; on in `strict`, which is
    /// section 5.9.3 as written.
    public var requireAnchoredClients: Bool

    public init(allowDraftRequests: Bool = true,
                allowUnsignedRequestObjects: Bool = false,
                rejectAmbiguousRequests: Bool = true,
                clientVerification: ClientVerification = .enforced,
                allowPreRegisteredClients: Bool = true,
                trustAnchors: [SecCertificate] = [],
                verifierAttestationIssuerKeys: [[String: Any]] = [],
                requireAnchoredClients: Bool = false) {
        self.allowDraftRequests = allowDraftRequests
        self.allowUnsignedRequestObjects = allowUnsignedRequestObjects
        self.rejectAmbiguousRequests = rejectAmbiguousRequests
        self.clientVerification = clientVerification
        self.allowPreRegisteredClients = allowPreRegisteredClients
        self.trustAnchors = trustAnchors
        self.verifierAttestationIssuerKeys = verifierAttestationIssuerKeys
        self.requireAnchoredClients = requireAnchoredClients
    }

    /// The SDK's existing behaviour.
    public static let `default` = PresentationRequestPolicy()

    /// OpenID4VP 1.0 as written: DCQL only, no draft parameters, no pre-registered clients.
    public static let strict = PresentationRequestPolicy(allowDraftRequests: false,
                                                         allowPreRegisteredClients: false,
                                                         requireAnchoredClients: true)
}
