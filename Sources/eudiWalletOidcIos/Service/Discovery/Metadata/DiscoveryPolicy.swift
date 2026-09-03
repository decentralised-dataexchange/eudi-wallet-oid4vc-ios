//
//  DiscoveryPolicy.swift
//  eudiWalletOidcIos
//

import Foundation

/// What the SDK will accept when discovering issuer and authorization server metadata.
///
/// Kept in one place so a rule can be tightened or relaxed without touching the resolution logic.
/// ``standard`` preserves the SDK's existing reach; ``strict`` is what OpenID4VCI 1.0 actually
/// requires.
///
/// Every non-spec allowance ``standard`` grants is load-bearing for a real issuer. Against the EBSI
/// conformance mocks the spec's own URL form returns 404, the metadata is draft-shaped, and the
/// `oauth-authorization-server` location returns 404 -- so ``strict`` would break that issuer on
/// three separate switches. ``strict`` is for conformance testing, not for a wallet.
public struct DiscoveryPolicy {

    /// Schemes accepted for metadata retrieval.
    ///
    /// Section 12.2.2: "Communication with the Credential Issuer Metadata Endpoint MUST utilize
    /// TLS". `http` is kept by default because issuers are commonly run locally during development.
    public var allowedSchemes: Set<String>

    /// Fall back to `<identifier>/.well-known/...` when the spec's insertion form yields nothing.
    ///
    /// Not in the specification, which requires the well-known string be inserted *between the host
    /// and the path*. Kept on because issuers that only serve the suffix form are common.
    public var allowSuffixWellKnownFallback: Bool

    /// Try `openid-configuration` when `oauth-authorization-server` yields nothing.
    ///
    /// Not in OpenID4VCI, which names only the RFC 8414 location. Kept on because authorization
    /// servers fronted by an OpenID Provider commonly publish only the OpenID Connect Discovery
    /// document.
    public var allowOpenIdConfigurationFallback: Bool

    /// Reject a document whose `credential_issuer` differs from the identifier it was fetched for.
    ///
    /// Section 12.2.4: if the values are not identical "the data contained in the response MUST NOT
    /// be used".
    ///
    /// **Off by default**, because real deployments do not satisfy it yet: the iGrant issuers serve
    /// their metadata at both `<base>/service` and `<base>/service/version-01` while always
    /// declaring the latter, and the wallet asks using the former. A mismatch is reported either
    /// way, so the gap stays visible. Turn it on once issuers are asked for their canonical
    /// identifier -- it is the check that stops a substituted document redirecting the credential
    /// endpoint.
    public var requireIssuerIdentifierMatch: Bool

    /// Accept pre-1.0 draft issuer metadata. Set `false` to require OpenID4VCI 1.0.
    public var allowDraftMetadata: Bool

    /// Reject a document whose `Content-Type` is not JSON.
    public var requireJSONContentType: Bool

    /// Send an `Accept-Language` header derived from the device locale (RECOMMENDED, 12.2.2).
    public var sendAcceptLanguage: Bool

    /// Overrides the device locale for `Accept-Language`.
    public var acceptLanguage: String?

    /// Largest metadata document accepted, in bytes.
    public var maxMetadataBytes: Int

    public init(
        allowedSchemes: Set<String> = ["https", "http"],
        allowSuffixWellKnownFallback: Bool = true,
        allowOpenIdConfigurationFallback: Bool = true,
        requireIssuerIdentifierMatch: Bool = false,
        allowDraftMetadata: Bool = true,
        requireJSONContentType: Bool = false,
        sendAcceptLanguage: Bool = true,
        acceptLanguage: String? = nil,
        maxMetadataBytes: Int = 512 * 1024
    ) {
        self.allowedSchemes = allowedSchemes
        self.allowSuffixWellKnownFallback = allowSuffixWellKnownFallback
        self.allowOpenIdConfigurationFallback = allowOpenIdConfigurationFallback
        self.requireIssuerIdentifierMatch = requireIssuerIdentifierMatch
        self.allowDraftMetadata = allowDraftMetadata
        self.requireJSONContentType = requireJSONContentType
        self.sendAcceptLanguage = sendAcceptLanguage
        self.acceptLanguage = acceptLanguage
        self.maxMetadataBytes = maxMetadataBytes
    }

    func allows(scheme: String?) -> Bool {
        guard let scheme else { return false }
        return allowedSchemes.contains { $0.caseInsensitiveCompare(scheme) == .orderedSame }
    }

    /// The SDK's existing reach.
    public static let standard = DiscoveryPolicy()

    /// OpenID4VCI 1.0 as written: https only, no fallbacks, no drafts.
    public static let strict = DiscoveryPolicy(
        allowedSchemes: ["https"],
        allowSuffixWellKnownFallback: false,
        allowOpenIdConfigurationFallback: false,
        requireIssuerIdentifierMatch: true,
        allowDraftMetadata: false,
        requireJSONContentType: true
    )
}
