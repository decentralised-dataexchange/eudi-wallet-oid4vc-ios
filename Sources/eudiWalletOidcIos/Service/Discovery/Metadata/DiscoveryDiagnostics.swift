//
//  DiscoveryDiagnostics.swift
//  eudiWalletOidcIos
//

import Foundation

/// What actually happened during a discovery call.
///
/// None of this reaches a host that only reads the configuration. It exists so each rewritten
/// function can be exercised on its own and report which internal path fired -- the thing that is
/// otherwise invisible, and the reason a non-conformant issuer looks identical to a broken one.
public struct IssuerMetadataDiagnostics {
    /// The identifier the well-known URLs were built from.
    public let identifier: String?
    /// Every URL tried, in order.
    public let attemptedURLs: [String]
    /// The URL that produced the document, or `nil` when none did.
    public let resolvedURL: String?
    /// Which layout ``resolvedURL`` used.
    public let form: WellKnownForm?
    /// The response's declared media type.
    public let contentType: String?
    /// Which parser claimed the document.
    public let specVersion: IssuerMetadataSpecVersion?

    /// `true` when the document came from the non-spec suffix fallback.
    public var usedSuffixFallback: Bool { form == .suffix }

    init(
        identifier: String?,
        attemptedURLs: [String] = [],
        resolvedURL: String? = nil,
        form: WellKnownForm? = nil,
        contentType: String? = nil,
        specVersion: IssuerMetadataSpecVersion? = nil
    ) {
        self.identifier = identifier
        self.attemptedURLs = attemptedURLs
        self.resolvedURL = resolvedURL
        self.form = form
        self.contentType = contentType
        self.specVersion = specVersion
    }
}

/// - SeeAlso: ``IssuerMetadataDiagnostics``
public struct AuthServerMetadataDiagnostics {
    public let identifier: String?
    public let attemptedURLs: [String]
    public let resolvedURL: String?
    public let form: WellKnownForm?
    public let contentType: String?
    /// Which well-known document answered: `oauth-authorization-server` is the location OpenID4VCI
    /// names, `openid-configuration` is the OpenID Connect Discovery fallback.
    public let wellKnown: String?

    /// `true` when the RFC 8414 location failed and OpenID Connect Discovery answered instead.
    public var usedOpenIdConfigurationFallback: Bool {
        wellKnown == WellKnownURLBuilder.openIdConfiguration
    }

    init(
        identifier: String?,
        attemptedURLs: [String] = [],
        resolvedURL: String? = nil,
        form: WellKnownForm? = nil,
        contentType: String? = nil,
        wellKnown: String? = nil
    ) {
        self.identifier = identifier
        self.attemptedURLs = attemptedURLs
        self.resolvedURL = resolvedURL
        self.form = form
        self.contentType = contentType
        self.wellKnown = wellKnown
    }
}

/// An issuer metadata lookup: what a host sees, plus how it got there.
public struct DiscoveredIssuerMetadata {
    public let configuration: IssuerWellKnownConfiguration
    public let diagnostics: IssuerMetadataDiagnostics
}

/// An authorization server metadata lookup: what a host sees, plus how it got there.
public struct DiscoveredAuthServerMetadata {
    public let configuration: AuthorisationServerWellKnownConfiguration
    public let diagnostics: AuthServerMetadataDiagnostics
}
