//
//  DiscoveryService.swift
//
//
//  Created by Mumthasir mohammed on 08/03/24.
//
import Foundation

/// Credential Issuer and Authorization Server metadata discovery.
///
/// A delegation to `Service/Discovery/Metadata/`, where URL construction, retrieval, trust in
/// signed documents, spec revision and conformance are each a separate, testable piece. Both
/// protocol methods keep their exact signatures, so hosts need no change.
public class DiscoveryService: DiscoveryServiceProtocol {

    public static var shared = DiscoveryService()

    /// What to accept. ``DiscoveryPolicy/standard`` preserves this SDK's existing reach;
    /// ``DiscoveryPolicy/strict`` is OpenID4VCI 1.0 as written and will reject pre-1.0 issuers.
    public var policy: DiscoveryPolicy

    /// Establishes trust in signed metadata. The default verifies the signature and accepts any
    /// signer that produced a valid one; see ``SignatureOnlyMetadataSignerTrust`` for what that
    /// does and does not prove. ``RejectingSignedMetadataVerifier`` refuses signed metadata
    /// outright, which is always safe: section 12.2.2 requires every issuer to serve unsigned JSON.
    public var signedMetadataVerifier: SignedMetadataVerifier

    public init(
        policy: DiscoveryPolicy = .standard,
        signedMetadataVerifier: SignedMetadataVerifier = SignatureValidatorSignedMetadataVerifier()
    ) {
        self.policy = policy
        self.signedMetadataVerifier = signedMetadataVerifier
    }

    private var issuerResolver: IssuerMetadataResolver {
        IssuerMetadataResolver(policy: policy, signedMetadataVerifier: signedMetadataVerifier)
    }

    private var authServerResolver: AuthServerMetadataResolver {
        AuthServerMetadataResolver(policy: policy, signedMetadataVerifier: signedMetadataVerifier)
    }

    // MARK: - Retrieves the issuer configuration asynchronously based on the provided credential issuer well-known URI.
    ///
    /// - Parameter credentialIssuerWellKnownURI: the Credential Issuer Identifier, with or without
    ///   a `/.well-known/openid-credential-issuer` segment; both spec URL layouts are recognised
    ///   and stripped back to the identifier before the request URLs are built.
    /// - Returns: never `nil`. A failure carries an `error` rather than being absent, so a caller
    ///   can always tell what went wrong and always has something to show.
    public func getIssuerConfig(credentialIssuerWellKnownURI: String?) async throws -> IssuerWellKnownConfiguration? {
        await issuerResolver.resolve(credentialIssuerWellKnownURI).configuration
    }

    // MARK: - To fetch the authorisation server configuration
    /// - SeeAlso: ``getIssuerConfig(credentialIssuerWellKnownURI:)``
    public func getAuthConfig(authorisationServerWellKnownURI: String?) async throws -> AuthorisationServerWellKnownConfiguration? {
        await authServerResolver.resolve(authorisationServerWellKnownURI).configuration
    }

    /// As ``getIssuerConfig(credentialIssuerWellKnownURI:)``, plus which URL layout answered, the
    /// media type, and which spec revision the document was. For diagnostics and for exercising
    /// this function on its own.
    public func getIssuerConfigDetailed(credentialIssuerWellKnownURI: String?) async -> DiscoveredIssuerMetadata {
        await issuerResolver.resolve(credentialIssuerWellKnownURI)
    }

    /// - SeeAlso: ``getIssuerConfigDetailed(credentialIssuerWellKnownURI:)``
    public func getAuthConfigDetailed(authorisationServerWellKnownURI: String?) async -> DiscoveredAuthServerMetadata {
        await authServerResolver.resolve(authorisationServerWellKnownURI)
    }

    /// Which authorization server to use, per OpenID4VCI 1.0 section 12.2.4.
    ///
    /// Handles the cases a host implementing this itself tends to miss: an absent
    /// `authorization_servers` means the Credential Issuer is its own authorization server, and an
    /// offer naming a server the issuer does not list must stop the flow rather than fall back.
    public func selectAuthorizationServer(
        issuerConfig: IssuerWellKnownConfiguration?,
        credentialOffer: CredentialOffer? = nil
    ) throws -> AuthorizationServerSelection {
        let selector = AuthorizationServerSelector()
        return try selector.select(issuerConfig: issuerConfig, hint: selector.hint(from: credentialOffer))
    }
}
