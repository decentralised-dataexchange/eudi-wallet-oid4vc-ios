//
//  AuthServerMetadataResolver.swift
//  eudiWalletOidcIos
//

import Foundation

/// Resolves an authorization server identifier into its metadata.
///
/// OpenID4VCI 1.0 section 12.2.4 names one location: "The actual OAuth 2.0 Authorization Server
/// metadata is obtained from the oauth-authorization-server well-known location as defined in
/// Section 3 of [RFC8414]". Deployments fronted by an OpenID Provider commonly publish only the
/// OpenID Connect Discovery document instead, so `openid-configuration` is tried afterwards behind
/// ``DiscoveryPolicy/allowOpenIdConfigurationFallback``. The EBSI conformance authorization server
/// is one of these: its `oauth-authorization-server` location returns 404.
///
/// Order is spec-first throughout, so a conformant server answers on the first request.
public struct AuthServerMetadataResolver {

    private struct Candidate {
        let url: String
        let wellKnown: String
        let form: WellKnownForm
    }

    private let policy: DiscoveryPolicy
    private let validator: AuthServerMetadataValidator
    private let signedMetadataVerifier: SignedMetadataVerifier
    private let session: URLSession

    public init(
        policy: DiscoveryPolicy = .standard,
        signedMetadataVerifier: SignedMetadataVerifier = SignatureValidatorSignedMetadataVerifier(),
        session: URLSession = .shared
    ) {
        self.policy = policy
        self.validator = AuthServerMetadataValidator()
        self.signedMetadataVerifier = signedMetadataVerifier
        self.session = session
    }

    public func resolve(_ input: String?) async -> DiscoveredAuthServerMetadata {
        guard let identifier = WellKnownURLBuilder.identifier(from: input) else {
            return Self.failure(.noIdentifier, AuthServerMetadataDiagnostics(identifier: nil))
        }
        guard let scheme = WellKnownURLBuilder.scheme(of: identifier), !scheme.isEmpty else {
            return Self.failure(.invalidIdentifier(identifier), AuthServerMetadataDiagnostics(identifier: identifier))
        }
        guard policy.allows(scheme: scheme) else {
            return Self.failure(.unsupportedScheme(scheme), AuthServerMetadataDiagnostics(identifier: identifier))
        }

        let candidates = candidatesFor(identifier)
        guard !candidates.isEmpty else {
            return Self.failure(.invalidIdentifier(identifier), AuthServerMetadataDiagnostics(identifier: identifier))
        }
        var mostInformative: DiscoveryError?

        for (index, candidate) in candidates.enumerated() {
            do {
                let document = try await MetadataFetcher.fetch(
                    url: candidate.url, tag: "auth-server-metadata", policy: policy,
                    supportsSignedMetadata: signedMetadataVerifier.supportsSignedMetadata,
                    session: session
                )
                let body = try await payload(of: document, identifier: identifier)
                guard let parsed = try? JSONDecoder()
                    .decode(AuthorisationServerWellKnownConfiguration.self, from: body)
                else {
                    throw DiscoveryError.malformed("The authorization server configuration was not valid JSON")
                }
                let configuration = try validator.validate(parsed, expectedIdentifier: identifier)

                if candidate.wellKnown == WellKnownURLBuilder.openIdConfiguration {
                    debugPrint("### Authorization server metadata came from OpenID Connect Discovery: \(candidate.url)")
                }
                return DiscoveredAuthServerMetadata(
                    configuration: configuration,
                    diagnostics: AuthServerMetadataDiagnostics(
                        identifier: identifier,
                        attemptedURLs: candidates.prefix(index + 1).map { $0.url },
                        resolvedURL: candidate.url,
                        form: candidate.form,
                        contentType: document.contentType,
                        wellKnown: candidate.wellKnown
                    )
                )
            } catch let error as DiscoveryError {
                mostInformative = DiscoveryError.mostInformative(mostInformative, error)
            } catch {
                mostInformative = DiscoveryError.mostInformative(
                    mostInformative, .malformed("The authorization server configuration could not be read")
                )
            }
        }

        return Self.failure(
            mostInformative ?? .fetchFailed(status: nil, detail: nil),
            AuthServerMetadataDiagnostics(identifier: identifier, attemptedURLs: candidates.map { $0.url })
        )
    }

    /// Spec location first, in both URL layouts, then the OpenID Connect Discovery document --
    /// the order this SDK has always used, so no server that works today starts failing.
    private func candidatesFor(_ identifier: String) -> [Candidate] {
        var wellKnowns = [WellKnownURLBuilder.oauthAuthorizationServer]
        if policy.allowOpenIdConfigurationFallback {
            wellKnowns.append(WellKnownURLBuilder.openIdConfiguration)
        }

        var seen: [String] = []
        var candidates: [Candidate] = []
        for wellKnown in wellKnowns {
            if let url = WellKnownURLBuilder.insertionForm(identifier, wellKnown: wellKnown), !seen.contains(url) {
                seen.append(url)
                candidates.append(Candidate(url: url, wellKnown: wellKnown, form: .insertion))
            }
        }
        if policy.allowSuffixWellKnownFallback {
            for wellKnown in wellKnowns {
                let url = WellKnownURLBuilder.suffixForm(identifier, wellKnown: wellKnown)
                if !seen.contains(url) {
                    seen.append(url)
                    candidates.append(Candidate(url: url, wellKnown: wellKnown, form: .suffix))
                }
            }
        }
        return candidates
    }

    /// Before this, a document delivered as a JWT had its payload decoded and trusted with no
    /// signature check, which put the token endpoint under the control of whoever answered.
    private func payload(of document: MetadataDocument, identifier: String) async throws -> Data {
        if document.isJWTMediaType || MetadataFetcher.looksLikeJWT(document.body) {
            let jwt = String(data: document.body, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return try await signedMetadataVerifier.verify(jwt: jwt, expectedIssuerIdentifier: identifier)
        }
        return document.body
    }

    private static func failure(
        _ error: DiscoveryError, _ diagnostics: AuthServerMetadataDiagnostics
    ) -> DiscoveredAuthServerMetadata {
        DiscoveredAuthServerMetadata(
            configuration: AuthorisationServerWellKnownConfiguration(
                error: EUDIError(from: ErrorResponse(message: error.errorDescription, code: error.httpStatus))
            ),
            diagnostics: diagnostics
        )
    }
}
