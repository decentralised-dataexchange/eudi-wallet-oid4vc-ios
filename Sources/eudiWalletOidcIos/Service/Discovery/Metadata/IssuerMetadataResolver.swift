//
//  IssuerMetadataResolver.swift
//  eudiWalletOidcIos
//

import Foundation

/// Resolves a Credential Issuer Identifier into its metadata: build the URLs, retrieve, establish
/// trust if the document is signed, pick a parser, validate.
///
/// The parser registry is ordered and OpenID4VCI 1.0 always comes first, so a draft parser only
/// ever sees a document 1.0 has declined. Legacy entries are grouped so draft support can be
/// removed as a block.
///
/// Every failure returns an `IssuerWellKnownConfiguration` carrying an `error` -- never a bare
/// `nil`. Callers previously could not tell "no address given" from "network failure" from "not an
/// issuer", and had nothing to show for any of them.
public struct IssuerMetadataResolver {

    private let policy: DiscoveryPolicy
    private let validator: IssuerMetadataValidator
    private let parsers: [IssuerMetadataParser]
    private let signedMetadataVerifier: SignedMetadataVerifier
    private let session: URLSession

    public init(
        policy: DiscoveryPolicy = .standard,
        signedMetadataVerifier: SignedMetadataVerifier = SignatureValidatorSignedMetadataVerifier(),
        session: URLSession = .shared
    ) {
        self.policy = policy
        self.validator = IssuerMetadataValidator()
        self.parsers = Self.defaultParsers()
        self.signedMetadataVerifier = signedMetadataVerifier
        self.session = session
    }

    public func resolve(_ input: String?) async -> DiscoveredIssuerMetadata {
        guard let identifier = WellKnownURLBuilder.identifier(from: input) else {
            return Self.failure(.noIdentifier, IssuerMetadataDiagnostics(identifier: nil))
        }
        guard let scheme = WellKnownURLBuilder.scheme(of: identifier), !scheme.isEmpty else {
            return Self.failure(.invalidIdentifier(identifier), IssuerMetadataDiagnostics(identifier: identifier))
        }
        guard policy.allows(scheme: scheme) else {
            return Self.failure(.unsupportedScheme(scheme), IssuerMetadataDiagnostics(identifier: identifier))
        }

        let candidates = WellKnownURLBuilder.candidates(
            for: identifier, wellKnown: WellKnownURLBuilder.openIdCredentialIssuer, policy: policy
        )
        guard !candidates.isEmpty else {
            return Self.failure(.invalidIdentifier(identifier), IssuerMetadataDiagnostics(identifier: identifier))
        }

        // The two layouts coincide for an identifier with no path, in which case the single URL is
        // the spec form and is reported as such.
        let insertionURL = WellKnownURLBuilder.insertionForm(
            identifier, wellKnown: WellKnownURLBuilder.openIdCredentialIssuer
        )
        var mostInformative: DiscoveryError?

        for (index, url) in candidates.enumerated() {
            let form: WellKnownForm = url == insertionURL ? .insertion : .suffix
            do {
                let document = try await MetadataFetcher.fetch(
                    url: url, tag: "issuer-metadata", policy: policy,
                    supportsSignedMetadata: signedMetadataVerifier.supportsSignedMetadata,
                    session: session
                )
                let body = try await payload(of: document, identifier: identifier)
                let json = try Self.jsonObject(body)
                let parser = try selectParser(json)
                let configuration = try validator.validate(
                    parser.parse(body), specVersion: parser.specVersion,
                    expectedIdentifier: identifier, policy: policy
                )

                if form == .suffix {
                    debugPrint("### Issuer metadata came from the non-spec suffix URL: \(url)")
                }
                return DiscoveredIssuerMetadata(
                    configuration: configuration,
                    diagnostics: IssuerMetadataDiagnostics(
                        identifier: identifier,
                        attemptedURLs: Array(candidates.prefix(index + 1)),
                        resolvedURL: url,
                        form: form,
                        contentType: document.contentType,
                        specVersion: parser.specVersion
                    )
                )
            } catch let error as DiscoveryError {
                mostInformative = DiscoveryError.mostInformative(mostInformative, error)
            } catch {
                mostInformative = DiscoveryError.mostInformative(
                    mostInformative, .malformed("The issuer configuration could not be read")
                )
            }
        }

        return Self.failure(
            mostInformative ?? .fetchFailed(status: nil, detail: nil),
            IssuerMetadataDiagnostics(identifier: identifier, attemptedURLs: candidates)
        )
    }

    /// A signed document reaches the verifier; anything else is used as-is.
    ///
    /// The JWT check is on shape as well as media type: a JWT served as `application/json` must
    /// still be verified, never decoded and trusted.
    private func payload(of document: MetadataDocument, identifier: String) async throws -> Data {
        if document.isJWTMediaType || MetadataFetcher.looksLikeJWT(document.body) {
            let jwt = String(data: document.body, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return try await signedMetadataVerifier.verify(jwt: jwt, expectedIssuerIdentifier: identifier)
        }
        if policy.requireJSONContentType, !document.isJSONMediaType {
            throw DiscoveryError.notJSON(contentType: document.contentType)
        }
        return document.body
    }

    private static func jsonObject(_ body: Data) throws -> [String: Any] {
        guard let object = try? JSONSerialization.jsonObject(with: body),
              let json = object as? [String: Any]
        else {
            throw DiscoveryError.malformed("The issuer configuration was not valid JSON")
        }
        return json
    }

    private func selectParser(_ json: [String: Any]) throws -> IssuerMetadataParser {
        let parser = parsers.first { candidate in
            if candidate.specVersion == .draft, !policy.allowDraftMetadata { return false }
            return candidate.supports(json)
        }
        guard let parser else {
            throw DiscoveryError.malformed("This address did not return a recognisable issuer configuration")
        }
        return parser
    }

    private static func failure(
        _ error: DiscoveryError, _ diagnostics: IssuerMetadataDiagnostics
    ) -> DiscoveredIssuerMetadata {
        DiscoveredIssuerMetadata(
            configuration: IssuerWellKnownConfiguration(
                from: EUDIError(from: ErrorResponse(message: error.errorDescription, code: error.httpStatus))
            ),
            diagnostics: diagnostics
        )
    }

    /// OpenID4VCI 1.0 first; everything below the marker is deletable as a block.
    static func defaultParsers() -> [IssuerMetadataParser] {
        [
            OpenId4VciV1IssuerMetadataParser(),
            // --- legacy, safe to delete together ---
            DraftIssuerMetadataParser(),
        ]
    }
}
