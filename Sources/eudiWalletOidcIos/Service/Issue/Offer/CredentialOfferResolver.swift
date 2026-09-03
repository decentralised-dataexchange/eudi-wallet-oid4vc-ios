//
//  CredentialOfferResolver.swift
//  eudiWalletOidcIos
//

import Foundation

/// Resolves scanned data into a credential offer: pick a source, retrieve the document, pick a
/// parser, validate.
///
/// Both registries are ordered, and OpenID4VCI 1.0 always comes first. Legacy entries are grouped
/// so draft support can be removed as a block.
///
/// Every failure returns a `CredentialOffer` carrying an `error` -- never a bare `nil`. Callers
/// previously could not distinguish "not an offer" from "malformed offer" from "network failure",
/// and had nothing to show the user for any of them.
public struct CredentialOfferResolver {

    private let policy: CredentialOfferPolicy
    private let validator: CredentialOfferValidator
    private let sources: [CredentialOfferSource]
    private let parsers: [CredentialOfferParser]

    public init(policy: CredentialOfferPolicy = .standard, session: URLSession = .shared) {
        self.policy = policy
        self.validator = CredentialOfferValidator()
        self.sources = Self.defaultSources(session: session)
        self.parsers = Self.defaultParsers()
    }

    init(
        policy: CredentialOfferPolicy,
        validator: CredentialOfferValidator = CredentialOfferValidator(),
        sources: [CredentialOfferSource],
        parsers: [CredentialOfferParser] = CredentialOfferResolver.defaultParsers()
    ) {
        self.policy = policy
        self.validator = validator
        self.sources = sources
        self.parsers = parsers
    }

    public func resolve(_ data: String?) async -> CredentialOffer {
        guard let data, !data.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return Self.failure(.noOffer)
        }

        do {
            let document = try await retrieve(data)
            let json = try Self.jsonObject(from: document)
            let parser = try selectParser(json)
            return try validator.validate(parser.parse(document), specVersion: parser.specVersion)
        } catch let error as CredentialOfferError {
            return Self.failure(error)
        } catch {
            // Nothing above should throw anything else; if it does, the user still gets a message.
            return Self.failure(.malformed("The credential offer could not be read"))
        }
    }

    private func retrieve(_ data: String) async throws -> Data {
        let matching = sources.filter { $0.supports(data) }

        // The specification forbids carrying both credential_offer and credential_offer_uri.
        if matching.count > 1, policy.rejectAmbiguousOffers {
            throw CredentialOfferError.ambiguousOffer
        }
        guard let source = matching.first else { throw CredentialOfferError.noOffer }
        return try await source.retrieve(data, policy: policy)
    }

    private static func jsonObject(from document: Data) throws -> [String: Any] {
        if looksLikeJWT(document) { throw CredentialOfferError.signedOfferRejected }

        guard let object = try? JSONSerialization.jsonObject(with: document),
              let json = object as? [String: Any]
        else {
            throw CredentialOfferError.malformed("The credential offer is not valid JSON")
        }
        return json
    }

    private func selectParser(_ json: [String: Any]) throws -> CredentialOfferParser {
        let parser = parsers.first { candidate in
            if candidate.specVersion == .draft, !policy.allowDraftOffers { return false }
            return candidate.supports(json)
        }
        guard let parser else {
            throw CredentialOfferError.malformed("This credential offer is not in a supported format")
        }
        return parser
    }

    /// Three dot-separated base64url segments, i.e. a compact JWS.
    ///
    /// Section 4.1.3: "The Credential Offer cannot be signed and MUST NOT use application/jwt with
    /// `alg`: `none`."
    private static func looksLikeJWT(_ document: Data) -> Bool {
        guard let text = String(data: document, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty
        else { return false }
        if text.hasPrefix("{") || text.hasPrefix("[") { return false }

        let parts = text.components(separatedBy: ".")
        guard parts.count == 3 else { return false }
        return parts.allSatisfy { part in
            !part.isEmpty && part.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
        }
    }

    private static func failure(_ error: CredentialOfferError) -> CredentialOffer {
        CredentialOffer(
            fromError: EUDIError(
                from: ErrorResponse(message: error.errorDescription, code: error.httpStatus)
            )
        )
    }

    /// Ordered: 1.0 mechanisms first, legacy last.
    static func defaultSources(session: URLSession = .shared) -> [CredentialOfferSource] {
        [
            InlineCredentialOfferSource(),
            RemoteCredentialOfferSource(session: session),
            // --- legacy, safe to delete as a block ---
            InitiateIssuanceOfferSource(),
        ]
    }

    /// Ordered: 1.0 first, so a draft parser only sees what 1.0 declined.
    static func defaultParsers() -> [CredentialOfferParser] {
        [
            OpenId4VciV1OfferParser(),
            // --- legacy, safe to delete as a block ---
            EbsiDraftOfferParser(),
            EwcDraftOfferParser(),
        ]
    }
}
