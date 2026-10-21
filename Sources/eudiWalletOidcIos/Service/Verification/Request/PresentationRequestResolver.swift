//
//  PresentationRequestResolver.swift
//  eudiWalletOidcIos
//

import Foundation

/// Resolves scanned data into a presentation request: pick a source, retrieve the parameters,
/// validate the query, dereference the draft URIs.
///
/// The registry is ordered and OpenID4VP 1.0 comes first. Legacy entries are grouped so draft
/// support can be removed as a block. Every failure is a `PresentationRequestOutcome.failed`
/// carrying a description a user can read, never a bare nil.
///
/// Every source funnels through `complete`, so a rule that applies to all of them, such as the
/// DCQL validation and the client identifier check, is written once.
struct PresentationRequestResolver {

    let policy: PresentationRequestPolicy
    let sources: [PresentationRequestSource]
    let presentationDefinitionUriResolver: PresentationDefinitionUriResolver
    let clientMetadataUriResolver: ClientMetadataUriResolver
    let clientIdentifierVerifier: ClientIdentifierVerifier

    init(policy: PresentationRequestPolicy = .default, session: URLSession = .shared,
         sources: [PresentationRequestSource]? = nil,
         clientIdentifierVerifier: ClientIdentifierVerifier = ClientIdentifierVerifier()) {
        self.policy = policy
        self.sources = sources ?? Self.defaultSources(session: session)
        self.presentationDefinitionUriResolver = PresentationDefinitionUriResolver(session: session)
        self.clientMetadataUriResolver = ClientMetadataUriResolver(session: session)
        self.clientIdentifierVerifier = clientIdentifierVerifier
    }

    /// Ordered: OpenID4VP 1.0 mechanisms first, the issuance profile extension last.
    static func defaultSources(session: URLSession) -> [PresentationRequestSource] {
        [
            InlinePresentationRequestSource(),
            RemotePresentationRequestSource(session: session),
            RequestObjectSource(),
            // --- extension: EWC interactive authorization request ---
            InteractiveAuthorizationRequestSource(),
        ]
    }

    func resolve(_ data: String?) async -> PresentationRequestOutcome {
        switch await resolveTyped(data) {
        case .success(let resolved):
            return .resolved(resolved)
        case .failure(let error):
            debugPrint("PresentationRequestResolver: presentation request rejected: \(error.message)")
            return .failed(error.eudiError)
        }
    }

    /// `resolve` with the failure still typed, for the deprecated adapter, which answers some
    /// failures with no error at all.
    func resolveTyped(_ data: String?) async -> Result<ResolvedPresentationRequest, PresentationRequestError> {
        guard let data, !data.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return .failure(.noRequest)
        }
        do {
            let source = try select(data)
            let request = try await source.retrieve(data, policy: policy)
            return .success(try await complete(request, source: source))
        } catch let error as PresentationRequestError {
            return .failure(error)
        } catch {
            // Nothing above should throw anything else; if it does, the user still gets a message.
            debugPrint("PresentationRequestResolver: unexpected failure resolving a presentation request: \(error)")
            return .failure(.malformed("Invalid Request"))
        }
    }

    private func select(_ data: String) throws -> PresentationRequestSource {
        // RFC 9101 section 5: "If [request] is present in the authorization request, request_uri
        // MUST NOT be present", and the reverse. Section 10.7 explains why: two copies of the
        // parameters invite a mismatch attack.
        if policy.rejectAmbiguousRequests,
           AuthorizationRequestURI.hasValue(data, "request"),
           AuthorizationRequestURI.hasValue(data, "request_uri") {
            throw PresentationRequestError.ambiguousRequest
        }
        guard let source = sources.first(where: { $0.supports(data) }) else {
            throw PresentationRequestError.noRequest
        }
        return source
    }

    private func complete(_ request: PresentationRequest, source: PresentationRequestSource) async throws -> ResolvedPresentationRequest {
        var request = request
        // A DCQL query that breaks OpenID4VP 1.0 is refused once, here, before any URI is
        // resolved or any stored credential is read.
        if let decodingError = request.dcqlQueryDecodingError {
            throw PresentationRequestError.invalidDcqlQuery(decodingError)
        }
        if let dcql = request.dcqlQuery {
            let violations = DcqlQueryValidator.validate(dcql)
            if !violations.isEmpty {
                throw PresentationRequestError.invalidDcqlQuery(violations.joined(separator: "; "))
            }
        }

        let hasPresentationDefinition = !Self.isBlank(request.presentationDefinition)
            || !Self.isBlank(request.presentationDefinitionUri)
        let specVersion: PresentationRequestSpecVersion =
            request.dcqlQuery == nil && hasPresentationDefinition ? .draft : .v1_0

        if specVersion == .v1_0 && hasPresentationDefinition {
            // 1.0 defines only dcql_query. A verifier sending both gets the 1.0 answer.
            debugPrint("PresentationRequestResolver: request carries both dcql_query and presentation_definition; the presentation definition is ignored")
            request.presentationDefinition = nil
            request.presentationDefinitionUri = nil
        }
        if specVersion == .draft && !policy.allowDraftRequests {
            throw PresentationRequestError.draftNotAllowed
        }

        // --- legacy, safe to delete as a block ---
        if Self.isBlank(request.presentationDefinition), let uri = request.presentationDefinitionUri, !Self.isBlank(uri) {
            request.presentationDefinition = try await presentationDefinitionUriResolver.resolve(uri)
        }
        if Self.isBlank(request.clientMetaData), let uri = request.clientMetaDataUri, !Self.isBlank(uri) {
            if policy.allowDraftRequests {
                request.clientMetaData = await clientMetadataUriResolver.resolve(uri)
            } else {
                debugPrint("PresentationRequestResolver: client_metadata_uri ignored: draft parameters are not allowed by the policy")
            }
        }
        // --- end legacy ---

        // Section 5.9: who the verifier is, by the rules of its client identifier prefix.
        let verifier = try await clientIdentifierVerifier.verify(&request, policy: policy)

        debugPrint("PresentationRequestResolver: resolved a \(specVersion) presentation request from \(source.name)")
        return ResolvedPresentationRequest(request: request, specVersion: specVersion, source: source.name, verifier: verifier)
    }

    private static func isBlank(_ value: String?) -> Bool {
        value?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true
    }
}
