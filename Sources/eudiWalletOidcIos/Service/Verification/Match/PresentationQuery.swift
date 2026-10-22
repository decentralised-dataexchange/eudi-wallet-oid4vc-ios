//
//  PresentationQuery.swift
//  eudiWalletOidcIos
//

import Foundation

/// What the verifier is asking for, in one of the two query languages a request can carry.
///
/// OpenID4VP 1.0 defines only `dcql`. `presentationDefinition` is Presentation Exchange from the
/// drafts and is kept for the verifiers still sending it.
public enum PresentationQuery {

    case dcql(DCQLQuery)

    case presentationDefinition(PresentationDefinitionModel)

    /// The request's query, DCQL first. Nil when the request carries neither.
    public static func from(_ request: PresentationRequest) -> PresentationQuery? {
        if let dcql = request.dcqlQuery { return .dcql(dcql) }
        if let text = request.presentationDefinition, !text.isEmpty,
           let definition = try? VerificationService.processPresentationDefinition(text) {
            return .presentationDefinition(definition)
        }
        return nil
    }
}
