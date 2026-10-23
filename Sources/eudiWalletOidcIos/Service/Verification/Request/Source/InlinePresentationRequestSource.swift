//
//  InlinePresentationRequestSource.swift
//  eudiWalletOidcIos
//

import Foundation

/// The parameters travel in the request URI itself: `?client_id=...&dcql_query=<JSON>&...`.
///
/// OpenID4VP 1.0 section 5. Recognised by the query parameter: `dcql_query` for 1.0, or the draft
/// `presentation_definition` and `presentation_definition_uri`, which the resolver quarantines.
/// Absent parameters are empty strings, as they have always been on this path.
struct InlinePresentationRequestSource: PresentationRequestSource {

    let name = "by_value"

    private static let queryParams = ["dcql_query", "presentation_definition", "presentation_definition_uri"]

    func supports(_ data: String) -> Bool {
        Self.queryParams.contains { !(AuthorizationRequestURI.queryParam(data, $0) ?? "").isEmpty }
    }

    func retrieve(_ data: String, policy: PresentationRequestPolicy) async throws -> PresentationRequest {
        func param(_ name: String) -> String { AuthorizationRequestURI.queryParam(data, name) ?? "" }

        var dcqlQuery: DCQLQuery? = nil
        let dcql = param("dcql_query")
        if !dcql.isEmpty {
            do {
                dcqlQuery = try JSONDecoder().decode(DCQLQuery.self, from: Data(dcql.utf8))
            } catch {
                // Malformed JSON, or a member of the wrong shape: refused the same way as a
                // structurally invalid query.
                throw PresentationRequestError.invalidDcqlQuery(DcqlQueryValidator.decodingMessage(error))
            }
        }

        // Section 5.1: a non-empty JSON array of base64url strings. An unreadable value is kept as
        // it is, so the transaction data check refuses it instead of it vanishing here.
        var transactionData: [String] = []
        let transactionDataParam = param("transaction_data")
        if !transactionDataParam.trimmingCharacters(in: .whitespaces).isEmpty {
            let array = (try? JSONSerialization.jsonObject(with: Data(transactionDataParam.utf8))) as? [Any]
            transactionData = array.map { $0.map { $0 as? String ?? "\($0)" } } ?? [transactionDataParam]
        }

        return PresentationRequest(state: param("state"),
                                   clientId: param("client_id"),
                                   redirectUri: param("redirect_uri"),
                                   responseUri: param("response_uri"),
                                   responseType: param("response_type"),
                                   responseMode: param("response_mode"),
                                   scope: param("scope"),
                                   nonce: param("nonce"),
                                   requestUri: param("request_uri"),
                                   presentationDefinition: param("presentation_definition"),
                                   clientMetaData: param("client_metadata"),
                                   presentationDefinitionUri: param("presentation_definition_uri"),
                                   clientMetaDataUri: param("client_metadata_uri"),
                                   clientIDScheme: param("client_id_scheme"),
                                   transactionData: transactionData,
                                   dcqlQuery: dcqlQuery,
                                   request: param("request"),
                                   authSession: param("auth_session"))
    }
}
