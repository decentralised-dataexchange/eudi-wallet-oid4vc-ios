//
//  PresentationQueryMatcher.swift
//  eudiWalletOidcIos
//

import Foundation

/// Picks the matcher for the request's query language and runs it. Ordered, OpenID4VP 1.0 first.
struct PresentationQueryMatcher {

    let matchers: [CredentialMatcher]

    init(matchers: [CredentialMatcher] = Self.defaultMatchers()) {
        self.matchers = matchers
    }

    func match(_ request: PresentationRequest, _ credentials: [String?]) async -> CredentialMatches {
        guard let query = PresentationQuery.from(request) else {
            debugPrint("PresentationQueryMatcher: the request carries neither dcql_query nor presentation_definition")
            return .none
        }
        return await match(query, credentials)
    }

    func match(_ query: PresentationQuery, _ credentials: [String?]) async -> CredentialMatches {
        guard let matcher = matchers.first(where: { $0.supports(query) }) else { return .none }
        let matches = await matcher.match(query, credentials)
        debugPrint("PresentationQueryMatcher: matched \(matches.entries.filter(\.isSatisfied).count) of \(matches.entries.count) entries, satisfiable=\(matches.satisfiable)")
        return matches
    }

    static func defaultMatchers() -> [CredentialMatcher] {
        [
            DcqlCredentialMatcher(),
            // --- legacy, safe to delete as a block ---
            PresentationDefinitionCredentialMatcher(),
        ]
    }
}
