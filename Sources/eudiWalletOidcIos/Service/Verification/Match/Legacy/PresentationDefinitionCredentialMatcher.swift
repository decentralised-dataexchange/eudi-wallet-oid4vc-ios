//
//  PresentationDefinitionCredentialMatcher.swift
//  eudiWalletOidcIos
//

import Foundation

/// LEGACY, Presentation Exchange from the OpenID4VP drafts: one entry per input descriptor,
/// matched by `PresentationDefinitionFiltering` as before. Submission requirements are not
/// evaluated, so every descriptor counts as required. Delete with the rest of `Legacy/`.
///
/// Nil and blank credentials are dropped before filtering. The filter reports matches by index
/// and skips nil entries while converting, so a nil in the list used to shift every later index
/// and return the wrong credential.
struct PresentationDefinitionCredentialMatcher: CredentialMatcher {

    func supports(_ query: PresentationQuery) -> Bool {
        if case .presentationDefinition = query { return true }
        return false
    }

    func match(_ query: PresentationQuery, _ credentials: [String?]) async -> CredentialMatches {
        guard case .presentationDefinition(let definition) = query else { return .none }
        let present = credentials.compactMap { $0 }.filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        let perDescriptor = PresentationDefinitionFiltering.filterCredentialUsingPresentationDefinition(
            presentationDefinition: definition, credentialList: present)

        let entries = (definition.inputDescriptors ?? []).enumerated().map { index, descriptor -> CredentialMatch in
            let format = (descriptor.format?.keys.first) ?? definition.format?.keys.first
            let matched = index < perDescriptor.count ? perDescriptor[index] : []
            return CredentialMatch(
                entry: QueryEntry(id: descriptor.id ?? "", format: format, purpose: descriptor.purpose),
                candidates: matched.compactMap { $0.index < present.count ? CredentialCandidate(credential: present[$0.index]) : nil })
        }
        let unsatisfied = entries.filter { !$0.isSatisfied }.map(\.entry.id)
        return CredentialMatches(entries: entries, satisfiable: unsatisfied.isEmpty, unsatisfied: unsatisfied)
    }
}
