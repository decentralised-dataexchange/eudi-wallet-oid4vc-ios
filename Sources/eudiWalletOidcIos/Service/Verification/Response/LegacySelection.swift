//
//  LegacySelection.swift
//  eudiWalletOidcIos
//

import Foundation

/// The previous API's contract: credentials and key ids arrive as lists aligned by position with
/// the query's entries. Turned into `SelectedCredential`s named by entry id, once, here.
enum LegacySelection {

    /// Nil when the groups cannot be mapped onto the DCQL query, which the previous API answered
    /// with an empty response. Blank credentials are left out; a missing key id falls back to the
    /// holder key. Under a presentation definition only the first credential of each group counts,
    /// as before.
    static func from(_ request: PresentationRequest, groups: [[String]]?, keyIds: [[String]]) -> [SelectedCredential]? {
        let entryIds: [String]
        if let queries = request.dcqlQuery?.credentials {
            guard let groups, queries.count == groups.count else { return nil }
            entryIds = queries.map { $0.id }
        } else {
            let definition = try? VerificationService.processPresentationDefinition(request.presentationDefinition)
            entryIds = definition?.inputDescriptors?.map { $0.id ?? "" } ?? []
        }
        var selected: [SelectedCredential] = []
        for (entryIndex, group) in (groups ?? []).enumerated() {
            let ids = entryIndex < keyIds.count ? keyIds[entryIndex] : []
            let credentials = request.dcqlQuery == nil ? Array(group.prefix(1)) : group
            for (position, credential) in credentials.enumerated()
            where !credential.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                selected.append(SelectedCredential(entryId: entryIndex < entryIds.count ? entryIds[entryIndex] : "",
                                                   credential: credential,
                                                   keyId: position < ids.count ? ids[position] : nil))
            }
        }
        return selected
    }
}
