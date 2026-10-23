//
//  CredentialMatch.swift
//  eudiWalletOidcIos
//

import Foundation

/// One row of the query the user picks a credential for: a DCQL credential query, or a
/// Presentation Exchange input descriptor. Identified by `id`, never by position.
public struct QueryEntry {

    /// The DCQL credential query `id` or the input descriptor `id`; the key of the response's `vp_token`.
    public let id: String

    /// The credential format identifier the entry asks for.
    public let format: String?

    /// False when the entry only appears in optional credential sets, or in none (section 6.4.2).
    public let required: Bool

    /// Section 6.1 `multiple`: whether more than one credential may be returned for this entry.
    public let multiple: Bool

    public let purpose: String?

    public init(id: String, format: String?, required: Bool = true, multiple: Bool = false, purpose: String? = nil) {
        self.id = id
        self.format = format
        self.required = required
        self.multiple = multiple
        self.purpose = purpose
    }
}

/// A stored credential that satisfies a `QueryEntry`.
public struct CredentialCandidate {

    /// The credential exactly as the host handed it in, so it can be looked up again.
    public let credential: String

    /// The claims path pointers to disclose: the claim set the wallet chose (section 6.4.1), or
    /// every requested claim when there are no claim sets. Empty means the verifier asked for no
    /// selectively disclosable claims and only the mandatory part is presented.
    public let claims: [[String?]]

    public init(credential: String, claims: [[String?]] = []) {
        self.credential = credential
        self.claims = claims
    }
}

public struct CredentialMatch {

    public let entry: QueryEntry

    public let candidates: [CredentialCandidate]

    public var isSatisfied: Bool { !candidates.isEmpty }

    public init(entry: QueryEntry, candidates: [CredentialCandidate]) {
        self.entry = entry
        self.candidates = candidates
    }
}

/// The answer to a presentation query over the wallet's credentials.
public struct CredentialMatches {

    /// One per query entry, in the verifier's order, each with its candidates.
    public let entries: [CredentialMatch]

    /// Section 6.4.2: every required entry, or every required credential set, has at least one
    /// candidate. When false the wallet should tell the user before any selection.
    public let satisfiable: Bool

    /// The ids of the required entries, or the indexes of the required credential sets, that
    /// nothing in the wallet satisfies.
    public let unsatisfied: [String]

    public init(entries: [CredentialMatch], satisfiable: Bool, unsatisfied: [String] = []) {
        self.entries = entries
        self.satisfiable = satisfiable
        self.unsatisfied = unsatisfied
    }

    public func candidatesFor(_ entryId: String) -> [CredentialCandidate] {
        entries.first { $0.entry.id == entryId }?.candidates ?? []
    }

    /// The shape of the previous API: candidate credentials per entry, in query order.
    public func asLegacyLists() -> [[String]] {
        entries.map { match in match.candidates.map(\.credential) }
    }

    /// A request with no query, or one no matcher understands.
    public static let none = CredentialMatches(entries: [], satisfiable: false)
}
