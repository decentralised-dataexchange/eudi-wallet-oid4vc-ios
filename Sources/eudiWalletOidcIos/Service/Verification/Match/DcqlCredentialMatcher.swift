//
//  DcqlCredentialMatcher.swift
//  eudiWalletOidcIos
//

import Foundation

/// OpenID4VP 1.0 section 6: one `CredentialMatch` per credential query, then the credential sets.
///
/// Section 6.4.2: "Credentials not matching the respective constraints expressed within
/// credentials MUST NOT be returned, i.e., they are treated as if they would not exist in the
/// Wallet." A credential is a candidate for a query when its format and metadata match, it
/// satisfies the claims (section 6.4.1), it carries holder binding when required (section 6.1),
/// and it matches a trusted authority when any are given (section 6.1.1).
struct DcqlCredentialMatcher: CredentialMatcher {

    func supports(_ query: PresentationQuery) -> Bool {
        if case .dcql = query { return true }
        return false
    }

    func match(_ query: PresentationQuery, _ credentials: [String?]) async -> CredentialMatches {
        guard case .dcql(let dcql) = query else { return .none }
        let candidates = credentials.compactMap(CandidateCredential.decode)
        let required = requiredEntryIds(dcql)

        var entries: [CredentialMatch] = []
        for credentialQuery in dcql.credentials {
            var matched: [CredentialCandidate] = []
            for candidate in candidates {
                if let match = await candidateFor(credentialQuery, candidate) { matched.append(match) }
            }
            entries.append(CredentialMatch(
                entry: QueryEntry(id: credentialQuery.id, format: credentialQuery.format,
                                  required: required?.contains(credentialQuery.id) ?? true,
                                  multiple: credentialQuery.multiple ?? false),
                candidates: matched))
        }
        let unsatisfied = unsatisfiedRequirements(dcql, entries)
        return CredentialMatches(entries: entries, satisfiable: unsatisfied.isEmpty, unsatisfied: unsatisfied)
    }

    private func candidateFor(_ query: CredentialItems, _ candidate: CandidateCredential) async -> CredentialCandidate? {
        guard candidate.accepts(query.format), metadataMatches(query, candidate) else { return nil }
        if query.requireCryptographicHolderBinding ?? true, !candidate.holderBound { return nil }
        guard let claims = selectClaims(query, candidate) else { return nil }
        if let authorities = query.trustedAuthorities, !authorities.isEmpty,
           !(await TrustedAuthorityMatcher.matches(candidate, authorities)) {
            return nil
        }
        return CredentialCandidate(credential: candidate.raw, claims: claims)
    }

    /// Appendix B: `vct_values` for SD-JWT VC, `doctype_value` for mdoc, `type_values` for W3C VC.
    private func metadataMatches(_ query: CredentialItems, _ candidate: CandidateCredential) -> Bool {
        switch (candidate.format, query.meta) {
        case (.sdJwt, .dcSDJWT(let meta)):
            guard !meta.vctValues.isEmpty else { return true }
            return (ClaimsPathPointer.select(candidate.json, ["vct"])?.first as? String).map(meta.vctValues.contains) ?? false
        case (.mdoc, .msoMdoc(let meta)):
            return meta.doctypeValue.isEmpty || candidate.docType == meta.doctypeValue
        case (.jwtVc, .jwt(let meta)):
            guard !meta.typeValues.isEmpty else { return true }
            let selected = ClaimsPathPointer.select(candidate.json, ["type"])?.first
            let types = (selected as? [String]) ?? [selected as? String].compactMap { $0 }
            return meta.typeValues.contains { option in option.allSatisfy(types.contains) }
        default:
            return false
        }
    }

    /// Section 6.4.1. Nil when the credential cannot satisfy the query; otherwise the claims to
    /// disclose: every claim, or the first claim set option the credential satisfies, or none when
    /// the verifier asked for none.
    private func selectClaims(_ query: CredentialItems, _ candidate: CandidateCredential) -> [[String?]]? {
        let claims = query.claims ?? []
        if claims.isEmpty { return [] }

        guard let claimSets = query.claimSets, !claimSets.isEmpty else {
            var paths: [[String?]] = []
            for claim in claims {
                let path = pathOf(claim)
                guard satisfies(claim, path, candidate) else { return nil }
                paths.append(path)
            }
            return paths
        }
        var byId: [String: Claim] = [:]
        for claim in claims {
            if case .pathClaim(let pathClaim) = claim, let id = pathClaim.id { byId[id] = claim }
        }
        // Section 6.4.1: "the Wallet SHOULD return the first option that it can satisfy. If the
        // Wallet cannot satisfy any of the options, it MUST NOT return any claims."
        optionLoop: for option in claimSets {
            let selected = option.compactMap { byId[$0] }
            if selected.isEmpty || selected.count != option.count { continue }
            var paths: [[String?]] = []
            for claim in selected {
                let path = pathOf(claim)
                guard satisfies(claim, path, candidate) else { continue optionLoop }
                paths.append(path)
            }
            return paths
        }
        return nil
    }

    private func pathOf(_ claim: Claim) -> [String?] {
        switch claim {
        case .pathClaim(let pathClaim): return pathClaim.path
        // Draft mdoc shape: namespace and claim_name instead of a path.
        case .namespacedClaim(let namespaced): return [namespaced.namespace, namespaced.claimName]
        }
    }

    private func satisfies(_ claim: Claim, _ path: [String?], _ candidate: CandidateCredential) -> Bool {
        if path.isEmpty { return false }
        var selected = ClaimsPathPointer.select(candidate.json, path)
        if selected == nil, candidate.format == .jwtVc {
            // W3C VCs keep subject claims under credentialSubject; the drafts addressed them without it.
            selected = ClaimsPathPointer.select(candidate.json, ["credentialSubject"] + path)
        }
        guard let values = selected else { return false }
        // Section 6.3: the claim is returned only when its type and value match one of `values`.
        guard case .pathClaim(let pathClaim) = claim, let expected = pathClaim.values, !expected.isEmpty else { return true }
        return values.contains { ClaimsPathPointer.matches($0, expected) }
    }

    /// Section 6.4.2: with credential_sets, only the entries named in a required set are
    /// required. Nil means every entry is required because there are no sets.
    private func requiredEntryIds(_ dcql: DCQLQuery) -> Set<String>? {
        guard let sets = dcql.credentialSets else { return nil }
        return Set(sets.filter { $0.required ?? true }.flatMap { $0.options.flatMap { $0 } })
    }

    private func unsatisfiedRequirements(_ dcql: DCQLQuery, _ entries: [CredentialMatch]) -> [String] {
        let satisfied = Set(entries.filter(\.isSatisfied).map(\.entry.id))
        guard let sets = dcql.credentialSets else {
            return entries.filter { !$0.isSatisfied }.map(\.entry.id)
        }
        let unmet = sets.enumerated().compactMap { index, set -> String? in
            guard set.required ?? true else { return nil }
            let met = set.options.contains { option in !option.isEmpty && option.allSatisfy(satisfied.contains) }
            return met ? nil : "credential_sets[\(index)]"
        }
        if !unmet.isEmpty { debugPrint("DcqlCredentialMatcher: required credential sets not satisfiable: \(unmet)") }
        return unmet
    }
}
