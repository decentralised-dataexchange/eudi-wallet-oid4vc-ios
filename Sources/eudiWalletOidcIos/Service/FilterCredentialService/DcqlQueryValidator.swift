import Foundation

/// Structural validation of a DCQL query against OpenID4VP 1.0, sections 6 and 7 and
/// Appendix B. It runs once on the parsed request, before any stored credential is read,
/// so a query that breaks the specification is refused instead of being matched on a
/// best-effort basis.
///
/// Only the shape of the query is checked here: required members, non-empty arrays, the
/// identifier character set, cross references between `claims` / `claim_sets` and
/// `credentials` / `credential_sets`, the format-specific `meta` members and the mdoc
/// two-component claim path. Whether the wallet holds matching credentials is decided
/// later by the filtering code. Unknown members are ignored by the decoder, as the
/// specification requires.
///
/// Some violations never reach this validator because `DCQLQuery` cannot represent them:
/// a missing or empty `meta`, a claim `values` entry that is not a string, integer or
/// boolean, or a path component that is not a string or null all fail at decode time.
/// `VerificationService` reports those through `decodingMessage(_:)` with the same error code.
public enum DcqlQueryValidator {

    private static let idPattern = try! NSRegularExpression(pattern: "^[A-Za-z0-9_-]+$")
    private static let formatSdJwt = "dc+sd-jwt"
    private static let formatMdoc = "mso_mdoc"
    private static let formatJwtVcJson = "jwt_vc_json"
    private static let formatLdpVc = "ldp_vc"
    private static let supportedFormats: Set<String> = [formatSdJwt, formatMdoc, formatJwtVcJson, formatLdpVc]
    private static let trustedAuthorityTypes: Set<String> = ["aki", "etsi_tl", "openid_federation"]

    /// - Returns: every violation found, in document order; an empty array means the query is valid.
    public static func validate(_ dcql: DCQLQuery?) -> [String] {
        var errors: [String] = []
        guard let dcql = dcql else {
            errors.append("dcql_query is missing")
            return errors
        }

        if dcql.credentials.isEmpty {
            errors.append("credentials must be a non-empty array")
            return errors
        }

        var credentialIds = Set<String>()
        for (index, credential) in dcql.credentials.enumerated() {
            validateCredentialQuery("credentials[\(index)]", credential, &credentialIds, &errors)
        }

        if let sets = dcql.credentialSets {
            if sets.isEmpty {
                errors.append("credential_sets must be a non-empty array when present")
            }
            for (index, set) in sets.enumerated() {
                validateCredentialSet("credential_sets[\(index)]", set, credentialIds, &errors)
            }
        }

        return errors
    }

    /// One line for a `dcql_query` that could not be decoded into `DCQLQuery`: the failing
    /// member's path and the decoder's explanation.
    public static func decodingMessage(_ error: Error) -> String {
        guard let decodingError = error as? DecodingError else { return error.localizedDescription }
        let context: DecodingError.Context
        switch decodingError {
        case .dataCorrupted(let c): context = c
        case .keyNotFound(_, let c): context = c
        case .typeMismatch(_, let c): context = c
        case .valueNotFound(_, let c): context = c
        @unknown default: return "\(decodingError)"
        }
        let path = context.codingPath
            .map { key in key.intValue.map { "[\($0)]" } ?? key.stringValue }
            .joined(separator: ".")
            .replacingOccurrences(of: ".[", with: "[")
        return path.isEmpty ? context.debugDescription : "\(path): \(context.debugDescription)"
    }

    private static func isValidId(_ id: String) -> Bool {
        idPattern.firstMatch(in: id, range: NSRange(id.startIndex..., in: id)) != nil
    }

    private static func validateCredentialQuery(
        _ prefix: String,
        _ credential: CredentialItems,
        _ credentialIds: inout Set<String>,
        _ errors: inout [String]
    ) {
        let id = credential.id
        if id.isEmpty {
            errors.append("\(prefix).id is required")
        } else if !isValidId(id) {
            errors.append("\(prefix).id must contain only letters, digits, '_' or '-'")
        } else if !credentialIds.insert(id).inserted {
            errors.append("\(prefix).id '\(id)' is not unique")
        }

        let format = credential.format
        if format.isEmpty {
            errors.append("\(prefix).format is required")
        } else if !supportedFormats.contains(format) {
            errors.append("\(prefix).format '\(format)' is not supported")
        }

        switch (format, credential.meta) {
        case (formatSdJwt, .dcSDJWT(let meta)):
            if meta.vctValues.isEmpty || meta.vctValues.contains(where: { $0.isBlank }) {
                errors.append("\(prefix).meta.vct_values must be a non-empty array of strings for \(formatSdJwt)")
            }
        case (formatSdJwt, _):
            errors.append("\(prefix).meta.vct_values must be a non-empty array of strings for \(formatSdJwt)")
        case (formatMdoc, .msoMdoc(let meta)):
            if meta.doctypeValue.isBlank {
                errors.append("\(prefix).meta.doctype_value is required for \(formatMdoc)")
            }
        case (formatMdoc, _):
            errors.append("\(prefix).meta.doctype_value is required for \(formatMdoc)")
        case (formatJwtVcJson, .jwt(let meta)), (formatLdpVc, .jwt(let meta)):
            if meta.typeValues.isEmpty || meta.typeValues.contains(where: { $0.isEmpty || $0.contains(where: { $0.isBlank }) }) {
                errors.append("\(prefix).meta.type_values must be a non-empty array of non-empty string arrays for \(format)")
            }
        case (formatJwtVcJson, _), (formatLdpVc, _):
            errors.append("\(prefix).meta.type_values must be a non-empty array of non-empty string arrays for \(format)")
        default:
            break
        }

        let claimSets = credential.claimSets
        var claimIds = Set<String>()
        if let claims = credential.claims {
            if claims.isEmpty {
                errors.append("\(prefix).claims must be a non-empty array when present")
            }
            for (index, claim) in claims.enumerated() {
                validateClaimsQuery("\(prefix).claims[\(index)]", claim, format, claimSets != nil, &claimIds, &errors)
            }
        }

        if let claimSets = claimSets {
            if credential.claims == nil {
                errors.append("\(prefix).claim_sets must not be present when claims is absent")
            } else if claimSets.isEmpty {
                errors.append("\(prefix).claim_sets must be a non-empty array when present")
            }
            for (index, set) in claimSets.enumerated() {
                if set.isEmpty {
                    errors.append("\(prefix).claim_sets[\(index)] must be a non-empty array")
                } else {
                    for unknown in set where !claimIds.contains(unknown) {
                        errors.append("\(prefix).claim_sets[\(index)] references unknown claim id '\(unknown)'")
                    }
                }
            }
        }

        if let authorities = credential.trustedAuthorities {
            if authorities.isEmpty {
                errors.append("\(prefix).trusted_authorities must be a non-empty array when present")
            }
            for (index, authority) in authorities.enumerated() {
                validateTrustedAuthority("\(prefix).trusted_authorities[\(index)]", authority, &errors)
            }
        }
    }

    private static func validateClaimsQuery(
        _ prefix: String,
        _ claim: Claim,
        _ format: String,
        _ claimSetsPresent: Bool,
        _ claimIds: inout Set<String>,
        _ errors: inout [String]
    ) {
        guard case .pathClaim(let pathClaim) = claim else {
            // The pre-1.0 namespace / claim_name shape carries no path.
            errors.append("\(prefix).path must be a non-empty array")
            return
        }

        if let id = pathClaim.id {
            if id.isBlank || !isValidId(id) {
                errors.append("\(prefix).id must contain only letters, digits, '_' or '-'")
            } else if !claimIds.insert(id).inserted {
                errors.append("\(prefix).id '\(id)' is not unique")
            }
        } else if claimSetsPresent {
            errors.append("\(prefix).id is required when claim_sets is present")
        }

        let path = pathClaim.path
        if path.isEmpty {
            errors.append("\(prefix).path must be a non-empty array")
        } else if format == formatMdoc && (path.count != 2 || path.contains(where: { $0?.isBlank ?? true })) {
            errors.append("\(prefix).path must have exactly two string components (namespace, element identifier) for \(formatMdoc)")
        }

        if let values = pathClaim.values, values.isEmpty {
            errors.append("\(prefix).values must be a non-empty array when present")
        }
    }

    private static func validateCredentialSet(
        _ prefix: String,
        _ set: CredentialSet,
        _ credentialIds: Set<String>,
        _ errors: inout [String]
    ) {
        if set.options.isEmpty {
            errors.append("\(prefix).options must be a non-empty array")
            return
        }
        for (index, option) in set.options.enumerated() {
            if option.isEmpty {
                errors.append("\(prefix).options[\(index)] must be a non-empty array")
            } else {
                for unknown in option where !credentialIds.contains(unknown) {
                    errors.append("\(prefix).options[\(index)] references unknown credential id '\(unknown)'")
                }
            }
        }
    }

    private static func validateTrustedAuthority(
        _ prefix: String,
        _ authority: TrustedAuthorities,
        _ errors: inout [String]
    ) {
        if let type = authority.type, !type.isBlank {
            if !trustedAuthorityTypes.contains(type) {
                errors.append("\(prefix).type '\(type)' is not supported")
            }
        } else {
            errors.append("\(prefix).type is required")
        }
        let values = authority.values ?? []
        if values.isEmpty || values.contains(where: { $0.isBlank }) {
            errors.append("\(prefix).values must be a non-empty array of strings")
        }
    }
}

private extension String {
    var isBlank: Bool { trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
}
