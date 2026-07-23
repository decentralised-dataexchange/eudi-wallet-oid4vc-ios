//
//  ServerTrustMechanismModels.swift
//  eudiWalletOidcIos
//
//  Codable payload models for the OWS Trust List backend (open lookup endpoint) used by
//  `ServerTrustMechanismService`. iOS counterpart of the Android SDK's TrustList models.
//
//  Endpoint: POST {baseURL}/trust-list/lookup  -> lookup by x5c / kid / did / jwksUri.
//

import Foundation

/// Lookup body — send the identifier the verifier/issuer is known by. Exactly one is populated.
public struct TrustListLookupRequest: Codable {
    public var x5c: [String]?
    public var kid: String?
    public var did: String?
    public var jwksUri: String?

    public init(x5c: [String]? = nil, kid: String? = nil, did: String? = nil, jwksUri: String? = nil) {
        self.x5c = x5c
        self.kid = kid
        self.did = did
        self.jwksUri = jwksUri
    }
}

/// Status of a matched trust-list service. Only `.granted` is trusted; everything else — including
/// a status we cannot parse — is refused (fail-closed).
///
/// The raw value is an ETSI URI whose last path segment carries the meaning, e.g.
/// `https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted/`. Scheme (http/https), letter case
/// and the trailing slash all vary between trust lists, so only that last segment is compared.
public enum TrustServiceStatus: String {
    case granted
    /// The WRPAC provider lists (`…/19602/WRPACProvidersList/SvcStatus/notified`) use `notified`
    /// where the ETSI trusted lists use `granted`. Treated as granted-equivalent — see `isTrusted`.
    case notified
    case withdrawn
    case unknown

    /// Only these statuses are trusted; anything else, including an unparseable value, is refused.
    public var isTrusted: Bool { self == .granted || self == .notified }

    public static func from(_ rawValue: String?) -> TrustServiceStatus {
        guard let raw = rawValue?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
              !raw.isEmpty else {
            return .unknown
        }
        let segment = raw.split(separator: "/").last.map(String.init) ?? raw
        return TrustServiceStatus(rawValue: segment) ?? .unknown
    }
}

/// The credential a trust check is about, used against a service's permitted / prohibited lists.
/// `vct` applies to SD-JWT VCs, `doctype` to mdoc.
public struct TrustCredentialDescriptor: Equatable {
    public let format: String?
    public let vct: String?
    public let doctype: String?

    public init(format: String?, vct: String? = nil, doctype: String? = nil) {
        self.format = format
        self.vct = vct
        self.doctype = doctype
    }

    public var debugDescription: String { "\(format ?? "-")/\(vct ?? doctype ?? "?")" }

    /// True when neither the type nor the format is known — the rules cannot be evaluated.
    public var isEmpty: Bool {
        (format?.isEmpty ?? true) && (vct?.isEmpty ?? true) && (doctype?.isEmpty ?? true)
    }
}

/// Outcome of applying a service's permitted / prohibited credential lists.
public enum TrustCredentialDecision: Equatable {
    case allowed
    case prohibited(TrustCredentialType)
    case notPermitted(allowList: [TrustCredentialType])
    /// The service carries rules but the credential could not be identified, so they were skipped.
    case notEvaluated
}

/// Applies a service's `permittedCredentials` (allow-list) and `prohibitedCredentials` (deny-list)
/// to the credential in play.
///
/// Rules, in order:
/// 1. prohibited is non-empty and the credential matches one → refused
/// 2. permitted is non-empty and the credential matches none → refused
/// 3. otherwise allowed (both lists empty ⇒ no credential restriction)
public enum TrustCredentialRules {

    /// What to do when the credential cannot be identified but the service carries rules.
    /// `false` (current) = skip the check and log loudly; `true` = fail closed.
    public static var denyWhenCredentialUnknown = false

    public static func evaluate(_ descriptor: TrustCredentialDescriptor?,
                                permitted: [TrustCredentialType],
                                prohibited: [TrustCredentialType]) -> TrustCredentialDecision {
        guard !permitted.isEmpty || !prohibited.isEmpty else { return .allowed }

        guard let descriptor = descriptor, !descriptor.isEmpty else {
            return denyWhenCredentialUnknown ? .notPermitted(allowList: permitted) : .notEvaluated
        }

        if let hit = prohibited.first(where: { matches(descriptor, $0) }) {
            return .prohibited(hit)
        }
        if !permitted.isEmpty, !permitted.contains(where: { matches(descriptor, $0) }) {
            return .notPermitted(allowList: permitted)
        }
        return .allowed
    }

    /// A rule matches when the formats agree AND, if the rule names a `vct`/`doctype`, that agrees
    /// too. A rule with only a format matches every credential of that format.
    static func matches(_ descriptor: TrustCredentialDescriptor, _ rule: TrustCredentialType) -> Bool {
        if let ruleFormat = normalise(rule.format), let credentialFormat = normalise(descriptor.format),
           ruleFormat != credentialFormat {
            return false
        }
        if let ruleVct = nonEmpty(rule.vct) {
            return nonEmpty(descriptor.vct)?.caseInsensitiveCompare(ruleVct) == .orderedSame
        }
        if let ruleDoctype = nonEmpty(rule.doctype) {
            return nonEmpty(descriptor.doctype)?.caseInsensitiveCompare(ruleDoctype) == .orderedSame
        }
        // Format-only rule: it matched above (or neither side declared a format).
        return rule.format != nil
    }

    /// `dc+sd-jwt` and `vc+sd-jwt` are the new and old names of the same format; a rule written for
    /// one must apply to a credential labelled the other, otherwise a PID prohibition silently fails.
    private static func normalise(_ format: String?) -> String? {
        guard let format = nonEmpty(format)?.lowercased() else { return nil }
        switch format {
        case "dc+sd-jwt", "vc+sd-jwt", "sd-jwt", "sd_jwt", "vc+sd-jwt-vc": return "sd-jwt"
        case "mso_mdoc", "mso-mdoc", "mdoc": return "mso_mdoc"
        default: return format
        }
    }

    private static func nonEmpty(_ value: String?) -> String? {
        guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else { return nil }
        return value
    }
}

public struct TrustListLookupResponse: Codable {
    public let match: Bool
    /// Current response shape: every trust-list service the identifier matched.
    public let entries: [TrustListEntry]?
    /// Legacy response shape: a single matched entry. Kept so an older backend still decodes.
    public let entry: TrustListEntry?

    /// All matched entries, whichever shape the backend returned — including withdrawn ones.
    /// Use `grantedEntries` for any trust decision.
    public var matchedEntries: [TrustListEntry] {
        if let entries = entries, !entries.isEmpty { return entries }
        return [entry].compactMap { $0 }
    }

    /// Matched entries whose service status is `granted`. An identifier can be granted in one trust
    /// list and withdrawn in another, so this filters per entry rather than rejecting the response.
    public var grantedEntries: [TrustListEntry] {
        matchedEntries.filter { $0.serviceStatus.isTrusted }
    }
}

public struct TrustListEntry: Codable {
    public let status: String?
    public let provider: TrustListProvider?
    public let service: TrustListServiceInfo?
    public let matchType: String?
    public let searchValue: String?
    public let certificateValid: Bool?
    public let certificateDetails: [TrustListCertDetail]?
    public let matchedCertIndex: Int?
    /// The specific trust list this entry matched — used to filter against DCQL `trusted_authorities`.
    public let trustList: TrustListInfo?
    /// Allow-list: when non-empty, ONLY these credential types may be issued/requested by this service.
    public let permittedCredentials: TrustCredentialList?
    /// Deny-list: a credential matching any of these is refused even if the role and status are fine.
    public let prohibitedCredentials: TrustCredentialList?

    /// Status of this entry's service. Reads the service-level `serviceStatus` URI, falling back to
    /// the entry-level `status`; `.unknown` when neither is present or parseable.
    public var serviceStatus: TrustServiceStatus {
        let fromService = TrustServiceStatus.from(service?.serviceStatus)
        return fromService == .unknown ? TrustServiceStatus.from(status) : fromService
    }
}

/// One credential type in a service's permitted / prohibited list, e.g.
/// `{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"}` or
/// `{"format": "mso_mdoc", "doctype": "eu.europa.ec.eudi.pid.1"}`.
public struct TrustCredentialType: Codable, Equatable {
    public let format: String?
    public let vct: String?
    public let doctype: String?

    public init(format: String?, vct: String? = nil, doctype: String? = nil) {
        self.format = format
        self.vct = vct
        self.doctype = doctype
    }

    /// Human-readable form for logs.
    public var debugDescription: String {
        "\(format ?? "-")/\(vct ?? doctype ?? "*")"
    }
}

/// Tolerant container for `permittedCredentials` / `prohibitedCredentials`.
///
/// These fields changed shape once already (an object with `category`/`issuesCredentials`, now a
/// list of credential types). Decoding them strictly would fail the WHOLE response — and a response
/// that fails to decode means every organisation is untrusted — so an unexpected shape decodes to
/// "no rules" instead of throwing.
public struct TrustCredentialList: Codable {
    public let items: [TrustCredentialType]

    public init(items: [TrustCredentialType] = []) { self.items = items }

    public init(from decoder: Decoder) throws {
        if let list = try? [TrustCredentialType](from: decoder) {
            items = list
        } else {
            items = []
        }
    }

    public func encode(to encoder: Encoder) throws { try items.encode(to: encoder) }
}

public struct TrustListInfo: Codable {
    public let name: String?
    public let url: String?
    public let schemeName: String?
}

public struct TrustListProvider: Codable {
    public let tSPName: String?
    public let tSPTradeName: String?
    public let streetAddress: String?
    public let locality: String?
    public let postalCode: String?
    public let countryName: String?
    public let electronicAddress: String?
    public let tSPInformationURI: String?
}

public struct TrustListServiceInfo: Codable {
    public let serviceTypeIdentifier: String?
    public let serviceStatus: String?
    public let statusStartingTime: String?
    public let serviceName: String?
    public let did: String?
    public let kid: String?
    public let jwksURI: String?
    /// Legacy: some responses may still return the cert chain here.
    public let digitalIdentity: [String]?
}

public struct TrustListCertDetail: Codable {
    public let subjectKeyIdentifier: String?
    public let sha256Fingerprint: String?
}
