//
//  CredentialSubject.swift
//

import Foundation

/// Which credential is being asked for.
///
/// OpenID4VCI 1.0 section 8.2 gives two ways to name it and forbids using both:
///
///  - `credential_identifier` is "REQUIRED when an Authorization Details of type
///    `openid_credential` was returned from the Token Response. It MUST NOT be used otherwise",
///    and "when this parameter is used, the `credential_configuration_id` MUST NOT be present";
///  - `credential_configuration_id` is "REQUIRED if a `credential_identifiers` parameter was not
///    returned from the Token Response", with the mirror-image exclusion.
///
/// An enum makes that exclusion unrepresentable. The previous implementation chose between five
/// `if`/`else` branches over the same optional fields, where nothing stopped both being set.
///
/// Note that **1.0 has no `format` parameter in the credential request** -- the format follows from
/// the configuration. ``legacyFormat(format:types:credentialDefinitionTypes:vct:docType:offerCredential:)``
/// exists only for the pre-1.0 drafts and EBSI, and is the single case to delete when draft support
/// goes.
///
/// Mirrors `CredentialSubject` in the Android SDK.
public enum CredentialSubject {

    /// The token response returned `credential_identifiers`; section 8.2 requires this form.
    case byIdentifier(credentialIdentifier: String, offerCredential: Credential? = nil)

    /// No `credential_identifiers` came back, so the configuration id names the credential.
    case byConfiguration(credentialConfigurationId: String, offerCredential: Credential? = nil)

    /// Pre-1.0 drafts and EBSI: `format` plus whichever of `types`, `vct` or `doctype` that
    /// revision used.
    ///
    /// - Parameter credentialDefinitionTypes: carried as `credential_definition.type`.
    /// - Parameter types: carried at the top level, the EBSI draft shape.
    case legacyFormat(
        format: String?,
        types: [String]? = nil,
        credentialDefinitionTypes: [String]? = nil,
        vct: String? = nil,
        docType: String? = nil,
        offerCredential: Credential? = nil
    )

    /// The offer entry this request is for.
    ///
    /// Carried rather than looked up. The previous implementation took `credentialTypes: [String]`
    /// and read `.first` in one branch and `.last` in another, with nothing explaining why -- and
    /// the proof read `.last` again to decide the binding method. Naming the credential by
    /// position in a parallel array is the mistake; what identifies it across the offer, the token
    /// response's `authorization_details` and the issuer metadata is its configuration id.
    ///
    /// `nil` when the caller has no offer entry (a re-issuance, say). The proof then falls back to
    /// a `jwk` header rather than guessing at a binding method.
    public var offerCredential: Credential? {
        switch self {
        case let .byIdentifier(_, credential): return credential
        case let .byConfiguration(_, credential): return credential
        case let .legacyFormat(_, _, _, _, _, credential): return credential
        }
    }

    /// The configuration id this subject names, for metadata lookups.
    var configurationId: String? {
        switch self {
        case let .byConfiguration(id, _): return id
        case let .byIdentifier(id, _): return id
        case let .legacyFormat(_, types, definitionTypes, _, _, _):
            return types?.first ?? definitionTypes?.first
        }
    }

    /// Whether the issuer's metadata makes the plural `proofs` object the right shape for this
    /// credential (section 8.2). Public because it is a property of the *issuer*, not of this
    /// SDK's internals, and a host that has to explain a rejected request needs it.
    public func sendsPluralProofs(in session: IssuanceSession) -> Bool {
        CredentialRequestParameters.declaresProofTypes(session: session, subject: self)
    }

    /// One line naming which of section 8.2's forms this is, for logs and bug reports.
    public var describedForLog: String {
        switch self {
        case let .byIdentifier(id, _): return "credential_identifier=\(id)"
        case let .byConfiguration(id, _): return "credential_configuration_id=\(id)"
        case let .legacyFormat(format, _, _, vct, docType, _):
            return "format=\(format ?? "-") vct=\(vct ?? "-") doctype=\(docType ?? "-")"
        }
    }
}

public extension CredentialSubject {

    /// Which form section 8.2 requires for `credential`, given what the token response returned.
    ///
    /// The rule is the specification's, so it belongs here rather than in every caller:
    ///
    ///  - `credential_identifier` is "REQUIRED when an Authorization Details of type
    ///    `openid_credential` was returned from the Token Response";
    ///  - `credential_configuration_id` is "REQUIRED if a `credential_identifiers` parameter was
    ///    not returned";
    ///  - and drafts, which predate both, name the credential by `format` plus their own type field.
    ///
    /// The 1.0-versus-draft test is whether the issuer publishes a nonce endpoint. That is a proxy
    /// rather than a version field, and a deliberate one: an earlier gate on "the token response
    /// carried no c_nonce" excluded issuers that publish a nonce endpoint *and* return a c_nonce
    /// with the token -- BankID does both -- and they reject the draft body with "Invalid request
    /// format".
    static func of(
        session: IssuanceSession,
        token: TokenResponse,
        credential: Credential?
    ) -> CredentialSubject {
        let details = (token.authorizationDetails ?? []).filter { $0.type == openIdCredential }

        // Only take a detail that names *this* credential. Falling back to the first one when
        // nothing matched sends another credential's `credential_identifier`, which the issuer
        // answers with an error or a 500 -- and only for the credentials after the first, so it
        // looks like one bad credential rather than a bad rule. A single detail is unambiguous and
        // is the one-credential case.
        let detail = details.first { matches($0, credential) } ?? (details.count == 1 ? details.first : nil)
        if detail == nil, details.count > 1 {
            debugPrint("""
                no authorization_details entry names \(credential?.types?.first ?? "-"); \
                naming it by configuration id instead of borrowing \
                \(details.first?.credentialConfigId ?? "-")
                """)
        }

        if let identifier = detail?.credentialIdentifiers?.first, !identifier.isEmpty {
            return .byIdentifier(credentialIdentifier: identifier, offerCredential: credential)
        }

        let publishesNonceEndpoint = session.issuerConfig?.nonceEndPoint?.isEmpty == false
        if publishesNonceEndpoint {
            let configurationId = detail?.credentialConfigId.flatMap { $0.isEmpty ? nil : $0 }
                ?? credential?.types?.first.flatMap { $0.isEmpty ? nil : $0 }
            if let configurationId {
                return .byConfiguration(
                    credentialConfigurationId: configurationId,
                    offerCredential: credential
                )
            }
        }

        return legacyFor(session: session, credential: credential)
    }

    /// The pre-1.0 shapes, chosen the way the old `params` chain chose them.
    ///
    /// Reads `credentialsSupported.dataSharing` directly rather than through `IssueService`'s
    /// `getFormatFromIssuerConfig` / `getTypesFromIssuerConfig`, which do exactly this lookup but
    /// are instance methods on a type that requires a `SecureKeyProtocol` -- a key handler is not
    /// needed to read metadata.
    private static func legacyFor(
        session: IssuanceSession,
        credential: Credential?
    ) -> CredentialSubject {
        let issuerConfig = session.issuerConfig
        let types = credential?.types ?? credential?.doctype.map { [$0] } ?? []
        let configuration = issuerConfig?.credentialsSupported?.dataSharing?[types.last ?? ""]
        let format = configuration?.format ?? "jwt_vc"

        if format == msoMdoc {
            return .legacyFormat(
                format: format,
                docType: credential?.doctype ?? types.last,
                offerCredential: credential
            )
        }

        // `version == "v1"` is the EBSI-era metadata that carries types at the top level; anything
        // else names them under `credential_definition`, or by `vct` for the SD-JWT formats.
        if issuerConfig?.credentialsSupported?.version == "v1" {
            return .legacyFormat(format: format, types: types, offerCredential: credential)
        }

        if format == "vc+sd-jwt" || format == "dc+sd-jwt" {
            let vct = configuration?.credentialDefinition?.vct ?? configuration?.vct
            if let vct, !vct.isEmpty {
                return .legacyFormat(format: format, vct: vct, offerCredential: credential)
            }
        }

        return .legacyFormat(
            format: format,
            credentialDefinitionTypes: configuration?.credentialDefinition?.type ?? types,
            offerCredential: credential
        )
    }

    /// Whether an authorization detail names this offer entry.
    private static func matches(_ detail: AuthorizationDetails, _ credential: Credential?) -> Bool {
        guard let type = credential?.types?.first else { return false }
        return detail.credentialConfigId == type
            || detail.credentialIdentifiers?.contains(type) == true
    }

    private static var openIdCredential: String { "openid_credential" }
    private static var msoMdoc: String { "mso_mdoc" }
}
