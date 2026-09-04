//
//  AuthorizationRequestParameters.swift
//
//  The authorization request parameters, assembled once.
//

import Foundation

/// The authorization request parameters, assembled once.
///
/// The four transports previously built the same set in four separate literal dictionaries, and
/// three of the four had already drifted. Blank values are **omitted rather than sent empty**:
/// `issuer_state ?? ""` used to put an empty parameter on every request that had no issuer state,
/// which some authorization servers reject.
///
/// Mirrors `AuthorizationRequestParameters` in the Android SDK.
struct AuthorizationRequestParameters {
    let responseType: String
    let scope: String
    let state: String
    let clientId: String
    let authorizationDetails: String
    let redirectUri: String
    let nonce: String
    let codeChallenge: String?
    let codeChallengeMethod: String
    let clientMetadata: String?
    let issuerState: String?
    let resource: String?

    static let defaultRedirectUri = "openid://callback"

    /// The parameters as they go on the wire, blanks omitted.
    func asDictionary() -> [String: String] {
        var out: [String: String] = [
            "response_type": responseType,
            "scope": scope,
            "state": state,
            "client_id": clientId,
            "authorization_details": authorizationDetails,
            "redirect_uri": redirectUri,
            "nonce": nonce,
        ]
        // Both or neither: a request carrying code_challenge_method with no code_challenge is a
        // malformed PKCE request (RFC 7636 section 4.3).
        if let codeChallenge, !codeChallenge.isEmpty {
            out["code_challenge"] = codeChallenge
            out["code_challenge_method"] = codeChallengeMethod
        }
        if let clientMetadata, !clientMetadata.isEmpty { out["client_metadata"] = clientMetadata }
        if let issuerState, !issuerState.isEmpty { out["issuer_state"] = issuerState }
        if let resource, !resource.isEmpty { out["resource"] = resource }
        return out
    }

    /// `endpoint` with these parameters as its query string.
    func appended(to endpoint: String) -> String {
        AuthorizationURI.appending(asDictionary().mapValues { Optional($0) }, to: endpoint)
    }

    /// Builds the parameters for one request.
    ///
    /// - Parameters:
    ///   - authorizationDetails: built by the caller, because it depends on the credential being
    ///     requested. See `IssueService.buildAuthorizationRequest`.
    static func build(
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation?,
        selection: CredentialSelection,
        authorizationDetails: String,
        codeVerifier: String,
        redirectUri: String?,
        policy: AuthorizationRequestPolicy
    ) -> AuthorizationRequestParameters {
        let redirect = redirectUri?.isEmpty == false ? redirectUri! : defaultRedirectUri
        let format = selection.format ?? ""

        // The mdoc scope is the doctype, space-separated from openid -- "mso_mdocopenid" (the
        // format glued onto openid) is not a scope any authorization server recognises.
        let baseScope: String
        if format == "mso_mdoc" {
            let mdocType = session.credentialOffer?.credentials?.first?.doctype ?? selection.docType ?? ""
            baseScope = "\(mdocType) openid".trimmingCharacters(in: .whitespaces)
        } else {
            baseScope = "openid"
        }
        let declaredScopes = policy.useCredentialScopes ? CredentialScopes.forOffer(session) : []
        var seenScopes = Set<String>()
        let scope = (declaredScopes + baseScope.split(separator: " ").map(String.init))
            .filter { !$0.isEmpty && seenScopes.insert($0).inserted }
            .joined(separator: " ")

        // Not sent for mso_mdoc, matching the previous implementation.
        var clientMetadata: String?
        if policy.sendClientMetadata && format != "mso_mdoc" {
            clientMetadata = ([
                "vp_formats_supported": [
                    "jwt_vp": ["alg": ["ES256"]],
                    "jwt_vc": ["alg": ["ES256"]],
                ],
                "response_types_supported": ["vp_token", "id_token"],
                "authorization_endpoint": redirect,
            ] as [String: Any]).toString()
        }

        return AuthorizationRequestParameters(
            responseType: "code",
            scope: scope,
            state: UUID().uuidString,
            clientId: IssueService.clientId(wua: attestation?.attestationJwt ?? "", fallbackDid: wallet.did),
            authorizationDetails: authorizationDetails,
            redirectUri: redirect,
            nonce: UUID().uuidString,
            codeChallenge: CodeVerifierService.shared.generateCodeChallenge(codeVerifier: codeVerifier),
            codeChallengeMethod: "S256",
            clientMetadata: clientMetadata,
            issuerState: session.issuerState,
            resource: resource(for: session, policy: policy)
        )
    }

    /// The `resource` value, set only when the issuer metadata declares the plural
    /// `authorization_servers` -- the same condition sections 5.1.2 and 6.1 attach to it, and the
    /// same one that governs the authorization detail's `locations`.
    private static func resource(
        for session: IssuanceSession,
        policy: AuthorizationRequestPolicy
    ) -> String? {
        guard policy.sendResourceParameter else { return nil }
        guard session.issuerConfig?.declaresAuthorizationServers == true else { return nil }
        return session.credentialOffer?.credentialIssuer ?? session.issuerConfig?.credentialIssuer
    }
}
