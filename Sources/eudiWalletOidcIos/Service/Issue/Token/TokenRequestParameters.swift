//
//  TokenRequestParameters.swift
//

import Foundation

/// The token request body, assembled once.
///
/// Blank values are **omitted rather than sent empty**, matching
/// ``AuthorizationRequestParameters``. The previous implementation sent `user_pin: ""` on the draft
/// branch whenever no code was supplied, which is not the same as not sending it.
struct TokenRequestParameters {
    let grant: TokenGrant
    let clientId: String?
    let txCodeParameterName: String
    let authorizationDetails: String?
    let resource: String?

    static let txCode = "tx_code"
    /// What the pre-1.0 drafts called it.
    static let userPin = "user_pin"

    /// The body as it goes on the wire, blanks omitted.
    func asDictionary() -> [String: String] {
        var out: [String: String] = ["grant_type": grant.grantType]

        switch grant {
        case let .preAuthorized(code, txCode):
            out["pre-authorized_code"] = code
            // Section 6.1: client authentication is OPTIONAL for this grant, and the previous
            // implementation sent no client_id here. Unchanged.
            if let txCode, !txCode.isEmpty { out[txCodeParameterName] = txCode }

        case let .authorizationCode(code, codeVerifier, redirectUri):
            out["code"] = code
            if let codeVerifier, !codeVerifier.isEmpty { out["code_verifier"] = codeVerifier }
            if let redirectUri, !redirectUri.isEmpty { out["redirect_uri"] = redirectUri }
            if let clientId, !clientId.isEmpty { out["client_id"] = clientId }
        }

        if let authorizationDetails, !authorizationDetails.isEmpty {
            out["authorization_details"] = authorizationDetails
        }
        if let resource, !resource.isEmpty { out["resource"] = resource }
        return out
    }

    static func build(
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation?,
        grant: TokenGrant,
        authorizationDetails: String? = nil,
        policy: TokenRequestPolicy = .standard
    ) -> TokenRequestParameters {
        TokenRequestParameters(
            grant: grant,
            // The same rule the authorization request uses: the wallet unit identifier from the
            // attestation, falling back to the DID (RFC 6749 section 4.1.3 -- the two legs agree).
            clientId: IssueService.clientId(
                wua: attestation?.attestationJwt ?? "",
                fallbackDid: wallet.did
            ),
            // 1.0 calls it tx_code; the pre-1.0 drafts called it user_pin.
            txCodeParameterName: session.credentialOffer?.version == "v1" ? userPin : txCode,
            authorizationDetails: policy.sendAuthorizationDetails ? authorizationDetails : nil,
            resource: resource(for: session, policy: policy)
        )
    }

    /// Set only when the issuer metadata declares the plural `authorization_servers` -- the same
    /// condition sections 5.1.2 and 6.1 attach to it.
    private static func resource(
        for session: IssuanceSession,
        policy: TokenRequestPolicy
    ) -> String? {
        guard policy.sendResourceParameter else { return nil }
        guard session.issuerConfig?.declaresAuthorizationServers == true else { return nil }
        return session.credentialOffer?.credentialIssuer ?? session.issuerConfig?.credentialIssuer
    }
}
