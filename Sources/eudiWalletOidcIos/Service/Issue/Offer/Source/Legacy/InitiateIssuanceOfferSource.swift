//
//  InitiateIssuanceOfferSource.swift
//  eudiWalletOidcIos
//

import Foundation

/// LEGACY -- pre-OpenID4VCI. The EBSI "initiate issuance" link, which spreads the offer across
/// query parameters instead of carrying a JSON document:
///
/// `openid://initiate_issuance?issuer=...&credential_type=...&pre-authorized_code=...&user_pin_required=true`
///
/// Rewritten here into a draft-shaped offer document so the rest of the pipeline is unaware of it.
/// Delete this file and its registry entry to drop support.
struct InitiateIssuanceOfferSource: CredentialOfferSource {

    let name = "initiate_issuance"

    private enum Parameter {
        static let marker = "initiate_issuance"
        static let issuer = "issuer"
        static let credentialType = "credential_type"
        static let preAuthorizedCode = "pre-authorized_code"
        static let userPinRequired = "user_pin_required"
        static let issuerState = "issuer_state"
        static let preAuthorizedGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }

    func supports(_ data: String) -> Bool {
        guard data.lowercased().contains(Parameter.marker) else { return false }
        let issuer = OfferURI.queryParameter(Parameter.issuer, in: data)
        return !(issuer ?? "").isEmpty
    }

    func retrieve(_ data: String, policy: CredentialOfferPolicy) async throws -> Data {
        guard let issuer = OfferURI.queryParameter(Parameter.issuer, in: data), !issuer.isEmpty else {
            throw CredentialOfferError.noOffer
        }

        var offer: [String: Any] = ["credential_issuer": issuer]

        let types = (OfferURI.queryParameter(Parameter.credentialType, in: data) ?? "")
            .split(separator: " ")
            .map(String.init)
            .filter { !$0.isEmpty }
        offer["credentials"] = types

        var grants: [String: Any] = [:]
        if let code = OfferURI.queryParameter(Parameter.preAuthorizedCode, in: data), !code.isEmpty {
            grants[Parameter.preAuthorizedGrant] = [
                "pre-authorized_code": code,
                "user_pin_required": (OfferURI.queryParameter(Parameter.userPinRequired, in: data) ?? "") == "true",
            ]
        }
        if let state = OfferURI.queryParameter(Parameter.issuerState, in: data), !state.isEmpty {
            grants["authorization_code"] = ["issuer_state": state]
        }
        if !grants.isEmpty { offer["grants"] = grants }

        do {
            return try JSONSerialization.data(withJSONObject: offer)
        } catch {
            throw CredentialOfferError.malformed("The credential offer link could not be read")
        }
    }
}
