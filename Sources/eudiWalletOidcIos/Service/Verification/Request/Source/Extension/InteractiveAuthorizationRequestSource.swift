//
//  InteractiveAuthorizationRequestSource.swift
//  eudiWalletOidcIos
//

import Foundation

/// EXTENSION, not part of OpenID4VP 1.0: the interactive authorization request of the EWC
/// issuance profile, where an issuer asks for a presentation in the middle of issuance.
///
/// The presentation request arrives as `?openid4vp_request=<JSON>` next to `auth_session` and
/// `type`. The JSON may itself carry a `request` object, whose payload then replaces the outer
/// parameters except for `client_id`, which stays the issuer's.
struct InteractiveAuthorizationRequestSource: PresentationRequestSource {

    let name = "openid4vp_request"

    private static let param = "openid4vp_request"

    func supports(_ data: String) -> Bool {
        AuthorizationRequestURI.hasQueryParam(data, Self.param)
    }

    func retrieve(_ data: String, policy: PresentationRequestPolicy) async throws -> PresentationRequest {
        guard let openid4vpRequest = AuthorizationRequestURI.queryParam(data, Self.param), !openid4vpRequest.isEmpty,
              var request = try? JSONDecoder().decode(PresentationRequest.self, from: Data(openid4vpRequest.utf8)) else {
            throw PresentationRequestError.malformed("Invalid Request")
        }
        let issuerClientId = request.clientId ?? ""
        // PresentationRequest's decoder does not read `request`, so it comes from the raw JSON.
        let raw = (try? JSONSerialization.jsonObject(with: Data(openid4vpRequest.utf8))) as? [String: Any]
        let requestObject = raw?["request"] as? String ?? ""
        if RequestObjectParser.looksLikeJwt(requestObject) {
            // An unreadable inner object leaves the outer parameters in force.
            request = (try? RequestObjectParser.parse(requestObject)) ?? request
        }
        request.authSession = AuthorizationRequestURI.queryParam(data, "auth_session") ?? ""
        request.type = AuthorizationRequestURI.queryParam(data, "type") ?? ""
        // The issuer's client id, without the redirect_uri prefix, as this path has always sent it.
        request.clientId = issuerClientId.replacingOccurrences(of: "redirect_uri:", with: "")
        // The scheme the decoder took from the inner object's client_id describes the verifier, not
        // the issuer client id above; left in place it would steer the client identifier check.
        request.clientIDScheme = nil
        request.request = requestObject
        return request
    }
}
