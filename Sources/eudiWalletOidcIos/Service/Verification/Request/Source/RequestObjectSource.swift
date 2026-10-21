//
//  RequestObjectSource.swift
//  eudiWalletOidcIos
//

import Foundation

/// The request object travels by value.
///
/// Two shapes: RFC 9101 section 5.1, `?client_id=...&request=<JWT>`, and a bare JWT scanned on its
/// own with no URI around it. The bare form is not in OpenID4VP 1.0 and is kept for the verifiers
/// that still print it (EWC RFC002 section 3.1.3).
struct RequestObjectSource: PresentationRequestSource {

    let name = "request"

    private static let param = "request"

    func supports(_ data: String) -> Bool {
        AuthorizationRequestURI.hasQueryParam(data, Self.param) || RequestObjectParser.looksLikeJwt(data)
    }

    func retrieve(_ data: String, policy: PresentationRequestPolicy) async throws -> PresentationRequest {
        if let byParameter = AuthorizationRequestURI.queryParam(data, Self.param) {
            guard RequestObjectParser.looksLikeJwt(byParameter) else {
                throw PresentationRequestError.malformed("Invalid Request")
            }
            let request = try RequestObjectParser.parse(byParameter)
            try RequestObjectParser.requireMatchingClientId(AuthorizationRequestURI.queryParam(data, "client_id"), request)
            return request
        }
        return try RequestObjectParser.parse(data)
    }
}
