//
//  AuthorizationResponseEncoder.swift
//  eudiWalletOidcIos
//

import Foundation

/// The form fields a response mode wants: the parameters, a JWE in `response`, or the interactive
/// authorization wrapping.
struct AuthorizationResponseEncoder {

    var encrypter = ResponseEncrypter()

    /// - Throws: `SubmissionError`
    func encode(_ mode: ResponseMode, _ response: AuthorizationResponseParameters, _ request: PresentationRequest) async throws -> [String: String] {
        switch mode {
        case .directPost, .dcApi:
            return response.formFields
        case .directPostJWT, .dcApiJWT:
            return ["response": try await encrypter.encrypt(response.parameters, request)]
        case .iarPost:
            return ["auth_session": request.authSession ?? "",
                    "openid4vp_presentation": AuthorizationResponseParameters.json(response.formFields) ?? ""]
        case .iarPostJWT:
            let jwe = try await encrypter.encrypt(response.parameters, request)
            return ["auth_session": request.authSession ?? "",
                    "openid4vp_presentation": AuthorizationResponseParameters.json(["response": jwe]) ?? ""]
        case .unsupported(let raw):
            throw SubmissionError.unsupportedResponseMode(raw)
        }
    }
}
