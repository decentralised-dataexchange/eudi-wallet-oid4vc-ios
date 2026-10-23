//
//  ClientIdentifierHandler.swift
//  eudiWalletOidcIos
//

import Foundation

/// The processing rules of one client identifier prefix (OpenID4VP 1.0 section 5.9.3).
///
/// A handler either establishes the verifier's identity and returns it, or throws
/// `PresentationRequestError.clientNotVerified` saying which rule the request broke. The request
/// is `inout` because a prefix can complete it: `redirect_uri` fills in the missing URI.
protocol ClientIdentifierHandler {

    /// The prefixes this handler implements.
    var prefixes: Set<ClientIdPrefix> { get }

    /// False when the wallet should not advertise the prefix under `policy`, for example because
    /// it lacks the trust material to verify it.
    func supported(_ policy: PresentationRequestPolicy) -> Bool

    func verify(_ request: inout PresentationRequest, _ identifier: ClientIdentifier,
                policy: PresentationRequestPolicy) async throws -> VerifierIdentity
}

extension ClientIdentifierHandler {

    func supported(_ policy: PresentationRequestPolicy) -> Bool { true }

    /// The signed request object every authenticating prefix requires.
    func signedRequestObject(_ request: PresentationRequest, _ prefix: ClientIdPrefix) throws -> String {
        let name = prefix.value ?? ""
        guard let jwt = request.request?.trimmingCharacters(in: .whitespacesAndNewlines),
              RequestObjectParser.looksLikeJwt(jwt) else {
            throw PresentationRequestError.clientNotVerified("the \(name) prefix requires a signed request object and the request carries none")
        }
        if RequestObjectParser.isUnsigned(jwt) {
            throw PresentationRequestError.clientNotVerified("the \(name) prefix requires a signed request object")
        }
        return jwt
    }
}
