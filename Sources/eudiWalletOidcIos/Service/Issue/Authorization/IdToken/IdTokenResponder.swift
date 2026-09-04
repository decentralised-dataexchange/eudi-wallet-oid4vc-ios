//
//  IdTokenResponder.swift
//
//  Answering an authorization server that asked for an ID token.
//

import Foundation

/// Answers an authorization server that asked for an ID token rather than authorizing directly.
///
/// A thin seam over `IssueService.processAuthorisationRequestUsingIdToken`, which builds and signs
/// the token. The token itself is built exactly as before -- this exists so the in-app transport can
/// reach it without depending on the whole service, and so it can be substituted in tests.
///
/// Mirrors `IdTokenResponder` in the Android SDK.
protocol IdTokenResponding {
    /// - Returns: the redirect the server answered with, or `nil` when it did not accept the token.
    func respond(
        wallet: WalletIdentity,
        authConfig: AuthorisationServerWellKnownConfiguration,
        location: String
    ) async -> String?
}

struct IdTokenResponder: IdTokenResponding {

    /// The service that builds and signs the token. Injected rather than constructed here: it owns
    /// the key handler, and the signing logic stays in one place.
    let service: IssueService

    func respond(
        wallet: WalletIdentity,
        authConfig: AuthorisationServerWellKnownConfiguration,
        location: String
    ) async -> String? {
        // The audience is the request's own client_id; the nonce is echoed back.
        let redirectURI = (AuthorizationURI.queryParameter(location, "redirect_uri") ?? "")
            .replacingOccurrences(of: "\n", with: "")
            .trimmingCharacters(in: .whitespaces)
        let nonce = AuthorizationURI.queryParameter(location, "nonce") ?? ""
        let state = AuthorizationURI.queryParameter(location, "state") ?? ""
        let clientID = AuthorizationURI.queryParameter(location, "client_id") ?? ""

        return await service.processAuthorisationRequestUsingIdToken(
            did: wallet.did,
            authServerWellKnownConfig: authConfig,
            redirectURI: redirectURI,
            nonce: nonce,
            state: state,
            clientID: clientID
        )
    }
}
