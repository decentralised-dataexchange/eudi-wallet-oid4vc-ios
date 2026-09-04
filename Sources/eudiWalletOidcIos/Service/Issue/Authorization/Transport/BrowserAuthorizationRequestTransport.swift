//
//  BrowserAuthorizationRequestTransport.swift
//

import Foundation

/// The plain authorization request: build the URL and hand it to a browser.
///
/// The default, and the last transport consulted. RFC 8252: for a scanned offer the browser must
/// make the request so the authorization server's session cookie lands there -- interactive servers
/// such as BankID depend on it.
struct BrowserAuthorizationRequestTransport: AuthorizationRequestTransport {

    let kind: AuthorizationTransportKind = .browser
    let name = "browser"

    func endpoint(for session: IssuanceSession) -> String? {
        session.authConfig?.authorizationEndpoint
    }

    /// The fallback: always applicable, so it is placed last in the registry.
    func supports(
        session: IssuanceSession,
        mode: AuthorizationMode,
        policy: AuthorizationRequestPolicy
    ) -> Bool { true }

    func perform(
        parameters: AuthorizationRequestParameters,
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation?,
        mode: AuthorizationMode,
        urlSession: URLSession
    ) async throws -> AuthorizationResponse {
        guard let endpoint = session.authConfig?.authorizationEndpoint else {
            throw AuthorizationError.noAuthorizationEndpoint
        }
        return .openInBrowser(url: parameters.appended(to: endpoint))
    }
}
