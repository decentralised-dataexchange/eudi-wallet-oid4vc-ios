//
//  InAppAuthorizationRequestTransport.swift
//

import Foundation

/// The wallet makes the authorization request itself and reads the redirect, rather than handing a
/// URL to a browser.
///
/// Used only for first-party, non-interactive flows -- the wallet-provider attestation bootstrap.
/// RFC 8252 is why it is not the default: a scanned offer must go through the browser so the
/// authorization server's session cookie lands there.
///
/// The interpretation of the redirect keeps the previous implementation's **order**, because
/// deployed servers are distinguished only by which case matches. What changed is that the cases
/// are now read as query parameters rather than as substrings of the whole URL (`contains("code=")`
/// also matched, for instance, a parameter merely *ending* in `code`), and that the first branch --
/// which returned code, error and presentation redirects as one undifferentiated string -- now
/// names which of the three it was.
struct InAppAuthorizationRequestTransport: AuthorizationRequestTransport {

    let kind: AuthorizationTransportKind = .inApp
    let name = "in_app"

    let idTokenResponder: IdTokenResponding

    func endpoint(for session: IssuanceSession) -> String? {
        session.authConfig?.authorizationEndpoint
    }

    func supports(
        session: IssuanceSession,
        mode: AuthorizationMode,
        policy: AuthorizationRequestPolicy
    ) -> Bool {
        mode == .inApp
    }

    func perform(
        parameters: AuthorizationRequestParameters,
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation?,
        mode: AuthorizationMode,
        urlSession: URLSession
    ) async throws -> AuthorizationResponse {
        guard let authConfig = session.authConfig,
              let authorizationEndpoint = authConfig.authorizationEndpoint else {
            throw AuthorizationError.noAuthorizationEndpoint
        }
        let authorizationURL = parameters.appended(to: authorizationEndpoint)
        guard let url = URL(string: authorizationURL) else {
            throw AuthorizationError.unusable("The authorization URL could not be constructed")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let location: String
        do {
            let result = try await AuthorizationHTTP.send(
                request, tag: "authorisation-request", session: urlSession
            )
            if result.status == 302, let header = result.header("Location") {
                location = header
            } else if result.status >= 400 {
                throw AuthorizationError.rejected(
                    status: result.status,
                    body: result.data,
                    contentType: result.contentType
                )
            } else if result.status == 200, result.contentType?.contains("text/html") == true {
                location = authorizationURL
            } else {
                location = String(data: result.data, encoding: .utf8) ?? ""
            }
        } catch let error as AuthorizationError {
            // Preserved: a redirect to a custom scheme fails the URL load, and the URL it failed on
            // IS the callback. Losing this would break the flows that end on `openid://callback`.
            if case let .requestFailed(_, failingURL) = error,
               let recovered = failingURL, !recovered.isEmpty {
                location = recovered
            } else {
                throw error
            }
        }

        guard !location.isEmpty else {
            throw AuthorizationError.unusable("The authorization server gave no redirect to continue with")
        }

        return try await interpret(
            location: location,
            parameters: parameters,
            wallet: wallet,
            authConfig: authConfig,
            answerIdToken: true
        )
    }

    /// Reads a redirect the authorization server sent.
    ///
    /// - Parameter answerIdToken: `false` when this redirect is itself the answer to an ID token we
    ///   just posted, so a server that asks twice cannot put us in a loop.
    private func interpret(
        location: String,
        parameters: AuthorizationRequestParameters,
        wallet: WalletIdentity,
        authConfig: AuthorisationServerWellKnownConfiguration,
        answerIdToken: Bool
    ) async throws -> AuthorizationResponse {
        func param(_ name: String) -> String? { AuthorizationURI.queryParameter(location, name) }

        if let error = param("error") {
            let description = param("error_description")
            return .failed(
                reason: description ?? error,
                errorCode: error,
                location: location
            )
        }

        if let code = param("code") {
            return .authorizationCode(code: code, state: param("state"), location: location)
        }

        let wantsPresentation = param("presentation_definition") != nil
            || param("presentation_definition_uri") != nil
            || (param("request_uri") != nil && param("response_type") == nil && param("state") == nil)
        if wantsPresentation {
            return .presentationRequired(url: location, authSession: param("auth_session"))
        }

        let asksForIdToken = param("response_type") == "id_token" && param("redirect_uri") != nil

        // A redirect away from our own redirect_uri is somewhere the user has to go -- but only when
        // the server has not explicitly asked for an ID token. This order is the previous
        // implementation's, and deployed servers are distinguished by it.
        if !asksForIdToken && !location.hasPrefix(parameters.redirectUri) {
            return .openInBrowser(url: location)
        }

        if !answerIdToken { return .idTokenRequired(url: location) }

        guard let next = await idTokenResponder.respond(
            wallet: wallet,
            authConfig: authConfig,
            location: location
        ) else {
            return .failed(reason: "The authorization server did not accept the wallet's identity token")
        }

        return try await interpret(
            location: next,
            parameters: parameters,
            wallet: wallet,
            authConfig: authConfig,
            answerIdToken: false
        )
    }
}
