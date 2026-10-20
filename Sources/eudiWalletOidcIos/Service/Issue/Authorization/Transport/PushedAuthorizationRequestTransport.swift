//
//  PushedAuthorizationRequestTransport.swift
//

import Foundation

/// Pushed Authorization Requests, RFC 9126.
///
/// OpenID4VCI 1.0 section 5: "When the grant type authorization_code is used, it is RECOMMENDED to
/// use PKCE [RFC7636] and Pushed Authorization Requests [RFC9126]." Used when the authorization
/// server sets `require_pushed_authorization_requests`.
///
/// The parameters are POSTed to the PAR endpoint, which answers with a `request_uri`; the
/// authorization request then carries only `client_id` and that `request_uri`.
struct PushedAuthorizationRequestTransport: AuthorizationRequestTransport {

    let kind: AuthorizationTransportKind = .pushed
    let name = "pushed_authorization_request"

    /// The PAR endpoint, not the authorization endpoint: that is where the request is POSTed.
    func endpoint(for session: IssuanceSession) -> String? {
        session.authConfig?.pushedAuthorizationRequestEndpoint
    }

    func supports(
        session: IssuanceSession,
        mode: AuthorizationMode,
        policy: AuthorizationRequestPolicy
    ) -> Bool {
        session.authConfig?.requirePushedAuthorizationRequests == true
    }

    func perform(
        parameters: AuthorizationRequestParameters,
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation?,
        mode: AuthorizationMode,
        urlSession: URLSession
    ) async throws -> AuthorizationResponse {
        guard let authorizationEndpoint = session.authConfig?.authorizationEndpoint else {
            throw AuthorizationError.noAuthorizationEndpoint
        }
        guard let request = HTTPCall.formPost(
            url: session.authConfig?.pushedAuthorizationRequestEndpoint ?? "",
            parameters: parameters.asDictionary(),
            attestation: attestation
        ) else {
            throw AuthorizationError.unusable("This issuer's pushed authorization endpoint is not a usable URL")
        }

        let result = try await HTTPCall.send(request, tag: "par-request", session: urlSession, onTransportFailure: authorizationTransportFailure)

        guard result.isSuccessful else {
            // The Date header is the server's own clock -- compare it with the proof-of-possession
            // `iat` when a rejection looks like clock skew.
            debugPrint("PAR rejected status=\(result.status) serverDate=\(result.header("Date") ?? "-")")
            throw AuthorizationError.rejected(
                status: result.status,
                body: result.data,
                contentType: result.contentType
            )
        }

        let json = (try? JSONSerialization.jsonObject(with: result.data)) as? [String: Any]
        guard let requestURI = json?["request_uri"] as? String, !requestURI.isEmpty else {
            throw AuthorizationError.unusable(
                "The authorization server returned no request_uri",
                status: result.status
            )
        }

        // RFC 9126 section 2.2: how long the request_uri stays usable. Received all along and never
        // read, so the caller could not tell a fresh hand-off from an expired one.
        let expiresIn = json?["expires_in"] as? Int

        let authorizationURL = AuthorizationURI.appending(
            ["client_id": parameters.clientId, "request_uri": requestURI],
            to: authorizationEndpoint
        )

        if mode == .browser {
            return .openInBrowser(url: authorizationURL, expiresIn: expiresIn)
        }

        // In-app: follow the authorization endpoint ourselves rather than handing it to a browser.
        return try await follow(
            authorizationURL: authorizationURL,
            expiresIn: expiresIn,
            urlSession: urlSession
        )
    }

    /// The follow-up to a PAR reads a response in its own way -- a 302 `Location` is returned
    /// verbatim, an HTML body means the final request URL is the answer -- so it is deliberately not
    /// shared with ``InAppAuthorizationRequestTransport``.
    private func follow(
        authorizationURL: String,
        expiresIn: Int?,
        urlSession: URLSession
    ) async throws -> AuthorizationResponse {
        guard let url = URL(string: authorizationURL) else {
            throw AuthorizationError.unusable("The authorization URL could not be constructed")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let result = try await HTTPCall.send(request, tag: "authorisation-request", session: urlSession, onTransportFailure: authorizationTransportFailure)

        if result.status == 302, let location = result.header("Location"), !location.isEmpty {
            return .openInBrowser(url: location, expiresIn: expiresIn)
        }
        if result.isSuccessful, result.contentType?.contains("text/html") == true {
            return .openInBrowser(url: authorizationURL, expiresIn: expiresIn)
        }
        if result.status >= 400 {
            throw AuthorizationError.rejected(
                status: result.status,
                body: result.data,
                contentType: result.contentType
            )
        }
        throw AuthorizationError.unusable(
            "The authorization server gave no redirect to continue with",
            status: result.status
        )
    }
}
