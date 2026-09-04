//
//  InteractiveAuthorizationTransport.swift
//
//  ** A PROFILE EXTENSION, NOT A SPECIFICATION FEATURE. **
//

import Foundation

/// Interactive Authorization Request (IAR) -- a profile extension.
///
/// `interactive_authorization_endpoint` appears in **no specification**: not OpenID4VCI, not
/// RFC 8414, not OpenID Connect Discovery. It is a profile extension, and it is required by iGrant
/// issuers, so it lives under `Extension/` rather than `Legacy/` -- `Legacy` in this SDK means
/// *deletable as a block*, and this is neither legacy nor optional.
///
/// How it works: the wallet POSTs the authorization parameters plus
/// `interaction_types_supported`, declaring what it can handle. The response carries a `type`:
///
/// - `openid4vp_presentation` -- the server wants a presentation mid-issuance (the BankID SUA
///   case). The wallet builds an authorization URL carrying `auth_session` and the embedded
///   `openid4vp_request`, with `client_id` rewritten to `iar:<endpoint>`.
/// - anything else -- the response carries a `request_uri` to continue with in a browser.
///
/// Nothing about its behaviour changes from the previous implementation.
struct InteractiveAuthorizationTransport: AuthorizationRequestTransport {

    let kind: AuthorizationTransportKind = .interactiveAuthorization
    let name = "interactive_authorization"

    /// What this wallet can be asked to do mid-authorization.
    private let interactionTypesSupported = "openid4vp_presentation,redirect_to_web"

    private let typePresentation = "openid4vp_presentation"
    private let typeRedirectToWeb = "redirect_to_web"

    /// The interactive endpoint, which is where the request is POSTed -- not `authorization_endpoint`.
    func endpoint(for session: IssuanceSession) -> String? {
        session.authConfig?.interactiveAuthorizationEndpoint
    }

    func supports(
        session: IssuanceSession,
        mode: AuthorizationMode,
        policy: AuthorizationRequestPolicy
    ) -> Bool {
        policy.allowInteractiveAuthorization
            && session.authConfig?.interactiveAuthorizationEndpoint?.isEmpty == false
    }

    func perform(
        parameters: AuthorizationRequestParameters,
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation?,
        mode: AuthorizationMode,
        urlSession: URLSession
    ) async throws -> AuthorizationResponse {
        let interactiveEndpoint = session.authConfig?.interactiveAuthorizationEndpoint ?? ""
        guard let authorizationEndpoint = session.authConfig?.authorizationEndpoint else {
            throw AuthorizationError.noAuthorizationEndpoint
        }

        var body = parameters.asDictionary()
        body["interaction_types_supported"] = interactionTypesSupported

        guard let request = AuthorizationHTTP.formPost(
            url: interactiveEndpoint,
            parameters: body,
            attestation: attestation
        ) else {
            throw AuthorizationError.unusable("This issuer's interactive authorization endpoint is not a usable URL")
        }

        let result = try await AuthorizationHTTP.send(request, tag: "iar-request", session: urlSession)

        guard result.isSuccessful else {
            throw AuthorizationError.rejected(
                status: result.status,
                body: result.data,
                contentType: result.contentType
            )
        }

        guard let json = (try? JSONSerialization.jsonObject(with: result.data)) as? [String: Any] else {
            throw AuthorizationError.unusable(
                "The interactive authorization endpoint did not answer with JSON",
                status: result.status
            )
        }

        let type = json["type"] as? String
        let status = json["status"] as? String
        let requestURI = json["request_uri"] as? String
        let authSession = json["auth_session"] as? String
        let expiresIn = json["expires_in"] as? Int

        // `type` is the discriminator, not the shape of the payload. The wallet advertises
        // `interaction_types_supported` and the server answers by naming the one it chose; reading
        // the payload instead would let the wallet decide what the server meant, and would make the
        // negotiation pointless. The payload is then required to match what the type announced --
        // without that check an announced presentation carrying no request silently became a
        // browser hand-off.
        switch type {
        case typePresentation:
            guard var openid4vpRequest = json["openid4vp_request"] as? [String: Any] else {
                throw AuthorizationError.unusable(
                    "This issuer announced an \(typePresentation) interaction but sent no openid4vp_request",
                    status: result.status
                )
            }
            // The presentation side identifies the verifier by this scheme.
            openid4vpRequest["client_id"] = "iar:\(interactiveEndpoint)"

            // `request_uri` is deliberately absent: Android's VerificationService tests it *before*
            // `openid4vp_request`, so carrying it would route an IAR presentation to the
            // request-uri handler instead.
            let url = AuthorizationURI.appending(
                [
                    "client_id": parameters.clientId,
                    "status": status,
                    "type": type,
                    "auth_session": authSession,
                    "openid4vp_request": openid4vpRequest.toString(),
                ],
                to: authorizationEndpoint
            )
            return .presentationRequired(url: url, authSession: authSession, expiresIn: expiresIn)

        case typeRedirectToWeb:
            guard let requestURI, !requestURI.isEmpty else {
                throw AuthorizationError.unusable(
                    "This issuer announced a \(typeRedirectToWeb) interaction but sent no request_uri",
                    status: result.status
                )
            }
            // `client_id` and `request_uri` only, as RFC 9126 section 4 describes. `type` and
            // `status` used to travel here so the wallet could read them back and work out what kind
            // of URL it had been handed -- the round trip the typed outcome replaces.
            let url = AuthorizationURI.appending(
                [
                    "client_id": parameters.clientId,
                    "request_uri": requestURI,
                ],
                to: authorizationEndpoint
            )
            return .openInBrowser(url: url, expiresIn: expiresIn)

        default:
            throw AuthorizationError.unusable(
                "This issuer asked for an interaction this wallet does not support: \(type ?? "none")",
                status: result.status
            )
        }
    }
}
