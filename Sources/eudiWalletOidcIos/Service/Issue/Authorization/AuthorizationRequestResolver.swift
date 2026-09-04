//
//  AuthorizationRequestResolver.swift
//
//  Makes the authorization request: assemble once, pick a transport, read the answer.
//

import Foundation

/// Makes the authorization request: assemble the parameters once, pick a transport, read the answer.
///
/// The four transports previously lived as four branches of one function, each rebuilding the same
/// parameters in its own literal dictionary. They are now a registry, consulted in the same
/// precedence as before -- the interactive extension, then PAR, then in-app, then the browser -- so
/// no server that works today changes path.
///
/// Every failure returns an ``AuthorizationResponse`` whose outcome is
/// ``AuthorizationOutcome/failed``, carrying a reason. A failed interactive call, an unrecognised
/// interaction type, a rejected PAR and a redirect-less response all used to end in
/// `WrappedResponse(data: nil, error: nil)`.
///
/// Mirrors `AuthorizationRequestResolver` in the Android SDK.
struct AuthorizationRequestResolver {

    let policy: AuthorizationRequestPolicy
    let transports: [AuthorizationRequestTransport]

    init(
        policy: AuthorizationRequestPolicy = .standard,
        transports: [AuthorizationRequestTransport]? = nil,
        idTokenResponder: IdTokenResponding
    ) {
        self.policy = policy
        self.transports = transports ?? Self.defaultTransports(idTokenResponder: idTokenResponder)
    }

    /// Ordered. The interactive extension takes precedence when the server advertises it, then PAR
    /// when the server requires it, then the in-app transport when the caller asked for it, and the
    /// browser last as the default.
    static func defaultTransports(idTokenResponder: IdTokenResponding) -> [AuthorizationRequestTransport] {
        [
            // --- profile extension, not a specification feature ---
            InteractiveAuthorizationTransport(),
            PushedAuthorizationRequestTransport(),
            InAppAuthorizationRequestTransport(idTokenResponder: idTokenResponder),
            BrowserAuthorizationRequestTransport(),
        ]
    }

    /// - Parameters:
    ///   - authorizationDetails: the `authorization_details` value, built by the caller because it
    ///     depends on the credential being requested.
    func resolve(
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation?,
        codeVerifier: String,
        authorizationDetails: String,
        selection: CredentialSelection = CredentialSelection(),
        redirectUri: String? = nil,
        mode: AuthorizationMode = .browser,
        urlSession: URLSession = URLSession(configuration: .default)
    ) async -> AuthorizationResponse {

        let parameters = AuthorizationRequestParameters.build(
            session: session,
            wallet: wallet,
            attestation: attestation,
            selection: selection,
            authorizationDetails: authorizationDetails,
            codeVerifier: codeVerifier,
            redirectUri: redirectUri,
            policy: policy
        )

        let transport = transports.first {
            $0.supports(session: session, mode: mode, policy: policy)
        }

        // Built once and attached to every outcome, success or failure: `redirectUri` and `state`
        // are needed to finish the flow, not merely to explain it.
        let request = AuthorizationRequestInfo(
            transport: transport?.kind ?? .browser,
            endpoint: transport?.endpoint(for: session) ?? session.authConfig?.authorizationEndpoint,
            redirectUri: parameters.redirectUri,
            state: parameters.state,
            nonce: parameters.nonce,
            sentWalletAttestation: attestation?.sanitisedAttestationJwt != nil,
            parameters: parameters.asDictionary()
        )

        guard let transport else {
            return AuthorizationResponse
                .failed(reason: "No way of making an authorization request to this issuer")
                .with(request: request)
        }

        debugPrint("authorization request via \(transport.name)")

        do {
            let response = try await transport.perform(
                parameters: parameters,
                session: session,
                wallet: wallet,
                attestation: attestation,
                mode: mode,
                urlSession: urlSession
            )
            return response.with(request: request)
        } catch let error as AuthorizationError {
            debugPrint("authorization request failed via \(transport.name): \(error.asEUDIError.message ?? "")")
            return AuthorizationResponse.failed(error.asEUDIError).with(request: request)
        } catch {
            return AuthorizationResponse
                .failed(reason: error.localizedDescription)
                .with(request: request)
        }
    }
}
