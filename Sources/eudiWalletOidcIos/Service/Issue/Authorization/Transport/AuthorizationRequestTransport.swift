//
//  AuthorizationRequestTransport.swift
//
//  One way of putting an authorization request to the authorization server.
//

import Foundation

/// One way of putting an authorization request to the authorization server.
///
/// The parameters are identical across all of them -- see ``AuthorizationRequestParameters`` -- so a
/// transport only decides how they travel and how the answer is read. Transports are consulted in
/// registry order, which preserves the precedence this SDK has always used: the interactive
/// extension, then PAR, then in-app, then the browser.
///
/// Mirrors `AuthorizationRequestTransport` in the Android SDK.
protocol AuthorizationRequestTransport {

    /// Which transport this is, reported back to the caller on every response.
    var kind: AuthorizationTransportKind { get }

    /// Human-readable name, used in logs.
    var name: String { get }

    /// The URL this transport will actually send to.
    ///
    /// Not always the authorization endpoint: PAR posts to the pushed-authorization endpoint and the
    /// interactive extension to its own. Reported as `request.endpoint` so a rejection can be traced
    /// to the URL that produced it.
    func endpoint(for session: IssuanceSession) -> String?

    /// True when this transport is the one to use for this session.
    func supports(
        session: IssuanceSession,
        mode: AuthorizationMode,
        policy: AuthorizationRequestPolicy
    ) -> Bool

    /// - Throws: ``AuthorizationError``
    func perform(
        parameters: AuthorizationRequestParameters,
        session: IssuanceSession,
        wallet: WalletIdentity,
        attestation: WalletAttestation?,
        mode: AuthorizationMode,
        urlSession: URLSession
    ) async throws -> AuthorizationResponse
}
