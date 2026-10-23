//
//  WebOriginClientHandler.swift
//  eudiWalletOidcIos
//

import Foundation

/// LEGACY, draft `web-origin`: the Digital Credentials API origin, which the platform
/// authenticates before the request reaches the wallet. Nothing in the request itself can be
/// checked here; the host's DC API trust check owns this case.
struct WebOriginClientHandler: ClientIdentifierHandler {

    let prefixes: Set<ClientIdPrefix> = [.webOrigin]

    func verify(_ request: inout PresentationRequest, _ identifier: ClientIdentifier,
                policy: PresentationRequestPolicy) async throws -> VerifierIdentity {
        VerifierIdentity(identifier: identifier, verified: false,
                         reason: "web-origin is authenticated by the platform, not by the request")
    }
}
