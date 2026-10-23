//
//  OpenIdFederationClientHandler.swift
//  eudiWalletOidcIos
//

import Foundation

/// Section 5.9.3 `openid_federation`: "Processing rules given in [OpenID.Federation] MUST be
/// followed." This SDK does not implement OpenID Federation, so the prefix is not advertised and
/// a request using it is refused rather than let through unverified.
struct OpenIdFederationClientHandler: ClientIdentifierHandler {

    let prefixes: Set<ClientIdPrefix> = [.openidFederation]

    func supported(_ policy: PresentationRequestPolicy) -> Bool { false }

    func verify(_ request: inout PresentationRequest, _ identifier: ClientIdentifier,
                policy: PresentationRequestPolicy) async throws -> VerifierIdentity {
        throw PresentationRequestError.unsupportedClientIdPrefix("openid_federation")
    }
}
