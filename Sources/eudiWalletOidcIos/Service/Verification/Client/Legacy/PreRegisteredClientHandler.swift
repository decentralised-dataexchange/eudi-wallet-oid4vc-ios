//
//  PreRegisteredClientHandler.swift
//  eudiWalletOidcIos
//

import Foundation

/// Section 5.9.2: a client id with no colon "MUST" be treated as a pre-registered client, and one
/// with an unrecognised prefix "can" be. The draft `https` scheme lands here too. The SDK has no
/// client registry, so such a request is let through unverified while the policy allows it; the
/// host's own trust list is what vouches for the client.
///
/// LEGACY in spirit: once every verifier sends a 1.0 prefix this handler can refuse by default.
struct PreRegisteredClientHandler: ClientIdentifierHandler {

    let prefixes: Set<ClientIdPrefix> = [.preRegistered, .https]

    func verify(_ request: inout PresentationRequest, _ identifier: ClientIdentifier,
                policy: PresentationRequestPolicy) async throws -> VerifierIdentity {
        guard policy.allowPreRegisteredClients else {
            throw PresentationRequestError.clientNotVerified(
                identifier.unrecognisedPrefix.map { "the client identifier prefix '\($0)' is not supported" }
                    ?? "pre-registered clients are not accepted")
        }
        return VerifierIdentity(
            identifier: identifier,
            verified: false,
            reason: identifier.unrecognisedPrefix.map { "unrecognised prefix '\($0)', treated as a pre-registered client" }
                ?? "pre-registered client; the request carries no authentication")
    }
}
