//
//  DecentralizedIdentifierClientHandler.swift
//  eudiWalletOidcIos
//

import Foundation

/// Section 5.9.3 `decentralized_identifier`: "The request MUST be signed with a private key
/// associated with the DID. A public key to verify the signature MUST be obtained from the
/// verificationMethod property of a DID Document. Since DID Document may include multiple public
/// keys, a particular public key used to sign the request in question MUST be identified by the
/// kid in the JOSE Header."
///
/// The `kid` has to be a DID URL under the client's own DID. Without that rule anyone could sign
/// with a key from a DID they control and name someone else's DID as the client. The key comes
/// from the `kid` alone; a `jwk` or `x5c` in the header proves nothing about the DID and is
/// ignored.
///
/// The draft `did:` scheme, where the client id is the bare DID, follows the same rules.
struct DecentralizedIdentifierClientHandler: ClientIdentifierHandler {

    let prefixes: Set<ClientIdPrefix> = [.decentralizedIdentifier, .did]

    func verify(_ request: inout PresentationRequest, _ identifier: ClientIdentifier,
                policy: PresentationRequestPolicy) async throws -> VerifierIdentity {
        let did = identifier.identifier
        guard did.hasPrefix("did:") else {
            throw PresentationRequestError.clientNotVerified("the client identifier is not a DID")
        }
        let jwt = try signedRequestObject(request, identifier.prefix)
        guard let kid = RequestObjectCertificates.header(jwt)?["kid"] as? String else {
            throw PresentationRequestError.clientNotVerified("the request object names no kid for the verifier's key")
        }
        guard kid == did || kid.hasPrefix("\(did)#") || kid.hasPrefix("\(did)?") else {
            throw PresentationRequestError.clientNotVerified("the kid does not belong to the client DID")
        }

        let keys = ((try? await JWKResolver().resolve(kid: kid, x5cChain: nil)) ?? [])
            .compactMap { $0 as? [String: Any] }
            .filter { !$0.isEmpty }
        guard !keys.isEmpty else {
            throw PresentationRequestError.clientNotVerified("the key \(kid) could not be resolved")
        }
        guard keys.contains(where: { RequestObjectCertificates.verifySignature(jwt, jwk: $0) }) else {
            throw PresentationRequestError.clientNotVerified("the request object signature does not verify")
        }
        return VerifierIdentity(identifier: identifier, verified: true)
    }
}
