//
//  X509SanUriClientHandler.swift
//  eudiWalletOidcIos
//

import Foundation

/// LEGACY, draft 20 `x509_san_uri`, removed in 1.0: like `x509_san_dns` with a
/// uniformResourceIdentifier SAN instead of a dNSName. Delete with the rest of `Legacy/`.
struct X509SanUriClientHandler: ClientIdentifierHandler {

    let prefixes: Set<ClientIdPrefix> = [.x509SanUri]

    func verify(_ request: inout PresentationRequest, _ identifier: ClientIdentifier,
                policy: PresentationRequestPolicy) async throws -> VerifierIdentity {
        let jwt = try signedRequestObject(request, identifier.prefix)
        guard let chain = try RequestObjectCertificates.chain(jwt), let leaf = chain.first else {
            throw PresentationRequestError.clientNotVerified("the request object carries no x5c certificate chain")
        }
        guard RequestObjectCertificates.verifySignature(jwt, certificate: leaf) else {
            throw PresentationRequestError.clientNotVerified("the request object is not signed with the leaf certificate's key")
        }
        guard RequestObjectCertificates.uriNames(leaf).contains(where: { $0.caseInsensitiveCompare(identifier.identifier) == .orderedSame }) else {
            throw PresentationRequestError.clientNotVerified("\(identifier.identifier) is not a URI SAN of the leaf certificate")
        }
        let anchored = try RequestObjectCertificates.checkChain(chain, anchors: policy.trustAnchors)
        return VerifierIdentity(identifier: identifier, verified: true, anchored: anchored, certificateChain: chain)
    }
}
