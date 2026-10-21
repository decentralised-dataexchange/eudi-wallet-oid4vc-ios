//
//  X509HashClientHandler.swift
//  eudiWalletOidcIos
//

import Foundation

/// Section 5.9.3 `x509_hash`: the identifier "MUST be a hash and match the hash of the leaf
/// certificate passed with the request. The request MUST be signed with the private key
/// corresponding to the public key in the leaf X.509 certificate ... The value of x509_hash is
/// the base64url-encoded value of the SHA-256 hash of the DER-encoded X.509 certificate. The
/// Wallet MUST validate the signature and the trust chain of the X.509 leaf certificate."
struct X509HashClientHandler: ClientIdentifierHandler {

    let prefixes: Set<ClientIdPrefix> = [.x509Hash]

    func verify(_ request: inout PresentationRequest, _ identifier: ClientIdentifier,
                policy: PresentationRequestPolicy) async throws -> VerifierIdentity {
        let jwt = try signedRequestObject(request, identifier.prefix)
        guard let chain = try RequestObjectCertificates.chain(jwt), let leaf = chain.first else {
            throw PresentationRequestError.clientNotVerified("the request object carries no x5c certificate chain")
        }
        guard RequestObjectCertificates.verifySignature(jwt, certificate: leaf) else {
            throw PresentationRequestError.clientNotVerified("the request object is not signed with the leaf certificate's key")
        }
        guard RequestObjectCertificates.sha256Base64Url(leaf) == identifier.identifier else {
            throw PresentationRequestError.clientNotVerified("the client_id hash does not match the leaf certificate")
        }
        let anchored = try RequestObjectCertificates.checkChain(chain, anchors: policy.trustAnchors)
        return VerifierIdentity(
            identifier: identifier,
            verified: true,
            anchored: anchored,
            certificateChain: chain,
            reason: anchored ? nil : "no trust anchors configured; the chain was checked for consistency only")
    }
}
