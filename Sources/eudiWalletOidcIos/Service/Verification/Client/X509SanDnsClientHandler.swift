//
//  X509SanDnsClientHandler.swift
//  eudiWalletOidcIos
//

import Foundation

/// Section 5.9.3 `x509_san_dns`: the identifier "MUST be a DNS name and match a dNSName Subject
/// Alternative Name (SAN) entry in the leaf certificate passed with the request. The request MUST
/// be signed with the private key corresponding to the public key in the leaf X.509 certificate
/// of the certificate chain added to the request in the x5c JOSE header. The Wallet MUST validate
/// the signature and the trust chain of the X.509 certificate."
struct X509SanDnsClientHandler: ClientIdentifierHandler {

    let prefixes: Set<ClientIdPrefix> = [.x509SanDns]

    func verify(_ request: inout PresentationRequest, _ identifier: ClientIdentifier,
                policy: PresentationRequestPolicy) async throws -> VerifierIdentity {
        let jwt = try signedRequestObject(request, identifier.prefix)
        guard let chain = try RequestObjectCertificates.chain(jwt), let leaf = chain.first else {
            throw PresentationRequestError.clientNotVerified("the request object carries no x5c certificate chain")
        }
        guard RequestObjectCertificates.verifySignature(jwt, certificate: leaf) else {
            throw PresentationRequestError.clientNotVerified("the request object is not signed with the leaf certificate's key")
        }
        guard RequestObjectCertificates.dnsNames(leaf).contains(where: { $0.caseInsensitiveCompare(identifier.identifier) == .orderedSame }) else {
            throw PresentationRequestError.clientNotVerified("\(identifier.identifier) is not a dNSName SAN of the leaf certificate")
        }
        let anchored = try RequestObjectCertificates.checkChain(chain, anchors: policy.trustAnchors)

        let target = [request.responseUri, request.redirectUri].compactMap { $0 }.first { !$0.isEmpty }
        let bound = target.map { URL(string: $0)?.host?.caseInsensitiveCompare(identifier.identifier) == .orderedSame }

        return VerifierIdentity(
            identifier: identifier,
            verified: true,
            anchored: anchored,
            certificateChain: chain,
            redirectUriBound: bound,
            reason: anchored ? nil : "no trust anchors configured; the chain was checked for consistency only")
    }
}
