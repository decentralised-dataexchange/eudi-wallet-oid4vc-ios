//
//  VerifierAttestationClientHandler.swift
//  eudiWalletOidcIos
//

import Foundation

/// Section 5.9.3 `verifier_attestation`: the identifier "MUST equal the sub claim value in the
/// Verifier attestation JWT. The request MUST be signed with the private key corresponding to the
/// public key in the cnf claim in the Verifier attestation JWT ... The Verifier attestation JWT
/// MUST be added to the jwt JOSE Header of the request object. The Wallet MUST validate the
/// signature on the Verifier attestation JWT. The iss claim value of the Verifier Attestation JWT
/// MUST identify a party the Wallet trusts for issuing Verifier Attestation JWTs. If the Wallet
/// cannot establish trust, it MUST refuse the request. If the issuer of the Verifier Attestation
/// JWT adds a redirect_uris claim to the attestation, the Wallet MUST ensure the redirect_uri
/// request parameter value exactly matches one of the redirect_uris claim entries."
///
/// Trust in the attester is anchoring, handled the same way as an x509 chain: an attestation
/// signed by one of `PresentationRequestPolicy.verifierAttestationIssuerKeys` is anchored. One
/// whose `iss` is a DID that resolves to the signing key is self-consistent and reported as
/// verified but not anchored, leaving the trust decision to the host; a policy with
/// `requireAnchoredClients` refuses it. Anything else cannot be checked and is refused.
struct VerifierAttestationClientHandler: ClientIdentifierHandler {

    let prefixes: Set<ClientIdPrefix> = [.verifierAttestation]

    func verify(_ request: inout PresentationRequest, _ identifier: ClientIdentifier,
                policy: PresentationRequestPolicy) async throws -> VerifierIdentity {
        let jwt = try signedRequestObject(request, identifier.prefix)

        guard let attestation = RequestObjectCertificates.header(jwt)?["jwt"] as? String,
              let claims = RequestObjectCertificates.claims(attestation) else {
            throw PresentationRequestError.clientNotVerified("the request object carries no verifier attestation JWT in its jwt header")
        }
        guard claims["sub"] as? String == identifier.identifier else {
            throw PresentationRequestError.clientNotVerified("the verifier attestation sub does not match the client identifier")
        }
        if let exp = (claims["exp"] as? NSNumber)?.doubleValue, Date(timeIntervalSince1970: exp) < Date() {
            throw PresentationRequestError.clientNotVerified("the verifier attestation has expired")
        }

        guard let cnfJwk = (claims["cnf"] as? [String: Any])?["jwk"] as? [String: Any] else {
            throw PresentationRequestError.clientNotVerified("the verifier attestation carries no cnf key")
        }
        guard RequestObjectCertificates.verifySignature(jwt, jwk: cnfJwk) else {
            throw PresentationRequestError.clientNotVerified("the request object is not signed with the attested key")
        }

        let anchored = policy.verifierAttestationIssuerKeys.contains { RequestObjectCertificates.verifySignature(attestation, jwk: $0) }
        let issuer = claims["iss"] as? String ?? ""
        if !anchored {
            let issuerKeys = await attesterKeys(issuer, attestation)
            guard !issuerKeys.isEmpty else {
                throw PresentationRequestError.clientNotVerified("the verifier attestation is not signed by a trusted issuer")
            }
            guard issuerKeys.contains(where: { RequestObjectCertificates.verifySignature(attestation, jwk: $0) }) else {
                throw PresentationRequestError.clientNotVerified("the verifier attestation signature does not verify against its issuer \(issuer)")
            }
        }

        let target = [request.redirectUri, request.responseUri].compactMap { $0 }.first { !$0.isEmpty }
        if let allowed = claims["redirect_uris"] as? [String], let target, !allowed.contains(target) {
            throw PresentationRequestError.clientNotVerified("the redirect_uri is not among the attestation's redirect_uris")
        }

        return VerifierIdentity(
            identifier: identifier,
            verified: true,
            anchored: anchored,
            reason: anchored ? nil : "the attester \(issuer) is not a configured trusted issuer; the attestation is self-consistent only")
    }

    /// The attester's keys when `iss` is a DID this SDK can resolve; empty otherwise. A `kid`
    /// under the issuer DID picks the verification method; otherwise the DID itself is resolved.
    private func attesterKeys(_ issuer: String, _ attestation: String) async -> [[String: Any]] {
        guard issuer.hasPrefix("did:") else { return [] }
        let kid = (RequestObjectCertificates.header(attestation)?["kid"] as? String).flatMap { $0.hasPrefix(issuer) ? $0 : nil } ?? issuer
        return ((try? await JWKResolver().resolve(kid: kid, x5cChain: nil)) ?? [])
            .compactMap { $0 as? [String: Any] }
            .filter { !$0.isEmpty }
    }
}
