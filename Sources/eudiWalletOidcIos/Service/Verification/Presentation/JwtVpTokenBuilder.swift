//
//  JwtVpTokenBuilder.swift
//  eudiWalletOidcIos
//

import Foundation

/// A W3C Verifiable Presentation as a JWT (OpenID4VP 1.0 Appendix B.1): `vp.verifiableCredential`
/// holds the credentials, `aud` the client identifier, `nonce` the request's nonce, `holder` the
/// wallet's DID. Signed with the wallet's key: W3C credentials in this wallet are bound to its DID,
/// so a credential's own key id is not used here.
struct JwtVpTokenBuilder {

    /// One presentation for one credential.
    func present(_ selected: SelectedCredential, _ inputs: PresentationInputs) throws -> Presentation {
        try aggregate([selected], inputs)
    }

    /// One presentation carrying every credential: the draft shape for several W3C VCs.
    func aggregate(_ selected: [SelectedCredential], _ inputs: PresentationInputs) throws -> Presentation {
        let entryId = selected.first?.entryId ?? ""
        guard let key = inputs.holderKey, let secureKey = key.generateSecureKey() else { throw PresentationError.noKey(entryId) }
        let did = inputs.holderDid ?? ""
        let id = "urn:uuid:\(UUID().uuidString)"
        let now = Int(Date().timeIntervalSince1970)
        let vp: [String: Any] = [
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "holder": did,
            "id": id,
            "type": ["VerifiablePresentation"],
            "verifiableCredential": selected.map { $0.credential }
        ]
        let claims: [String: Any] = [
            "aud": inputs.request.clientId ?? "",
            "exp": now + 3600,
            "iat": now,
            "iss": did,
            "jti": id,
            "nbf": now,
            "nonce": inputs.request.nonce ?? "",
            "sub": did,
            "vp": vp
        ]
        let header: [String: Any] = [
            "alg": "ES256",
            "kid": "\(did)#\(did.replacingOccurrences(of: "did:key:", with: ""))",
            "typ": "JWT",
            "jwk": Self.publicJwk(secureKey.publicKey)
        ]
        guard let payload = claims.toString(), let headerText = header.toString(),
              let token = key.sign(payload: payload, header: Data(headerText.utf8), withKey: secureKey.privateKey),
              !token.isEmpty else {
            throw PresentationError.presentationSigningFailed(entryId)
        }
        return Presentation(entryIds: selected.map { $0.entryId }, format: .w3cVp, token: token)
    }

    /// The P-256 public key as a JWK, from its raw `x || y` form.
    private static func publicJwk(_ raw: Data) -> [String: Any] {
        let split = raw.index(raw.startIndex, offsetBy: min(32, raw.count))
        return ["crv": "P-256", "kty": "EC",
                "x": raw[raw.startIndex..<split].urlSafeBase64EncodedString(),
                "y": raw[split..<raw.endIndex].urlSafeBase64EncodedString()]
    }
}
