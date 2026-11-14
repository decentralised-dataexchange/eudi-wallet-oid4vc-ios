//
//  JwtVpTokenBuilder.swift
//  eudiWalletOidcIos
//

import Foundation

/// A W3C Verifiable Presentation as a JWT (OpenID4VP 1.0 Appendix B.1): `vp.verifiableCredential`
/// holds the credentials, `aud` the client identifier, `nonce` the request's nonce, `holder` the
/// wallet's DID. A credential with its own key (`keyId`) is presented with that key, since the
/// verifier checks the signature against the credential's `cnf`; one without falls back to the
/// wallet's key and DID.
struct JwtVpTokenBuilder {

    /// One presentation for one credential, signed with the credential's own key when it has one,
    /// with `iss`, `sub` and `holder` the did:key of that key.
    func present(_ selected: SelectedCredential, _ inputs: PresentationInputs) async throws -> Presentation {
        guard let keyId = selected.keyId, !keyId.isEmpty else { return try aggregate([selected], inputs) }
        let key = SecureEnclaveHandler.presentationKey(keyId)
        guard let secureKey = key.generateSecureKey(),
              let did = await DidService.shared.createES256DID(jwk: Self.publicJwk(secureKey.publicKey)) else {
            throw PresentationError.noKey(selected.entryId)
        }
        return try sign([selected], key: key, secureKey: secureKey, did: did, inputs)
    }

    /// One presentation carrying every credential, signed with the wallet's key: the draft shape for several W3C VCs.
    func aggregate(_ selected: [SelectedCredential], _ inputs: PresentationInputs) throws -> Presentation {
        let entryId = selected.first?.entryId ?? ""
        guard let key = inputs.holderKey, let secureKey = key.generateSecureKey() else { throw PresentationError.noKey(entryId) }
        return try sign(selected, key: key, secureKey: secureKey, did: inputs.holderDid ?? "", inputs)
    }

    private func sign(_ selected: [SelectedCredential], key: SecureKeyProtocol, secureKey: SecureKeyData,
                      did: String, _ inputs: PresentationInputs) throws -> Presentation {
        let entryId = selected.first?.entryId ?? ""
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

    /// The P-256 public key as a JWK, from its raw `x || y` form or the `0x04 || x || y` form a
    /// Secure Enclave key gives.
    private static func publicJwk(_ key: Data) -> [String: Any] {
        let raw = key.count == 65 && key.first == 0x04 ? key.dropFirst() : key
        let split = raw.index(raw.startIndex, offsetBy: min(32, raw.count))
        return ["crv": "P-256", "kty": "EC",
                "x": raw[raw.startIndex..<split].urlSafeBase64EncodedString(),
                "y": raw[split..<raw.endIndex].urlSafeBase64EncodedString()]
    }
}
