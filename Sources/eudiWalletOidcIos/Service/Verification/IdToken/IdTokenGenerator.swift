//
//  IdTokenGenerator.swift
//  eudiWalletOidcIos
//

import Foundation

/// The self-issued `id_token` a request with response type `id_token` asks for (SIOPv2), signed
/// with the wallet's DID key.
struct IdTokenGenerator {

    func generate(_ request: PresentationRequest, did: String, keyHandler: SecureKeyProtocol) async -> String {
        let header = ([
            "typ": "JWT",
            "alg": "ES256",
            "kid": "\(did)#\(did.replacingOccurrences(of: "did:key:", with: ""))"
        ]).toString() ?? ""
        let currentTime = Int(Date().timeIntervalSince1970)
        let payload = ([
            "iss": did,
            "sub": did,
            "aud": request.clientId ?? "",
            "exp": currentTime + 3600,
            "iat": currentTime,
            "nonce": request.nonce ?? ""
        ] as [String: Any]).toString() ?? ""
        let secureData = await keyHandler.generateSecureKey()
        return keyHandler.sign(payload: payload, header: Data(header.utf8), withKey: secureData?.privateKey) ?? ""
    }
}
