//
//  VerifierKey.swift
//  eudiWalletOidcIosTests
//

import Foundation
import CryptoKit
import JOSESwift
@testable import eudiWalletOidcIos

/// The verifier's response encryption key, with the private half for decrypting in a test.
struct VerifierKey {
    let privateKey = P256.KeyAgreement.PrivateKey()
    let kid = "verifier-enc"

    var publicJwk: [String: Any] {
        let raw = privateKey.publicKey.rawRepresentation
        return ["kty": "EC", "crv": "P-256", "use": "enc", "kid": kid,
                "x": raw.prefix(32).b64url, "y": raw.suffix(32).b64url]
    }

    /// Decrypts a compact JWE, returning its header and JSON payload.
    func decrypt(_ compact: String) throws -> (header: JWEHeader, payload: [String: Any]) {
        let jwe = try JWE(compactSerialization: compact)
        let raw = privateKey.publicKey.rawRepresentation
        let key = try ECPrivateKey(crv: "P-256", x: raw.prefix(32).b64url,
                               y: raw.suffix(32).b64url,
                               privateKey: privateKey.rawRepresentation.b64url)
        guard let algorithm = jwe.header.keyManagementAlgorithm, let enc = jwe.header.contentEncryptionAlgorithm,
              let decrypter = Decrypter(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: enc,
                                        decryptionKey: key) else {
            throw NSError(domain: "VerifierKey", code: 0)
        }
        let payload = try jwe.decrypt(using: decrypter).data()
        return (jwe.header, (try JSONSerialization.jsonObject(with: payload)) as? [String: Any] ?? [:])
    }
}
