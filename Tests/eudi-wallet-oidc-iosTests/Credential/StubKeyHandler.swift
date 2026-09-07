//
//  StubKeyHandler.swift
//  eudiWalletOidcIosTests
//

import Foundation
import CryptoKit
@testable import eudiWalletOidcIos

/// A key handler that signs deterministically, so a proof can be taken apart in a test.
///
/// The real handlers reach the Secure Enclave or the keychain; neither is available to a unit test,
/// and neither is what these tests are about. `sign` produces a well-formed compact JWS whose
/// signature is a placeholder -- every assertion here is about the header and the claims.
final class StubKeyHandler: NSObject, SecureKeyProtocol {

    var keyStorageType: SecureKeyTypes = .cryptoKit

    /// Minted once, so `generateSecureKey`'s load-or-create contract holds: repeated calls must
    /// observe the same key, never mint a replacement.
    private let key = P256.Signing.PrivateKey()

    /// How many times the proof asked for a key. The production factory must resolve it once.
    private(set) var keyRequests = 0

    func generateSecureKey() -> SecureKeyData? {
        keyRequests += 1
        return SecureKeyData(publicKey: key.publicKey.rawRepresentation, privateKey: key.rawRepresentation)
    }

    func getJWK(publicKey: Data) -> [String: Any]? {
        let raw = publicKey.isEmpty ? key.publicKey.rawRepresentation : publicKey
        guard raw.count >= 64 else { return nil }
        return [
            "kty": "EC",
            "crv": "P-256",
            "x": raw.prefix(32).base64URLEncodedString(),
            "y": raw.suffix(32).base64URLEncodedString(),
        ]
    }

    func sign(payload: String, header: Data, withKey privateKey: Data?) -> String? {
        let headerSegment = header.base64URLEncodedString()
        let payloadSegment = Data(payload.utf8).base64URLEncodedString()
        return "\(headerSegment).\(payloadSegment).c2lnbmF0dXJl"
    }

    func getSecurePrivateKey() -> SecKey? { nil }

    /// The public JWK this handler signs with, for comparing a `kid` against.
    var publicJWK: [String: Any] { getJWK(publicKey: key.publicKey.rawRepresentation)! }
}

/// The header and claims of a compact JWS, for assertions.
enum JWTParts {
    static func header(_ jwt: String) -> [String: Any]? { segment(jwt, 0) }
    static func claims(_ jwt: String) -> [String: Any]? { segment(jwt, 1) }

    private static func segment(_ jwt: String, _ index: Int) -> [String: Any]? {
        let parts = jwt.split(separator: ".")
        guard parts.count > index, let data = Data(base64URLEncoded: String(parts[index])) else {
            return nil
        }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}
