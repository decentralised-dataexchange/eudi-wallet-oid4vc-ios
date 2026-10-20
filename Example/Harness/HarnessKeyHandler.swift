//
//  HarnessKeyHandler.swift
//  Harness
//

import Foundation
import CryptoKit
import eudiWalletOidcIos

/// A throwaway P-256 key handler for the harness.
///
/// The SDK asks the host for one because a real wallet keeps its keys in the Secure Enclave or the
/// keychain. The harness is not a wallet and holds nothing between launches, so this generates a
/// fresh key in memory each time. **Not suitable for anything but testing.**
final class HarnessKeyHandler: NSObject, SecureKeyProtocol {

    var keyStorageType: SecureKeyTypes = .cryptoKit

    func generateSecureKey() -> SecureKeyData? {
        let key = P256.Signing.PrivateKey()
        return SecureKeyData(
            publicKey: key.publicKey.rawRepresentation,
            privateKey: key.rawRepresentation
        )
    }

    func sign(payload: String, header: Data, withKey privateKey: Data?) -> String? {
        guard let privateKey,
              let key = try? P256.Signing.PrivateKey(rawRepresentation: privateKey),
              let payloadData = payload.data(using: .utf8) else { return nil }

        let signingInput = "\(Self.base64url(header)).\(Self.base64url(payloadData))"
        guard let signingData = signingInput.data(using: .utf8),
              let signature = try? key.signature(for: signingData) else { return nil }

        return "\(signingInput).\(Self.base64url(signature.rawRepresentation))"
    }

    func getJWK(publicKey: Data) -> [String: Any]? {
        guard publicKey.count == 64 else { return nil }
        return [
            "kty": "EC",
            "crv": "P-256",
            "x": Self.base64url(publicKey.prefix(32)),
            "y": Self.base64url(publicKey.suffix(32)),
        ]
    }

    private static func base64url<D: DataProtocol>(_ data: D) -> String {
        Data(data).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
