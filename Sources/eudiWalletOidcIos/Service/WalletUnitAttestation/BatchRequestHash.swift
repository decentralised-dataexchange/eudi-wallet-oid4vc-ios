//
//  BatchRequestHash.swift
//  eudiWalletOidcIos
//

import Foundation
import CryptoKit

/// App Attest challenge for a batch wallet-unit request:
///
///     base64url(SHA-256(concat(sorted(RFC 7638 thumbprint of each cnf key))))
///
/// Thumbprints are sorted as plain strings and concatenated with no separator.
/// The wallet provider recomputes the value from the cnf keys it receives and
/// refuses a mismatch. Base64URL without padding.
public enum BatchRequestHash {

    public static func compute(jwks: [[String: Any]]) -> String {
        computeFromThumbprints(jwks.map { Data(computeJwkThumbprintBytes(jwk: $0)).base64URLEncodedString() })
    }

    public static func computeFromThumbprints(_ thumbprints: [String]) -> String {
        let joined = thumbprints.sorted().joined()
        return Data(SHA256.hash(data: Data(joined.utf8))).base64URLEncodedString()
    }

    /// The request binding of a single wallet-unit request:
    ///
    ///     base64url(SHA-256(UTF-8(nonce + "." + base64url(SHA-256(UTF-8(thumbprint))))))
    ///
    /// `thumbprint` is the RFC 7638 thumbprint of the cnf key. App Attest signs
    /// SHA-256 of the UTF-8 bytes of the binding, at the registration and in
    /// every later assertion.
    static func requestBinding(nonce: String, thumbprint: String) -> String {
        let input = nonce + "." + computeFromThumbprints([thumbprint])
        return Data(SHA256.hash(data: Data(input.utf8))).base64URLEncodedString()
    }
}
