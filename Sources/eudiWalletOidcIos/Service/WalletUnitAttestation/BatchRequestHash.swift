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
}
