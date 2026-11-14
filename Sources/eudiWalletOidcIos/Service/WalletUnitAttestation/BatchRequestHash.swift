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

    /// The request binding of a wallet provider protocol 2 request:
    ///
    ///     base64url(SHA-256(UTF-8(nonce + "." + batch request hash of jwks)))
    ///
    /// Every piece of App Attest evidence of the request covers it, so an
    /// attestation or assertion made for one request cannot be replayed on
    /// another. The keys per request:
    ///
    /// - registration: the cnf key of each client assertion plus the public
    ///   JWK of the request key;
    /// - later WIA request (single or batch): the cnf key of each client assertion;
    /// - status and revocation code: no key, so the hash is of the empty string;
    /// - key attestation: the issuer `c_nonce` and the attested keys.
    ///
    /// Returns nil when a key is not an EC JWK with `crv`, `x` and `y`: the
    /// request cannot be bound, so it must not be sent.
    static func requestBinding(nonce: String, jwks: [[String: Any]]) -> String? {
        var thumbprints: [String] = []
        for jwk in jwks {
            guard let thumbprint = JWKThumbprint.rfc7638(of: jwk) else { return nil }
            thumbprints.append(thumbprint)
        }
        let input = nonce + "." + computeFromThumbprints(thumbprints)
        return Data(SHA256.hash(data: Data(input.utf8))).base64URLEncodedString()
    }

    /// The `clientDataHash` that App Attest signs for a request: SHA-256 of
    /// the UTF-8 bytes of its request binding. The same value goes to
    /// `attestKey` at the registration and to `generateAssertion` afterwards.
    static func clientDataHash(binding: String) -> Data {
        Data(SHA256.hash(data: Data(binding.utf8)))
    }
}
