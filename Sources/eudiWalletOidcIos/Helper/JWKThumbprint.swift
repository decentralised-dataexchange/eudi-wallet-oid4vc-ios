//
//  JWKThumbprint.swift
//
//  RFC 7638 JWK thumbprints, in one place.
//

import Foundation
import CryptoKit

/// RFC 7638: SHA-256 over the **required members only**, lexicographically ordered, no whitespace.
///
/// One implementation, because there were three and no two agreed. ``WalletAttestation`` compares
/// the DPoP key against the attestation's `cnf` with it, and the credential proof uses it for the
/// `kid` of the `jwk` binding method -- where iOS previously hashed the *whole* JWK with
/// `.sortedKeys`, so any incidental member (`alg`, `use`, `kid`) changed the value, and Android
/// used the key's own `kid` field. Two platforms, two values, neither of them the standard.
enum JWKThumbprint {

    /// The thumbprint of an EC JWK, or `nil` when it is missing a required member.
    static func rfc7638(of jwk: [String: Any]) -> String? {
        guard let x = jwk["x"] as? String,
              let y = jwk["y"] as? String,
              let crv = jwk["crv"] as? String else { return nil }
        let canonical = "{\"crv\":\"\(crv)\",\"kty\":\"EC\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
        return Data(SHA256.hash(data: Data(canonical.utf8))).base64URLEncodedString()
    }
}
