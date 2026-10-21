//
//  RequestUriMethod.swift
//
//  OpenID4VP 1.0 section 5.10, Request URI Method `post`.
//
//  When the authorization request carries `request_uri_method=post`, the request object is
//  fetched with an HTTP POST (`application/x-www-form-urlencoded`) that carries the wallet's
//  metadata and a fresh `wallet_nonce`. The verifier MUST echo that nonce in the signed request
//  object, and the wallet MUST refuse a request object that does not carry it back. Any other
//  value, or no value at all, keeps the plain GET of RFC 9101.
//

import Foundation
import JOSESwift

enum RequestUriMethod {

    static let param = "request_uri_method"
    static let walletNonceField = "wallet_nonce"
    static let walletMetadataField = "wallet_metadata"
    static let requestObjectMediaType = "application/oauth-authz-req+jwt"

    /// True when the authorization request asks for the request object to be fetched by POST.
    static func isPost(_ authorisationRequestData: String) -> Bool {
        guard let value = queryParameter(authorisationRequestData, param) else { return false }
        return value.trimmingCharacters(in: .whitespacesAndNewlines).caseInsensitiveCompare("post") == .orderedSame
    }

    /// The `request_uri` of the authorization request, or nil when it carries none.
    static func requestUri(_ authorisationRequestData: String) -> String? {
        guard let value = queryParameter(authorisationRequestData, "request_uri"), !value.isEmpty else { return nil }
        return value
    }

    /// Reads one query parameter from the raw authorization request URI. Parsed by hand so that
    /// a custom scheme such as `openid4vp://?...` and values with reserved characters decode the
    /// same way on every platform.
    static func queryParameter(_ uri: String, _ name: String) -> String? {
        guard let questionMark = uri.firstIndex(of: "?") else { return nil }
        var query = String(uri[uri.index(after: questionMark)...])
        if let hash = query.firstIndex(of: "#") { query = String(query[..<hash]) }
        for pair in query.split(separator: "&", omittingEmptySubsequences: true) {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.first.map(String.init) == name else { continue }
            let raw = parts.count > 1 ? String(parts[1]) : ""
            return raw.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? raw
        }
        return nil
    }

    /// A fresh, URL-safe random value for the `wallet_nonce` POST parameter.
    static func newWalletNonce() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64URLEncodedString()
    }

    /// A fresh P-256 key for one request-object fetch. Section 5.10: "If the Wallet requires the
    /// Verifier to encrypt the Request Object, it SHOULD use the `jwks` parameter within the
    /// `wallet_metadata` parameter to pass public encryption keys." The private half never leaves
    /// the fetch that created it.
    static func newEncryptionKey() -> ECPrivateKey? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]
        ]
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else { return nil }
        return try? ECPrivateKey(
            privateKey: secKey,
            additionalParameters: ["kid": UUID().uuidString, "use": "enc", "alg": KeyManagementAlgorithm.ECDH_ES.rawValue]
        )
    }

    /// The public half of [key] as a JWK, with the same `kid`, `use` and `alg`.
    static func publicJwk(of key: ECPrivateKey) -> ECPublicKey {
        var parameters: [String: String] = [:]
        for name in ["kid", "use", "alg"] {
            if let value = key[name] { parameters[name] = value }
        }
        return ECPublicKey(crv: key.crv, x: key.x, y: key.y, additionalParameters: parameters)
    }

    /// Unwraps an encrypted request object (RFC 9101 section 6.1, a JWE whose payload is the signed
    /// request JWT) with [key]. A body that is not a JWE is returned untouched, so a verifier that
    /// chose not to encrypt still works. Nil when the body is a JWE this key cannot open.
    static func unwrapEncrypted(_ body: String, key: ECPrivateKey) -> String? {
        let trimmed = body.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.filter({ $0 == "." }).count == 4 else { return trimmed }
        do {
            let jwe = try JWE(compactSerialization: trimmed)
            guard let alg = jwe.header.keyManagementAlgorithm,
                  let enc = jwe.header.contentEncryptionAlgorithm,
                  let decrypter = Decrypter(keyManagementAlgorithm: alg, contentEncryptionAlgorithm: enc, decryptionKey: key)
            else { return nil }
            let payload = try jwe.decrypt(using: decrypter)
            return String(data: payload.data(), encoding: .utf8)
        } catch {
            return nil
        }
    }

    /// The wallet metadata sent with the POST (OpenID4VP 1.0 section 10 and 5.10): the credential
    /// formats and algorithms this SDK can present, the client id prefixes it can verify, the
    /// response modes it can answer with, and, when [encryptionKey] is given, the public key and
    /// algorithms the verifier can use to encrypt the request object. Serialised as the JSON string
    /// the form parameter expects.
    static func walletMetadata(encryptionKey: ECPrivateKey? = nil) -> String {
        var metadata: [String: Any] = [
            "vp_formats_supported": [
                "dc+sd-jwt": ["sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["ES256"]],
                "mso_mdoc": ["issuerauth_alg_values": [-7], "deviceauth_alg_values": [-7]]
            ],
            // Derived from the client identifier registry, so the advertisement and the enforcement
            // cannot drift apart.
            "client_id_prefixes_supported": ClientIdentifierVerifier().supportedPrefixes(.default),
            "response_modes_supported": ["direct_post", "direct_post.jwt"],
            "request_object_signing_alg_values_supported": ["ES256"]
        ]
        if let key = encryptionKey,
           let jwkData = publicJwk(of: key).jsonData(),
           let jwk = try? JSONSerialization.jsonObject(with: jwkData) {
            metadata["jwks"] = ["keys": [jwk]]
            metadata["request_object_encryption_alg_values_supported"] = [
                KeyManagementAlgorithm.ECDH_ES.rawValue,
                KeyManagementAlgorithm.ECDH_ES_A128KW.rawValue,
                KeyManagementAlgorithm.ECDH_ES_A256KW.rawValue
            ]
            metadata["request_object_encryption_enc_values_supported"] = [
                ContentEncryptionAlgorithm.A128GCM.rawValue,
                ContentEncryptionAlgorithm.A256GCM.rawValue,
                ContentEncryptionAlgorithm.A128CBCHS256.rawValue
            ]
        }
        guard let data = try? JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys]),
              let json = String(data: data, encoding: .utf8) else { return "{}" }
        return json
    }

    /// Section 5.10: if the wallet sent a `wallet_nonce`, the request object MUST carry the same
    /// value back. [sent] is nil when the request object was fetched by GET, and then nothing is
    /// checked.
    static func nonceAccepted(sent: String?, received: String?) -> Bool {
        guard let sent = sent else { return true }
        return received == sent
    }
}
