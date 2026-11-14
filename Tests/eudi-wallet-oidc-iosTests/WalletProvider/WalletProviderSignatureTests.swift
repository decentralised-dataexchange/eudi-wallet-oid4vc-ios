import XCTest
import CryptoKit
@testable import eudiWalletOidcIos

/// Wallet provider protocol 2: the request binding, the Content-Digest, the
/// RFC 9421 signature base and the request key. The vectors come from the
/// platform team's reference data (test-vector-protocol2.json and
/// examples-protocol2.json of 13 November 2026); the server code made and
/// checked them. The keys are test keys.
final class WalletProviderSignatureTests: XCTestCase {

    // MARK: - Vectors

    /// test-vector-protocol2.json, case `ios-registration`.
    private enum IOSRegistration {
        static let privateScalarHex = "2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819"
        static let publicJWK: [String: Any] = ["kty": "EC", "crv": "P-256",
                                               "x": "faEG3Kbj1y_SVWKX59GgL_bVttCjiH9URC8OV_3Yp68",
                                               "y": "HkRfkmW_Yr5N9dc9lD8Hh26QngNaG0YJfNEnRin-1Lk"]
        static let keyId = "kSc7spBQECERrP8dgtToyyh8P5b00fg070Nww3UI3DY"
        static let targetURI = "https://wallet.example/organisation/6ae0f1a2-c4b6-4e7a-9c1d-2f3e4a5b6c7d/service/wallet-provider/wallet-unit/request"
        static let body = #"{"client_assertion":"eyJ0ZXN0IjoxfQ.e30.c2ln","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}"#
        static let created = 1794556860
        static let components = ["@method", "@target-uri", "content-digest", "x-wallet-unit-nonce",
                                 "x-wallet-unit-platform", "x-wallet-app-version", "x-wallet-app-build",
                                 "x-wallet-unit-request-key"]
        static let requestKeyHeader = "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImZhRUczS2JqMXlfU1ZXS1g1OUdnTF9iVnR0Q2ppSDlVUkM4T1ZfM1lwNjgiLCJ5IjoiSGtSZmttV19ZcjVOOWRjOWxEOEhoMjZRbmdOYUcwWUpmTkVuUmluLTFMayJ9"
        static let headers: [String: String] = [
            "Content-Type": "application/json",
            "Content-Digest": "sha-256=:ykEqvRQ01qDR7wg6+ivS/+ZlCp5Wv1/Ie5VT5DM+V4I=:",
            "X-Wallet-Unit-Nonce": "n-91d2e3f4a5",
            "X-Wallet-Unit-Platform": "ios",
            "X-Wallet-App-Version": "2026.12.0",
            "X-Wallet-App-Build": "7",
            "X-Wallet-Unit-Request-Key": requestKeyHeader
        ]
        static let signatureInput = #"wp=("@method" "@target-uri" "content-digest" "x-wallet-unit-nonce" "x-wallet-unit-platform" "x-wallet-app-version" "x-wallet-app-build" "x-wallet-unit-request-key");created=1794556860;keyid="kSc7spBQECERrP8dgtToyyh8P5b00fg070Nww3UI3DY";alg="ecdsa-p256-sha256""#
        static let signatureRaw = "W9LNQ4GjEm2VIP33Bq/SfH5j+KXqsadMGO1gGuERgHCks5oYISSK32mm3TRWw5c6+qdp/3/bZwiMURWebRJi7A=="
        static let signatureBase = """
        "@method": POST
        "@target-uri": https://wallet.example/organisation/6ae0f1a2-c4b6-4e7a-9c1d-2f3e4a5b6c7d/service/wallet-provider/wallet-unit/request
        "content-digest": sha-256=:ykEqvRQ01qDR7wg6+ivS/+ZlCp5Wv1/Ie5VT5DM+V4I=:
        "x-wallet-unit-nonce": n-91d2e3f4a5
        "x-wallet-unit-platform": ios
        "x-wallet-app-version": 2026.12.0
        "x-wallet-app-build": 7
        "x-wallet-unit-request-key": eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImZhRUczS2JqMXlfU1ZXS1g1OUdnTF9iVnR0Q2ppSDlVUkM4T1ZfM1lwNjgiLCJ5IjoiSGtSZmttV19ZcjVOOWRjOWxEOEhoMjZRbmdOYUcwWUpmTkVuUmluLTFMayJ9
        "@signature-params": ("@method" "@target-uri" "content-digest" "x-wallet-unit-nonce" "x-wallet-unit-platform" "x-wallet-app-version" "x-wallet-app-build" "x-wallet-unit-request-key");created=1794556860;keyid="kSc7spBQECERrP8dgtToyyh8P5b00fg070Nww3UI3DY";alg="ecdsa-p256-sha256"
        """
    }

    /// test-vector-protocol2.json, case `android-status`: the same rules with
    /// another component list and an empty body.
    private enum AndroidStatus {
        static let publicJWK: [String: Any] = ["kty": "EC", "crv": "P-256",
                                               "x": "wjk5lWu3smO1SfHPxgj8utTSNaK8PjDOuJ0jQLLhgmM",
                                               "y": "qyxVsnVhA9rn9HymNjOR_9IROFxBXOKU3ZAfboyUTGw"]
        static let targetURI = "https://wallet.example/organisation/6ae0f1a2-c4b6-4e7a-9c1d-2f3e4a5b6c7d/service/wallet-provider/wallet-unit/status"
        static let components = ["@method", "@target-uri", "content-digest", "x-wallet-unit-nonce",
                                 "x-wallet-unit-platform", "x-wallet-app-version", "x-wallet-app-build",
                                 "x-wallet-device-model"]
        static let headers: [String: String] = [
            "Content-Digest": "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:",
            "X-Wallet-Unit-Nonce": "n-7c1f0a9e2b",
            "X-Wallet-Unit-Platform": "android",
            "X-Wallet-App-Version": "2026.12.0",
            "X-Wallet-App-Build": "490",
            "X-Wallet-Device-Model": "samsung SM-A125F"
        ]
        static let signatureRaw = "lvKXiPAJGyoy3C6/DKcOMtix2087G/IQXlABmU0K0qa60YGQ/aOYmk5vfQR18Gbn55uA+Zj8mGUtQFv7O6H2EQ=="
    }

    /// examples-protocol2.json (iOS): the cnf key of the client assertion.
    private let cnfKey: [String: Any] = ["kty": "EC", "crv": "P-256",
                                         "x": "JXlfGjy5MoMHseuORMctu9tRprlVFSHpBA-NahQp4VE",
                                         "y": "UJ_wHjUtLBBCLnxYBrRtPggzCJ2y0IVo0gtoo8FCKfU"]
    private let secondCnfKey: [String: Any] = ["kty": "EC", "crv": "P-256",
                                               "x": "9AfCwvHQzQ3no6bjLNoDHgQCZ3f5zo6iKjFDPQaMh7w",
                                               "y": "C5i_AZ9J8DsX9x3QII5lazk1GlburTiU6yAxt-c9a48"]

    private func softwareKey(hex: String) throws -> SoftwareRequestKey {
        var bytes = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return SoftwareRequestKey(privateKey: try P256.Signing.PrivateKey(rawRepresentation: bytes))
    }

    private func publicKey(_ jwk: [String: Any]) throws -> P256.Signing.PublicKey {
        let x = Data(base64URLEncoded: jwk["x"] as! String)!
        let y = Data(base64URLEncoded: jwk["y"] as! String)!
        return try P256.Signing.PublicKey(rawRepresentation: x + y)
    }

    private func verifies(base: String, rawSignatureBase64: String, jwk: [String: Any]) throws -> Bool {
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: Data(base64Encoded: rawSignatureBase64)!)
        return try publicKey(jwk).isValidSignature(signature, for: Data(base.utf8))
    }

    // MARK: - Request binding

    func testRegistrationBindingCoversTheCnfKeyAndTheRequestKey() {
        XCTAssertEqual(
            BatchRequestHash.requestBinding(nonce: "ViJQNXjm4qiV1SInLWHC7xezZuA=", jwks: [cnfKey, IOSRegistration.publicJWK]),
            "BoNwk8j7JP57dhH-ZkAF6rqhcWnfKWwrT1bIuVOpLtc")
    }

    func testLaterWiaRequestBindingCoversTheCnfKeyOnly() {
        XCTAssertEqual(
            BatchRequestHash.requestBinding(nonce: "K1HUQWuceXPnPAoeLv+qlEPEL1M=", jwks: [cnfKey]),
            "pH3cDKxXJGdSBIrm6srmr5Pdqhb9HlwhhVmga5wciDQ")
    }

    func testBatchBindingCoversEveryCnfKeyInAnyOrder() {
        let nonce = "YyiygdD0UX7VJ2OWmgbSfwSjOJc="
        let expected = "pfNV9LFrbzpdAqiIY0ZmwyAagtyORTWEYHhGuuzYpvU"
        XCTAssertEqual(BatchRequestHash.requestBinding(nonce: nonce, jwks: [cnfKey, secondCnfKey]), expected)
        XCTAssertEqual(BatchRequestHash.requestBinding(nonce: nonce, jwks: [secondCnfKey, cnfKey]), expected)
    }

    func testStatusBindingHasNoKey() {
        XCTAssertEqual(
            BatchRequestHash.requestBinding(nonce: "kf5GCxbb2X3kcxAaauCbPDEDV58=", jwks: []),
            "LMo7R9OW2QptIrwZ1TcUKPWX-kHRLqJRPzm8EThhJ3s")
    }

    func testKeyAttestationBindingUsesTheIssuerNonceAndTheAttestedKeys() {
        let attested: [String: Any] = ["kty": "EC", "crv": "P-256",
                                       "x": "I9et4FjCuIKx_E8ze4fl-CTQOUFfiQTaQqUoxj0C254",
                                       "y": "yrZfoyoop7y2u2V7Is5mV-NWFCRLdlw4Shq9mV36sjo"]
        XCTAssertEqual(
            BatchRequestHash.requestBinding(nonce: "issuer-c-nonce-3f9a1b7c", jwks: [attested]),
            "Qeb_pCojHdeXAPAXIi76saNosPljN198kdJ-oeA8EvM")
    }

    func testBindingIgnoresMembersOutsideRfc7638() {
        var withExtras = cnfKey
        withExtras["kid"] = "key-1"
        withExtras["alg"] = "ES256"
        XCTAssertEqual(BatchRequestHash.requestBinding(nonce: "n", jwks: [withExtras]),
                       BatchRequestHash.requestBinding(nonce: "n", jwks: [cnfKey]))
    }

    func testBindingRefusesAKeyThatIsNotAnEcJwk() {
        XCTAssertNil(BatchRequestHash.requestBinding(nonce: "n", jwks: [["kty": "RSA", "n": "AQAB"]]))
    }

    func testClientDataHashIsSha256OfTheBinding() {
        let binding = "BoNwk8j7JP57dhH-ZkAF6rqhcWnfKWwrT1bIuVOpLtc"
        XCTAssertEqual(BatchRequestHash.clientDataHash(binding: binding), Data(SHA256.hash(data: Data(binding.utf8))))
    }

    // MARK: - Content-Digest

    func testContentDigestOfAnEmptyObject() {
        XCTAssertEqual(HTTPMessageSignature.contentDigest(body: Data("{}".utf8)),
                       "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:")
    }

    func testContentDigestOfTheRegistrationBody() {
        XCTAssertEqual(HTTPMessageSignature.contentDigest(body: Data(IOSRegistration.body.utf8)),
                       IOSRegistration.headers["Content-Digest"])
    }

    // MARK: - Signature base

    func testSignatureParamsMatchTheVector() {
        let params = HTTPMessageSignature.signatureParams(components: IOSRegistration.components,
                                                          created: IOSRegistration.created,
                                                          keyId: IOSRegistration.keyId)
        XCTAssertEqual("wp=" + params, IOSRegistration.signatureInput)
    }

    func testRegistrationSignatureBaseIsRebuiltByteForByte() {
        let params = HTTPMessageSignature.signatureParams(components: IOSRegistration.components,
                                                          created: IOSRegistration.created,
                                                          keyId: IOSRegistration.keyId)
        let base = HTTPMessageSignature.signatureBase(method: "post", targetURI: IOSRegistration.targetURI,
                                                      headers: IOSRegistration.headers,
                                                      components: IOSRegistration.components,
                                                      signatureParams: params)
        XCTAssertEqual(base, IOSRegistration.signatureBase)
        XCTAssertFalse(base?.hasSuffix("\n") ?? true)
    }

    func testTheVectorSignatureVerifiesOverTheRebuiltBase() throws {
        XCTAssertTrue(try verifies(base: IOSRegistration.signatureBase,
                                   rawSignatureBase64: IOSRegistration.signatureRaw,
                                   jwk: IOSRegistration.publicJWK))
    }

    func testTheAndroidStatusVectorAlsoVerifies() throws {
        let params = HTTPMessageSignature.signatureParams(components: AndroidStatus.components,
                                                          created: 1794556800,
                                                          keyId: "kc_AsxzLRyGU7LlE4hEDy7XLCYZvR77pyE6wfYqHbFI")
        let base = try XCTUnwrap(HTTPMessageSignature.signatureBase(method: "POST", targetURI: AndroidStatus.targetURI,
                                                                    headers: AndroidStatus.headers,
                                                                    components: AndroidStatus.components,
                                                                    signatureParams: params))
        XCTAssertTrue(try verifies(base: base, rawSignatureBase64: AndroidStatus.signatureRaw, jwk: AndroidStatus.publicJWK))
    }

    func testHeaderLookupIgnoresCaseAndTrimsValues() {
        let headers = ["x-wallet-unit-nonce": "  n-1 ", "X-WALLET-UNIT-PLATFORM": "ios"]
        let base = HTTPMessageSignature.signatureBase(method: "POST", targetURI: "https://wp.example/x",
                                                      headers: headers,
                                                      components: ["x-wallet-unit-nonce", "x-wallet-unit-platform"],
                                                      signatureParams: "()")
        XCTAssertEqual(base, "\"x-wallet-unit-nonce\": n-1\n\"x-wallet-unit-platform\": ios\n\"@signature-params\": ()")
    }

    func testAMissingCoveredHeaderGivesNoBase() {
        XCTAssertNil(HTTPMessageSignature.signatureBase(method: "POST", targetURI: "https://wp.example/x",
                                                        headers: [:], components: ["content-digest"],
                                                        signatureParams: "()"))
    }

    // MARK: - Request key and signing

    func testTheRequestKeyGivesTheVectorJwkAndKeyId() throws {
        let key = try softwareKey(hex: IOSRegistration.privateScalarHex)
        XCTAssertEqual(key.publicJWK["x"] as? String, IOSRegistration.publicJWK["x"] as? String)
        XCTAssertEqual(key.publicJWK["y"] as? String, IOSRegistration.publicJWK["y"] as? String)
        XCTAssertEqual(key.keyId, IOSRegistration.keyId)
    }

    func testSignProducesTheVectorHeadersAndAVerifyingSignature() throws {
        let key = try softwareKey(hex: IOSRegistration.privateScalarHex)
        let signed = try XCTUnwrap(HTTPMessageSignature.sign(method: "POST", targetURI: IOSRegistration.targetURI,
                                                             headers: IOSRegistration.headers,
                                                             components: IOSRegistration.components,
                                                             created: IOSRegistration.created, key: key))
        XCTAssertEqual(signed.signatureInput, IOSRegistration.signatureInput)
        XCTAssertEqual(signed.signatureBase, IOSRegistration.signatureBase)
        // ECDSA signatures are randomised: check the form and that it verifies.
        XCTAssertTrue(signed.signature.hasPrefix("wp=:") && signed.signature.hasSuffix(":"))
        let raw = String(signed.signature.dropFirst(4).dropLast())
        XCTAssertEqual(Data(base64Encoded: raw)?.count, 64)
        XCTAssertTrue(try verifies(base: signed.signatureBase, rawSignatureBase64: raw, jwk: IOSRegistration.publicJWK))
    }

    func testTheRequestKeyHeaderIsTheBase64UrlJsonOfThePublicJwk() throws {
        let decoded = try XCTUnwrap(Data(base64URLEncoded: IOSRegistration.requestKeyHeader))
        let jwk = try XCTUnwrap(JSONSerialization.jsonObject(with: decoded) as? [String: Any])
        XCTAssertEqual(JWKThumbprint.rfc7638(of: jwk), IOSRegistration.keyId)
    }
}
