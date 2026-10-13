//
//  RequestUriMethodTests.swift
//
//  OpenID4VP 1.0 section 5.10 and 5.10.1: Request URI Method `post`. Mirrors the Android SDK's
//  RequestUriMethodTest and RequestUriMethodFetchTest.
//

import XCTest
import JOSESwift
@testable import eudiWalletOidcIos

final class RequestUriMethodTests: XCTestCase {

    private let base = "openid4vp://?request_uri=https%3A%2F%2Fverifier.example%2Freq%2F1&client_id=x509_san_dns%3Averifier.example"

    func testPostIsUsedOnlyWhenRequestUriMethodIsPost() {
        XCTAssertTrue(RequestUriMethod.isPost("\(base)&request_uri_method=post"))
        XCTAssertTrue(RequestUriMethod.isPost("\(base)&request_uri_method=POST"))
        XCTAssertFalse(RequestUriMethod.isPost("\(base)&request_uri_method=get"))
        XCTAssertFalse(RequestUriMethod.isPost(base))
        XCTAssertFalse(RequestUriMethod.isPost("not a uri"))
    }

    func testRequestUriIsReadAndPercentDecoded() {
        let uri = "openid4vp://?client_id=x509_san_dns%3Averifier.example&request_uri=https%3A%2F%2Fverifier.example%2Freq%2F1%3Fa%3Db%26c%3Dd&request_uri_method=post"
        XCTAssertEqual(RequestUriMethod.requestUri(uri), "https://verifier.example/req/1?a=b&c=d")
        XCTAssertNil(RequestUriMethod.requestUri("openid4vp://?client_id=x"))
        XCTAssertNil(RequestUriMethod.requestUri("openid4vp://?request_uri="))
    }

    func testWalletNonceIsFreshAndUrlSafe() {
        let a = RequestUriMethod.newWalletNonce()
        let b = RequestUriMethod.newWalletNonce()
        XCTAssertNotEqual(a, b)
        XCTAssertNotNil(a.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression))
    }

    func testRequestObjectMustEchoTheNonceTheWalletSent() {
        XCTAssertTrue(RequestUriMethod.nonceAccepted(sent: nil, received: nil))
        XCTAssertTrue(RequestUriMethod.nonceAccepted(sent: nil, received: "anything"))
        XCTAssertTrue(RequestUriMethod.nonceAccepted(sent: "n1", received: "n1"))
        XCTAssertFalse(RequestUriMethod.nonceAccepted(sent: "n1", received: nil))
        XCTAssertFalse(RequestUriMethod.nonceAccepted(sent: "n1", received: "n2"))
    }

    func testWalletMetadataAdvertisesTheFormatsAndPrefixesTheSdkSupports() throws {
        let json = try metadataJson(RequestUriMethod.walletMetadata())
        let formats = json["vp_formats_supported"] as? [String: Any]
        let sdJwt = formats?["dc+sd-jwt"] as? [String: Any]
        XCTAssertEqual((sdJwt?["sd-jwt_alg_values"] as? [String])?.first, "ES256")
        let mdoc = formats?["mso_mdoc"] as? [String: Any]
        XCTAssertEqual((mdoc?["deviceauth_alg_values"] as? [Int])?.first, -7)
        XCTAssertTrue((json["client_id_prefixes_supported"] as? [String])?.contains("x509_san_dns") ?? false)
        XCTAssertTrue((json["response_modes_supported"] as? [String])?.contains("direct_post.jwt") ?? false)
        XCTAssertNil(json["jwks"])
    }

    func testWalletMetadataCarriesOnlyThePublicHalfOfTheEncryptionKey() throws {
        let key = try XCTUnwrap(RequestUriMethod.newEncryptionKey())
        let json = try metadataJson(RequestUriMethod.walletMetadata(encryptionKey: key))
        let keys = (json["jwks"] as? [String: Any])?["keys"] as? [[String: Any]]
        let jwk = try XCTUnwrap(keys?.first)
        XCTAssertEqual(jwk["kty"] as? String, "EC")
        XCTAssertEqual(jwk["use"] as? String, "enc")
        XCTAssertEqual(jwk["kid"] as? String, key["kid"])
        XCTAssertNil(jwk["d"])
        let algs = json["request_object_encryption_alg_values_supported"] as? [String] ?? []
        XCTAssertTrue(algs.contains("ECDH-ES") && algs.contains("ECDH-ES+A256KW"))
        XCTAssertTrue((json["request_object_encryption_enc_values_supported"] as? [String])?.contains("A128GCM") ?? false)
    }

    func testAnEncryptedRequestObjectIsOpenedWithTheFetchKey() throws {
        let key = try XCTUnwrap(RequestUriMethod.newEncryptionKey())
        let signedRequest = "eyJhbGciOiJFUzI1NiJ9.eyJ3YWxsZXRfbm9uY2UiOiJuMSJ9.c2ln"
        let jwe = try Self.encrypt(signedRequest, to: RequestUriMethod.publicJwk(of: key), alg: .ECDH_ES, enc: .A128GCM)
        XCTAssertEqual(RequestUriMethod.unwrapEncrypted(jwe, key: key), signedRequest)
        XCTAssertEqual(RequestUriMethod.unwrapEncrypted(signedRequest, key: key), signedRequest)
        // A verifier may pick the key-wrap variant, as the SCA payment verifier did on 2026-10-13.
        let jweKeyWrap = try Self.encrypt(signedRequest, to: RequestUriMethod.publicJwk(of: key), alg: .ECDH_ES_A256KW, enc: .A256GCM)
        XCTAssertEqual(RequestUriMethod.unwrapEncrypted(jweKeyWrap, key: key), signedRequest)
        let otherKey = try XCTUnwrap(RequestUriMethod.newEncryptionKey())
        XCTAssertNil(RequestUriMethod.unwrapEncrypted(jwe, key: otherKey))
    }

    private func metadataJson(_ string: String) throws -> [String: Any] {
        let data = try XCTUnwrap(string.data(using: .utf8))
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    static func encrypt(_ payload: String, to jwk: ECPublicKey, alg: KeyManagementAlgorithm, enc: ContentEncryptionAlgorithm) throws -> String {
        let header = JWEHeader(keyManagementAlgorithm: alg, contentEncryptionAlgorithm: enc)
        let encrypter = try XCTUnwrap(Encrypter(keyManagementAlgorithm: alg, contentEncryptionAlgorithm: enc, encryptionKey: jwk))
        let jwe = try JWE(header: header, payload: Payload(payload.data(using: .utf8)!), encrypter: encrypter)
        return jwe.compactSerializedString
    }
}

/// Section 5.10 and 5.10.1 exercised through the real fetch path against a mock verifier. The mock
/// uses the `redirect_uri` prefix, whose request object is unsigned by definition (section 5.9), so
/// the path runs without the certificate handling the x509 prefixes need. The method, nonce and
/// encryption rules under test do not depend on the prefix.
final class RequestUriMethodFetchTests: XCTestCase {

    private let clientId = "redirect_uri:https://verifier.example/response"
    private let requestUri = "https://verifier.example/request/1"
    private var session: URLSession!

    override func setUp() {
        super.setUp()
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RequestUriMethodVerifierProtocol.self]
        session = URLSession(configuration: config)
        RequestUriMethodVerifierProtocol.recorded = []
    }

    private func authorisationRequest(method: String? = nil) -> String {
        let uri = requestUri.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? ""
        let client = clientId.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? ""
        let suffix = method.map { "&request_uri_method=\($0)" } ?? ""
        return "openid4vp://?client_id=\(client)&request_uri=\(uri)\(suffix)"
    }

    /// A request object, optionally echoing [walletNonce], as the verifier would mint it.
    private func requestObject(walletNonce: String?) -> String {
        var claims: [String: Any] = [
            "client_id": clientId,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "response_uri": "https://verifier.example/response",
            "nonce": "n-verifier",
            "dcql_query": ["credentials": [[
                "id": "pid", "format": "dc+sd-jwt",
                "meta": ["vct_values": ["urn:eudi:pid:1"]],
                "claims": [["path": ["family_name"]]]
            ]]]
        ]
        if let walletNonce = walletNonce { claims["wallet_nonce"] = walletNonce }
        let header = try! JSONSerialization.data(withJSONObject: ["alg": "none", "typ": "oauth-authz-req+jwt"])
        let payload = try! JSONSerialization.data(withJSONObject: claims)
        return "\(Self.base64Url(header)).\(Self.base64Url(payload))."
    }

    private static func base64Url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Answers the way a section 5.10 verifier does: echoes the nonce, encrypts when asked.
    private func verifier(echoNonce: Bool = true, encrypt: Bool = false, status: Int = 200) {
        RequestUriMethodVerifierProtocol.handler = { request, form in
            if status != 200 {
                let body = #"{"error":"invalid_request","error_description":"refused"}"#
                return (status, "application/json", body)
            }
            let nonce = echoNonce ? form["wallet_nonce"] : nil
            var body = self.requestObject(walletNonce: nonce)
            if encrypt {
                let metadata = try JSONSerialization.jsonObject(with: form["wallet_metadata"]!.data(using: .utf8)!) as! [String: Any]
                let jwk = ((metadata["jwks"] as! [String: Any])["keys"] as! [[String: Any]])[0]
                let walletKey = try ECPublicKey(data: try JSONSerialization.data(withJSONObject: jwk))
                body = try RequestUriMethodTests.encrypt(body, to: walletKey, alg: .ECDH_ES_A256KW, enc: .A256GCM)
            }
            return (200, "application/oauth-authz-req+jwt", body)
        }
    }

    private func fetch(method: String?) async -> (PresentationRequest?, EUDIError?) {
        let service = VerificationService(keyhandler: RequestUriStubKeyHandler())
        service.requestObjectSession = session
        return await service.processAuthorisationRequest(data: authorisationRequest(method: method))
    }

    private var recorded: RequestUriMethodVerifierProtocol.Recorded { RequestUriMethodVerifierProtocol.recorded[0] }

    func testWithoutRequestUriMethodTheRequestObjectIsFetchedByGet() async {
        verifier()
        let (request, error) = await fetch(method: nil)
        XCTAssertEqual(recorded.method, "GET")
        XCTAssertTrue(recorded.form.isEmpty)
        XCTAssertNil(error)
        XCTAssertEqual(request?.clientId, clientId)
    }

    func testRequestUriMethodGetIsAPlainGet() async {
        verifier()
        _ = await fetch(method: "get")
        XCTAssertEqual(recorded.method, "GET")
    }

    func testRequestUriMethodPostSendsAFormWithWalletMetadataAndWalletNonce() async throws {
        verifier()
        let (request, error) = await fetch(method: "post")
        XCTAssertEqual(recorded.method, "POST")
        XCTAssertTrue(recorded.headers["Content-Type"]?.hasPrefix("application/x-www-form-urlencoded") ?? false)
        XCTAssertEqual(recorded.headers["Accept"], "application/oauth-authz-req+jwt")
        let metadata = try JSONSerialization.jsonObject(with: try XCTUnwrap(recorded.form["wallet_metadata"]?.data(using: .utf8))) as? [String: Any]
        XCTAssertNotNil(metadata?["vp_formats_supported"])
        XCTAssertEqual(((metadata?["jwks"] as? [String: Any])?["keys"] as? [Any])?.count, 1)
        XCTAssertGreaterThanOrEqual(recorded.form["wallet_nonce"]?.count ?? 0, 32)
        XCTAssertNil(error)
        XCTAssertEqual(request?.walletNonce, recorded.form["wallet_nonce"])
        XCTAssertNotNil(request?.request)
    }

    func testARequestObjectThatDoesNotEchoTheWalletNonceIsRefused() async {
        verifier(echoNonce: false)
        let (request, error) = await fetch(method: "post")
        XCTAssertNil(request)
        XCTAssertEqual(error?.message, "Request validation failed")
    }

    func testAnEncryptedRequestObjectIsOpenedAndThenCheckedLikeAPlainOne() async {
        verifier(encrypt: true)
        let (request, error) = await fetch(method: "post")
        XCTAssertNil(error)
        XCTAssertEqual(request?.walletNonce, recorded.form["wallet_nonce"])
        XCTAssertEqual(request?.clientId, clientId)
        // The request object, not the JWE, is what the rest of the flow sees.
        XCTAssertEqual(request?.request?.filter { $0 == "." }.count, 2)
    }

    func testAnEncryptedRequestObjectThatDropsTheNonceIsRefused() async {
        verifier(echoNonce: false, encrypt: true)
        let (request, error) = await fetch(method: "post")
        XCTAssertNil(request)
        XCTAssertEqual(error?.message, "Request validation failed")
    }

    func testAnHttpErrorFromTheVerifierTerminatesTheProcess() async {
        verifier(status: 400)
        let (request, error) = await fetch(method: "post")
        XCTAssertNil(request)
        XCTAssertNotNil(error)
        XCTAssertTrue(error?.message?.contains("refused") ?? false, error?.message ?? "nil")
    }
}

private final class RequestUriStubKeyHandler: NSObject, SecureKeyProtocol {
    var keyStorageType: SecureKeyTypes = .cryptoKit
    func generateSecureKey() -> SecureKeyData? { nil }
    func sign(payload: String, header: Data, withKey privateKey: Data?) -> String? { nil }
    func getJWK(publicKey: Data) -> [String: Any]? { nil }
    func getSecurePrivateKey() -> SecKey? { nil }
}

/// Mock verifier: records each request (method, headers, decoded form) and answers via `handler`.
final class RequestUriMethodVerifierProtocol: URLProtocol {
    struct Recorded { let method: String; let headers: [String: String]; let form: [String: String] }
    static var recorded: [Recorded] = []
    static var handler: ((URLRequest, [String: String]) throws -> (Int, String, String))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        let form = Self.form(from: Self.body(of: request))
        Self.recorded.append(Recorded(method: request.httpMethod ?? "GET", headers: request.allHTTPHeaderFields ?? [:], form: form))
        do {
            let (status, contentType, body) = try Self.handler!(request, form)
            let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": contentType])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body.data(using: .utf8)!)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    private static func body(of request: URLRequest) -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open(); defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }

    private static func form(from data: Data) -> [String: String] {
        guard let body = String(data: data, encoding: .utf8), !body.isEmpty else { return [:] }
        var result: [String: String] = [:]
        for pair in body.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let key = String(parts[0]).removingPercentEncoding ?? String(parts[0])
            let value = parts.count > 1 ? (String(parts[1]).replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? String(parts[1])) : ""
            result[key] = value
        }
        return result
    }
}
