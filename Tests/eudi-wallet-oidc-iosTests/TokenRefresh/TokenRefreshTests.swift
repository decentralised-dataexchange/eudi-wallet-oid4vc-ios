//
//  TokenRefreshTests.swift
//

import XCTest
import CryptoKit
@testable import eudiWalletOidcIos

/// The refresh request body, its headers and the answers it reads (RFC 6749 section 6).
final class TokenRefreshTests: XCTestCase {

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    private func refresh(attestation: WalletAttestation? = nil) async -> (String?, String?) {
        await TokenRefreshService().refresh(
            refreshToken: "refresh-1",
            tokenEndpoint: "https://as.example.com/token",
            attestation: attestation,
            urlSession: StubURLProtocol.session()
        )
    }

    private func capture(status: Int = 200, body: String) -> () -> URLRequest? {
        var seen: URLRequest?
        StubURLProtocol.handler = { request in
            seen = request
            let response = HTTPURLResponse(
                url: request.url!, statusCode: status, httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (response, Data(body.utf8))
        }
        return { seen }
    }

    func testTheRequestIsAFormPostNamingTheRefreshToken() async {
        let seen = capture(body: #"{"access_token":"at-2","refresh_token":"rt-2"}"#)

        let (accessToken, refreshToken) = await refresh()

        let request = seen()
        XCTAssertEqual(request?.httpMethod, "POST")
        XCTAssertEqual(request?.value(forHTTPHeaderField: "Content-Type"), "application/x-www-form-urlencoded")
        let form = request.map { String(decoding: Self.body(of: $0), as: UTF8.self) } ?? ""
        XCTAssertTrue(form.contains("grant_type=refresh_token"), form)
        XCTAssertTrue(form.contains("refresh_token=refresh-1"), form)
        XCTAssertEqual(accessToken, "at-2")
        XCTAssertEqual(refreshToken, "rt-2")
    }

    func testWithoutAnAttestationNoClientAttestationHeadersAreSent() async {
        let seen = capture(body: "{}")

        _ = await refresh()

        XCTAssertNil(seen()?.value(forHTTPHeaderField: "OAuth-Client-Attestation"))
        XCTAssertNil(seen()?.value(forHTTPHeaderField: "OAuth-Client-Attestation-PoP"))
        XCTAssertNil(seen()?.value(forHTTPHeaderField: "DPoP"))
        let form = seen().map { String(decoding: Self.body(of: $0), as: UTF8.self) } ?? ""
        XCTAssertFalse(form.contains("client_id="), form)
    }

    /// RFC 6749 section 3.2.1: the client identifies itself on the refresh as it did on the token
    /// request, by the wallet unit identifier the attestation carries as `sub`.
    func testTheClientIdIsTheAttestationsSubject() async {
        let seen = capture(body: "{}")

        _ = await refresh(attestation: WalletAttestation(attestationJwt: wua(sub: "wallet-unit-1"), proofOfPossession: "pop.jwt"))

        let form = seen().map { String(decoding: Self.body(of: $0), as: UTF8.self) } ?? ""
        XCTAssertTrue(form.contains("client_id=wallet-unit-1"), form)
    }

    /// RFC 9449 section 5: tokens bound to a DPoP key are refreshed with a proof for that key. A
    /// token-endpoint proof names the method and the endpoint and carries no `ath`.
    func testADPoPKeyAddsAProofForTheTokenEndpoint() async {
        let seen = capture(body: "{}")

        _ = await refresh(attestation: attestationWithKey())

        let claims = JWTParts.claims(seen()?.value(forHTTPHeaderField: "DPoP") ?? "")
        XCTAssertEqual(claims?["htm"] as? String, "POST")
        XCTAssertEqual(claims?["htu"] as? String, "https://as.example.com/token")
        XCTAssertNil(claims?["ath"])
        XCTAssertNil(claims?["nonce"])
    }

    /// RFC 9449 section 8: a `DPoP-Nonce` on the refusal is put in the proof and the request sent
    /// again, once.
    func testADPoPNonceChallengeIsRetriedOnceWithTheNonce() async {
        var nonces: [String?] = []
        StubURLProtocol.handler = { request in
            nonces.append(JWTParts.claims(request.value(forHTTPHeaderField: "DPoP") ?? "")?["nonce"] as? String)
            if nonces.count == 1 {
                let challenged = HTTPURLResponse(
                    url: request.url!, statusCode: 400, httpVersion: nil,
                    headerFields: ["Content-Type": "application/json", "DPoP-Nonce": "n-1"]
                )!
                return (challenged, Data(#"{"error":"use_dpop_nonce"}"#.utf8))
            }
            let ok = HTTPURLResponse(
                url: request.url!, statusCode: 200, httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            )!
            return (ok, Data(#"{"access_token":"at-2","refresh_token":"rt-2"}"#.utf8))
        }

        let (accessToken, refreshToken) = await refresh(attestation: attestationWithKey())

        XCTAssertEqual(nonces, [nil, "n-1"])
        XCTAssertEqual(accessToken, "at-2")
        XCTAssertEqual(refreshToken, "rt-2")
    }

    func testASecondNonceChallengeGivesUpRatherThanLooping() async {
        var attempts = 0
        StubURLProtocol.handler = { request in
            attempts += 1
            let challenged = HTTPURLResponse(
                url: request.url!, statusCode: 400, httpVersion: nil,
                headerFields: ["Content-Type": "application/json", "DPoP-Nonce": "n-\(attempts)"]
            )!
            return (challenged, Data(#"{"error":"use_dpop_nonce"}"#.utf8))
        }

        let (accessToken, _) = await refresh(attestation: attestationWithKey())

        XCTAssertEqual(attempts, 2)
        XCTAssertNil(accessToken)
    }

    /// Without a key there is nothing to put a nonce in, so a challenge is just a refusal.
    func testANonceChallengeWithoutAKeyIsNotRetried() async {
        var attempts = 0
        StubURLProtocol.handler = { request in
            attempts += 1
            let challenged = HTTPURLResponse(
                url: request.url!, statusCode: 400, httpVersion: nil,
                headerFields: ["Content-Type": "application/json", "DPoP-Nonce": "n-1"]
            )!
            return (challenged, Data(#"{"error":"use_dpop_nonce"}"#.utf8))
        }

        _ = await refresh()

        XCTAssertEqual(attempts, 1)
    }

    private func attestationWithKey() -> WalletAttestation {
        WalletAttestation(attestationJwt: nil, proofOfPossession: nil, dpopKey: P256.Signing.PrivateKey())
    }

    /// A wallet unit attestation whose payload carries `sub`; the signature is not checked here.
    private func wua(sub: String) -> String {
        let payload = Data("{\"sub\":\"\(sub)\"}".utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "eyJhbGciOiJFUzI1NiJ9.\(payload).signature"
    }

    func testTheAttestationAndItsProofTravelAsHeaders() async {
        let seen = capture(body: "{}")

        // The `~`-terminated form is sanitised, as it is on the token request.
        _ = await refresh(attestation: WalletAttestation(attestationJwt: "wua.jwt~", proofOfPossession: "pop.jwt"))

        XCTAssertEqual(seen()?.value(forHTTPHeaderField: "OAuth-Client-Attestation"), "wua.jwt")
        XCTAssertEqual(seen()?.value(forHTTPHeaderField: "OAuth-Client-Attestation-PoP"), "pop.jwt")
    }

    func testARefusedRefreshYieldsNoTokens() async {
        _ = capture(status: 400, body: #"{"error":"invalid_grant"}"#)

        let (accessToken, refreshToken) = await refresh()

        XCTAssertNil(accessToken)
        XCTAssertNil(refreshToken)
    }

    /// `URLProtocol` hands the body over as a stream, never as `httpBody`.
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
}
