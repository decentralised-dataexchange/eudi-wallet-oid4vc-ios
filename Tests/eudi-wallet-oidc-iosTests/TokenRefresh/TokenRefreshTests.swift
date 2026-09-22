//
//  TokenRefreshTests.swift
//

import XCTest
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
