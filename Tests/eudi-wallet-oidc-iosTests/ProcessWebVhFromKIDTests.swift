//
//  ProcessWebVhFromKIDTests.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 09/12/25.
//

import XCTest
@testable import eudiWalletOidcIos

final class ProcessWebVhFromKIDTests: XCTestCase {

    
    override func setUp() {
        super.setUp()
        
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [URLProtocolMock.self]
        URLSession.shared.configuration.protocolClasses = [URLProtocolMock.self]
    }
    
    func testFetchDIDDocument_ParsesCorrectJwk() async throws {
        // GIVEN
        let did = "did:webvh:example.com:user:alice"
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [URLProtocolMock.self]
        let mockSession = URLSession(configuration: config)
        // This is the URL the function will create:
        // https://example.com/user/alice/did.jsonl
        let expectedURL = "https://example.com/user/alice/did.jsonl"
        
        let mockJSON: [[String: Any]] = [
            [
                "value": [
                    "verificationMethod": [
                        [
                            "id": did,
                            "publicKeyJwk": [
                                "kty": "EC",
                                "crv": "P-256",
                                "x": "abc",
                                "y": "xyz"
                            ]
                        ]
                    ]
                ]
            ]
        ]
        
        let data = try JSONSerialization.data(withJSONObject: mockJSON)
        URLProtocolMock.testData = data
        URLProtocolMock.testResponse = HTTPURLResponse(
            url: URL(string: expectedURL)!,
            statusCode: 200,
            httpVersion: nil,
            headerFields: nil
        )
        
        // WHEN
        let result = try await ProcessWebVhFromKID.fetchDIDDocument(did: did, session: mockSession)
        
        // THEN
        XCTAssertNotNil(result, "Expected non-nil JWK dictionary")
        XCTAssertEqual(result?["kty"] as? String, "EC")
        XCTAssertEqual(result?["crv"] as? String, "P-256")
        XCTAssertEqual(result?["x"] as? String, "abc")
        XCTAssertEqual(result?["y"] as? String, "xyz")
    }


}

class URLProtocolMock: URLProtocol {
    static var testData: Data?
    static var testResponse: HTTPURLResponse?
    
    override class func canInit(with request: URLRequest) -> Bool {
        return true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }

    override func startLoading() {
        if let response = URLProtocolMock.testResponse {
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        }
        if let data = URLProtocolMock.testData {
            client?.urlProtocol(self, didLoad: data)
        }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}


