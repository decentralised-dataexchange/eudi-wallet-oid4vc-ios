//
//  StubURLProtocol.swift
//  eudiWalletOidcIosTests
//

import Foundation

/// Serves canned responses so offer-fetch tests stay offline.
///
/// Installed on a `URLSession` that is handed to `CredentialOfferResolver`, which already accepts
/// one so this is possible without touching production code.
final class StubURLProtocol: URLProtocol {

    /// Answers a request, or throws to simulate a transport failure.
    static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    static func session() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    static func respond(status: Int = 200, contentType: String? = "application/json", body: String) {
        handler = { request in
            var headers: [String: String] = [:]
            if let contentType { headers["Content-Type"] = contentType }
            let response = HTTPURLResponse(
                url: request.url!, statusCode: status, httpVersion: nil, headerFields: headers
            )!
            return (response, Data(body.utf8))
        }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = StubURLProtocol.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
