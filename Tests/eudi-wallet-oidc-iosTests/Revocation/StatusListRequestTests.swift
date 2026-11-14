//
//  StatusListRequestTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

/// The status list request skips the local HTTP cache unless the caller asks for it, so a
/// revocation is seen at once rather than after the server's `Cache-Control: max-age`.
final class StatusListRequestTests: XCTestCase {

    private let url = URL(string: "https://issuer.example/statuslists/1")!

    func testByDefaultTheCacheIsSkipped() {
        let request = StatusListRequest.make(url, accept: "application/statuslist+jwt", useCache: false)

        XCTAssertEqual(request.cachePolicy, .reloadIgnoringLocalCacheData)
        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Accept"), "application/statuslist+jwt")
    }

    func testWithUseCacheTheServersCacheHeadersApply() {
        let request = StatusListRequest.make(url, useCache: true)

        XCTAssertEqual(request.cachePolicy, .useProtocolCachePolicy)
        XCTAssertNil(request.value(forHTTPHeaderField: "Accept"))
    }
}
