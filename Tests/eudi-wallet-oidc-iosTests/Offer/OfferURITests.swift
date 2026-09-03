//
//  OfferURITests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

final class OfferURITests: XCTestCase {

    func testReadsAQueryParameter() {
        let link = "openid-credential-offer://?credential_offer=%7B%22a%22:1%7D"
        XCTAssertEqual(OfferURI.queryParameter("credential_offer", in: link), "{\"a\":1}")
    }

    func testReturnsNilForAMissingParameter() {
        XCTAssertNil(OfferURI.queryParameter("credential_offer_uri", in: "openid://?credential_offer=%7B%7D"))
        XCTAssertNil(OfferURI.queryParameter("credential_offer", in: "openid://"))
        XCTAssertNil(OfferURI.queryParameter("credential_offer", in: nil))
    }

    func testIgnoresTheFragment() {
        XCTAssertNil(OfferURI.queryParameter("credential_offer", in: "openid://#?credential_offer=x"))
    }

    /// Custom schemes are the norm for offer links, so this must not assume http(s).
    func testReadsTheScheme() {
        XCTAssertEqual(OfferURI.scheme(of: "openid-credential-offer://?x=1"), "openid-credential-offer")
        XCTAssertEqual(OfferURI.scheme(of: "HTTPS://example.com"), "https")
        XCTAssertNil(OfferURI.scheme(of: "no-scheme-here"))
        XCTAssertNil(OfferURI.scheme(of: "1nvalid://x"))
    }
}
