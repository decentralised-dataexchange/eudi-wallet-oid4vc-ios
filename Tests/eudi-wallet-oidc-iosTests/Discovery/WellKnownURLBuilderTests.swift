//
//  WellKnownURLBuilderTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

/// OpenID4VCI 1.0 section 12.2.2 and RFC 8414 section 3 both insert the well-known string between
/// the host and the path. The two worked examples below are the specification's own.
final class WellKnownURLBuilderTests: XCTestCase {

    private let wellKnown = WellKnownURLBuilder.openIdCredentialIssuer

    func testInsertionFormPlacesTheWellKnownBetweenHostAndPath() {
        XCTAssertEqual(
            WellKnownURLBuilder.insertionForm("https://issuer.example.com/tenant", wellKnown: wellKnown),
            "https://issuer.example.com/.well-known/openid-credential-issuer/tenant"
        )
    }

    func testInsertionFormOnABareHostAppendsOnly() {
        XCTAssertEqual(
            WellKnownURLBuilder.insertionForm("https://tenant.issuer.example.com", wellKnown: wellKnown),
            "https://tenant.issuer.example.com/.well-known/openid-credential-issuer"
        )
    }

    func testInsertionFormKeepsThePort() {
        XCTAssertEqual(
            WellKnownURLBuilder.insertionForm("http://localhost:8080/tenant", wellKnown: wellKnown),
            "http://localhost:8080/.well-known/openid-credential-issuer/tenant"
        )
    }

    func testInsertionFormRejectsAValueThatIsNotAnAbsoluteURL() {
        XCTAssertNil(WellKnownURLBuilder.insertionForm("not a url", wellKnown: wellKnown))
        XCTAssertNil(WellKnownURLBuilder.insertionForm("/tenant", wellKnown: wellKnown))
    }

    func testSuffixFormAppends() {
        XCTAssertEqual(
            WellKnownURLBuilder.suffixForm("https://issuer.example.com/tenant", wellKnown: wellKnown),
            "https://issuer.example.com/tenant/.well-known/openid-credential-issuer"
        )
    }

    func testIdentifierStripsEitherLayout() {
        XCTAssertEqual(
            WellKnownURLBuilder.identifier(from: "https://issuer.example.com/tenant/.well-known/openid-credential-issuer"),
            "https://issuer.example.com/tenant"
        )
        XCTAssertEqual(
            WellKnownURLBuilder.identifier(from: "https://issuer.example.com/.well-known/openid-credential-issuer/tenant"),
            "https://issuer.example.com/tenant"
        )
    }

    func testIdentifierStripsBothAuthorizationServerWellKnowns() {
        XCTAssertEqual(
            WellKnownURLBuilder.identifier(from: "https://as.example.com/.well-known/oauth-authorization-server"),
            "https://as.example.com"
        )
        XCTAssertEqual(
            WellKnownURLBuilder.identifier(from: "https://as.example.com/.well-known/openid-configuration"),
            "https://as.example.com"
        )
    }

    func testIdentifierStripsATrailingSlashAndRejectsBlanks() {
        XCTAssertEqual(WellKnownURLBuilder.identifier(from: "https://issuer.example.com/"), "https://issuer.example.com")
        XCTAssertNil(WellKnownURLBuilder.identifier(from: nil))
        XCTAssertNil(WellKnownURLBuilder.identifier(from: "   "))
    }

    func testCandidatesTryTheSpecFormFirst() {
        let candidates = WellKnownURLBuilder.candidates(
            for: "https://issuer.example.com/tenant", wellKnown: wellKnown, policy: .standard
        )
        XCTAssertEqual(candidates, [
            "https://issuer.example.com/.well-known/openid-credential-issuer/tenant",
            "https://issuer.example.com/tenant/.well-known/openid-credential-issuer",
        ])
    }

    func testCandidatesCollapseToOneWhenTheIdentifierHasNoPath() {
        let candidates = WellKnownURLBuilder.candidates(
            for: "https://issuer.example.com", wellKnown: wellKnown, policy: .standard
        )
        XCTAssertEqual(candidates, ["https://issuer.example.com/.well-known/openid-credential-issuer"])
    }

    func testStrictPolicyOffersOnlyTheSpecForm() {
        let candidates = WellKnownURLBuilder.candidates(
            for: "https://issuer.example.com/tenant", wellKnown: wellKnown, policy: .strict
        )
        XCTAssertEqual(candidates.count, 1)
        XCTAssertTrue(candidates[0].contains("/.well-known/openid-credential-issuer/tenant"))
    }
}
