//
//  CertificateExtensionTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

/// The SAN and AuthorityKeyIdentifier reads must not depend on the build: an optimised build
/// once returned nothing for both (#373). Run with `swift test -c release -Xswiftc -enable-testing`
/// to cover the optimised build.
final class CertificateExtensionTests: XCTestCase {

    func testDnsNamesOfLeaf() {
        let leaf = CertificateFixtures.certificate(CertificateFixtures.leaf)
        XCTAssertEqual(RequestObjectCertificates.dnsNames(leaf), ["verifier.example.com"])
    }

    func testUriNamesOfLeaf() {
        let leaf = CertificateFixtures.certificate(CertificateFixtures.leaf)
        XCTAssertEqual(RequestObjectCertificates.uriNames(leaf), ["https://verifier.example.com/callback"])
    }

    func testAuthorityKeyIdentifierOfLeaf() {
        let leaf = CertificateFixtures.certificate(CertificateFixtures.leaf)
        XCTAssertEqual(TrustedAuthorityMatcher.authorityKeyIdentifier(leaf), CertificateFixtures.leafAuthorityKeyId)
    }
}
