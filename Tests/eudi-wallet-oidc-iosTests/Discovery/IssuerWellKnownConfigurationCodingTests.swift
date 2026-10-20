//
//  IssuerWellKnownConfigurationCodingTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

/// Wallets persist `IssuerWellKnownConfiguration` inside every credential record, so a document
/// written by an earlier SDK has to keep decoding after a field is added.
final class IssuerWellKnownConfigurationCodingTests: XCTestCase {

    /// `declaresAuthorizationServers` did not exist when these were stored. A synthesised decoder
    /// treats a non-optional key as required and would have refused them -- and the wallet's
    /// lenient decoding would have turned that into an empty issuer configuration on every
    /// existing credential.
    func testAStoredConfigurationWithoutTheAuthorizationServersFlagStillDecodes() throws {
        let stored = """
        {"credentialIssuer":"https://issuer.example.com",
         "authorizationServer":["https://as-a.example.com","https://as-b.example.com"],
         "credentialEndpoint":"https://issuer.example.com/credential"}
        """
        let config = try JSONDecoder().decode(IssuerWellKnownConfiguration.self, from: Data(stored.utf8))
        XCTAssertEqual(config.credentialIssuer, "https://issuer.example.com")
        XCTAssertEqual(config.authorizationServer?.count, 2)
        XCTAssertEqual(config.credentialEndpoint, "https://issuer.example.com/credential")
        XCTAssertFalse(config.declaresAuthorizationServers)
        XCTAssertNil(config.version)
    }

    func testAnEmptyDocumentDecodes() throws {
        let config = try JSONDecoder().decode(IssuerWellKnownConfiguration.self, from: Data("{}".utf8))
        XCTAssertFalse(config.declaresAuthorizationServers)
        XCTAssertNil(config.credentialIssuer)
    }

    /// Parsed from the wire, stored, read back: the flag and the version survive the round trip.
    func testTheFlagAndTheVersionSurviveARoundTrip() throws {
        let metadata = """
        {"credential_issuer":"https://issuer.example.com",
         "credential_endpoint":"https://issuer.example.com/credential",
         "authorization_servers":["https://as.example.com"],
         "credential_configurations_supported":{"PID":{"format":"dc+sd-jwt"}}}
        """
        let parsed = try OpenId4VciV1IssuerMetadataParser().parse(Data(metadata.utf8))
        XCTAssertTrue(parsed.declaresAuthorizationServers)

        let restored = try JSONDecoder().decode(
            IssuerWellKnownConfiguration.self, from: JSONEncoder().encode(parsed)
        )
        XCTAssertTrue(restored.declaresAuthorizationServers)
        XCTAssertEqual(restored.version, 2)
        XCTAssertEqual(restored.authorizationServer, ["https://as.example.com"])
    }
}
