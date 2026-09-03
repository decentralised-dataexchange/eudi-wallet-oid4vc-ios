//
//  AuthorizationServerSelectorTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

/// OpenID4VCI 1.0 section 12.2.4 and the `authorization_server` grant parameter.
final class AuthorizationServerSelectorTests: XCTestCase {

    private let selector = AuthorizationServerSelector()
    private let issuer = "https://issuer.example.com"

    /// Built through the real parser, so the fixtures are documents an issuer could actually send.
    private func config(servers: String? = nil, singular: String? = nil) throws -> IssuerWellKnownConfiguration {
        var fields = [
            "\"credential_issuer\":\"\(issuer)\"",
            "\"credential_endpoint\":\"\(issuer)/credential\"",
            "\"credential_configurations_supported\":{\"PidSdJwt\":{\"format\":\"dc+sd-jwt\"}}",
        ]
        if let servers { fields.append("\"authorization_servers\":\(servers)") }
        if let singular { fields.append("\"authorization_server\":\"\(singular)\"") }
        let json = "{" + fields.joined(separator: ",") + "}"
        return try OpenId4VciV1IssuerMetadataParser().parse(Data(json.utf8))
    }

    /// "If this parameter is omitted, the entity providing the Credential Issuer is also acting as
    /// the Authorization Server."
    func testAbsentServersMakesTheCredentialIssuerItsOwnAuthorizationServer() throws {
        let selection = try selector.select(issuerConfig: config())
        XCTAssertEqual(selection.identifier, issuer)
        XCTAssertEqual(selection.source, .credentialIssuer)
    }

    /// The draft-era singular parameter, which the model merges into the same array.
    func testTheDraftSingularParameterIsUsedWhenPresent() throws {
        let selection = try selector.select(issuerConfig: config(singular: "https://as.example.com/auth-mock"))
        XCTAssertEqual(selection.identifier, "https://as.example.com/auth-mock")
        XCTAssertEqual(selection.source, .soleEntry)
    }

    func testASingleEntryIsUsed() throws {
        let selection = try selector.select(issuerConfig: config(servers: "[\"https://as.example.com\"]"))
        XCTAssertEqual(selection.identifier, "https://as.example.com")
        XCTAssertEqual(selection.source, .soleEntry)
    }

    func testAMatchingOfferHintPicksItsEntryOutOfSeveral() throws {
        let selection = try selector.select(
            issuerConfig: config(servers: "[\"https://as-a.example.com\",\"https://as-b.example.com\"]"),
            hint: "https://as-b.example.com"
        )
        XCTAssertEqual(selection.identifier, "https://as-b.example.com")
        XCTAssertEqual(selection.source, .offerHint)
    }

    /// "the Wallet MUST NOT proceed with the flow if the authorization_server Credential Offer
    /// parameter value does not match any of the entries in the authorization_servers array."
    func testANonMatchingOfferHintStopsTheFlow() throws {
        let config = try config(servers: "[\"https://as-a.example.com\",\"https://as-b.example.com\"]")
        XCTAssertThrowsError(try selector.select(issuerConfig: config, hint: "https://attacker.example.com")) { error in
            XCTAssertTrue((error as? DiscoveryError)?.errorDescription?.contains("does not list") == true)
        }
    }

    func testANonMatchingHintAgainstASingleEntryAlsoStopsTheFlow() throws {
        let config = try config(servers: "[\"https://as-a.example.com\"]")
        XCTAssertThrowsError(try selector.select(issuerConfig: config, hint: "https://other.example.com"))
    }

    func testSeveralEntriesAndNoHintTakeTheFirst() throws {
        let selection = try selector.select(
            issuerConfig: config(servers: "[\"https://as-a.example.com\",\"https://as-b.example.com\"]")
        )
        XCTAssertEqual(selection.identifier, "https://as-a.example.com")
        XCTAssertEqual(selection.source, .firstOfSeveral)
        XCTAssertEqual(selection.candidates.count, 2)
    }

    func testNoIssuerAndNoServersIsRejected() {
        let empty = IssuerWellKnownConfiguration(
            from: EUDIError(from: ErrorResponse(message: nil, code: nil))
        )
        XCTAssertThrowsError(try selector.select(issuerConfig: empty))
    }
}
