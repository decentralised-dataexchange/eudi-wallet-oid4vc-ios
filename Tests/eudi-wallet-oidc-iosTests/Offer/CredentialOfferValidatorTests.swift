//
//  CredentialOfferValidatorTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

/// OpenID4VCI 1.0 section 4.1.1.
final class CredentialOfferValidatorTests: XCTestCase {

    private let validator = CredentialOfferValidator()
    private let issuer = "https://issuer.example.com"

    /// Built through the real parsers, so the fixtures are documents an issuer could actually send.
    private func offer(_ json: String, version: CredentialOfferSpecVersion = .v1_0) throws -> CredentialOffer {
        let data = Data(json.utf8)
        let parser: CredentialOfferParser = version == .v1_0
            ? OpenId4VciV1OfferParser()
            : EbsiDraftOfferParser()
        return try parser.parse(data)
    }

    private func validate(
        _ json: String,
        version: CredentialOfferSpecVersion = .v1_0
    ) throws -> CredentialOffer {
        try validator.validate(offer(json, version: version), specVersion: version)
    }

    private func assertInvalid(_ json: String, containing text: String, line: UInt = #line) {
        do {
            _ = try validate(json)
            XCTFail("expected the offer to be rejected", line: line)
        } catch let error as CredentialOfferError {
            XCTAssertTrue(
                error.errorDescription?.contains(text) == true,
                "expected a message containing \"\(text)\", got \"\(error.errorDescription ?? "")\"",
                line: line
            )
        } catch {
            XCTFail("unexpected error: \(error)", line: line)
        }
    }

    func testAConformantOfferPasses() throws {
        let result = try validate("""
        {"credential_issuer":"\(issuer)","credential_configuration_ids":["PidSdJwt"]}
        """)
        XCTAssertEqual(result.credentialIssuer, issuer)
        XCTAssertEqual(result.version, "v2")
    }

    func testRejectsAMissingIssuer() {
        assertInvalid("""
        {"credential_configuration_ids":["PidSdJwt"]}
        """, containing: "does not name an issuer")
    }

    func testRejectsAnIssuerThatIsNotAUrl() {
        assertInvalid("""
        {"credential_issuer":"not a url","credential_configuration_ids":["PidSdJwt"]}
        """, containing: "invalid issuer")
    }

    func testRejectsAnEmptyConfigurationIdArray() {
        assertInvalid("""
        {"credential_issuer":"\(issuer)","credential_configuration_ids":[]}
        """, containing: "does not name any credentials")
    }

    /// Section 4.1.1: "a non-empty array of **unique** strings". Duplicates would otherwise be
    /// requested twice.
    func testRejectsDuplicateConfigurationIds() {
        assertInvalid("""
        {"credential_issuer":"\(issuer)","credential_configuration_ids":["PidSdJwt","PidSdJwt"]}
        """, containing: "more than once")
    }

    func testRejectsAPreAuthorizedGrantWithNoCode() {
        assertInvalid("""
        {"credential_issuer":"\(issuer)","credential_configuration_ids":["PidSdJwt"],
         "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"tx_code":{}}}}
        """, containing: "missing its pre-authorized code")
    }

    /// "Object indicating that a Transaction Code is required if present, **even if empty**."
    func testAnEmptyTxCodeStillRequiresACode() throws {
        let result = try validate("""
        {"credential_issuer":"\(issuer)","credential_configuration_ids":["PidSdJwt"],
         "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":
           {"pre-authorized_code":"abc","tx_code":{}}}}
        """)
        let txCode = result.grants?.urnIETFParamsOauthGrantTypePreAuthorizedCode?.txCode
        XCTAssertNotNil(txCode)
        XCTAssertEqual(txCode?.inputMode, "numeric")
        XCTAssertNil(txCode?.length, "a length must never be invented when the issuer declares none")
    }

    func testInputModeDefaultsToNumericAndKeepsText() throws {
        func inputMode(for declared: String) throws -> String? {
            try validate("""
            {"credential_issuer":"\(issuer)","credential_configuration_ids":["PidSdJwt"],
             "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":
               {"pre-authorized_code":"abc","tx_code":{"input_mode":"\(declared)"}}}}
            """).grants?.urnIETFParamsOauthGrantTypePreAuthorizedCode?.txCode?.inputMode
        }
        XCTAssertEqual(try inputMode(for: "text"), "text")
        XCTAssertEqual(try inputMode(for: "numeric"), "numeric")
        XCTAssertEqual(try inputMode(for: "something-else"), "numeric")
    }

    /// "The length of the string MUST NOT exceed 300 characters" -- and it is issuer-controlled
    /// text rendered directly in the PIN screen.
    func testTruncatesAnOverlongDescription() throws {
        let long = String(repeating: "a", count: 400)
        let result = try validate("""
        {"credential_issuer":"\(issuer)","credential_configuration_ids":["PidSdJwt"],
         "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":
           {"pre-authorized_code":"abc","tx_code":{"description":"\(long)"}}}}
        """)
        let description = result.grants?.urnIETFParamsOauthGrantTypePreAuthorizedCode?.txCode?.description
        XCTAssertEqual(description?.count, 300)
    }

    /// Draft type arrays are hierarchies, so the last element is the credential being offered, and
    /// repeats across entries are not the duplicate the 1.0 rule is about.
    func testDraftOffersUseTheLastTypeAndSkipTheUniquenessRule() throws {
        let result = try validate("""
        {"credential_issuer":"\(issuer)","credentials":[
          {"format":"jwt_vc","types":["VerifiableCredential","VerifiableAttestation"]},
          {"format":"jwt_vc","types":["VerifiableCredential","VerifiableAttestation"]}]}
        """, version: .draft)
        XCTAssertEqual(result.version, "v1")
        XCTAssertEqual(result.credentials?.count, 2)
    }
}
