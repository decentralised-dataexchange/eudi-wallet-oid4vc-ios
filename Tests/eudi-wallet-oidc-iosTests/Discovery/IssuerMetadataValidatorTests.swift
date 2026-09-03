//
//  IssuerMetadataValidatorTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

/// OpenID4VCI 1.0 section 12.2.4, applied only to the revision that defines each rule.
final class IssuerMetadataValidatorTests: XCTestCase {

    private let validator = IssuerMetadataValidator()
    private let identifier = "https://issuer.example.com"

    private var enforcing: DiscoveryPolicy {
        var policy = DiscoveryPolicy.standard
        policy.requireIssuerIdentifierMatch = true
        return policy
    }

    private func validate(
        _ json: String,
        version: IssuerMetadataSpecVersion = .v1_0,
        policy: DiscoveryPolicy = .standard
    ) throws -> IssuerWellKnownConfiguration {
        let parser: IssuerMetadataParser = version == .v1_0
            ? OpenId4VciV1IssuerMetadataParser()
            : DraftIssuerMetadataParser()
        let config = try parser.parse(Data(json.utf8))
        return try validator.validate(
            config, specVersion: version, expectedIdentifier: identifier, policy: policy
        )
    }

    private func conformant(issuer: String? = nil, extra: String = "") -> String {
        """
        {"credential_issuer":"\(issuer ?? identifier)",
         "credential_endpoint":"\(identifier)/credential"\(extra),
         "credential_configurations_supported":{"PidSdJwt":{"format":"dc+sd-jwt"}}}
        """
    }

    func testAConformantDocumentPasses() throws {
        let result = try validate(conformant())
        XCTAssertEqual(result.credentialIssuer, identifier)
    }

    /// "If these values are not identical ... the data contained in the response MUST NOT be used."
    func testAMismatchedIssuerIsRejectedWhenTheCheckIsEnabled() {
        XCTAssertThrowsError(
            try validate(conformant(issuer: "https://attacker.example.com"), policy: enforcing)
        ) { error in
            XCTAssertTrue((error as? DiscoveryError)?.errorDescription?.contains("different issuer") == true)
        }
    }

    /// Off by default: deployed issuers answer at one path while declaring another -- the iGrant
    /// issuers serve at `<base>/service` and declare `<base>/service/version-01` -- so enforcing it
    /// rejects a working issuer.
    func testAMismatchedIssuerIsToleratedByDefault() throws {
        let result = try validate(conformant(issuer: "\(identifier)/version-01"))
        XCTAssertEqual(result.credentialIssuer, "\(identifier)/version-01")
    }

    func testATrailingSlashDoesNotFailTheIdentityCheck() throws {
        _ = try validate(conformant(issuer: "\(identifier)/"), policy: enforcing)
    }

    func testAMissingCredentialIssuerIsRejectedForOneZero() {
        let json = """
        {"credential_endpoint":"\(identifier)/credential",
         "credential_configurations_supported":{"PidSdJwt":{"format":"dc+sd-jwt"}}}
        """
        XCTAssertThrowsError(try validate(json))
    }

    func testAMissingCredentialEndpointIsRejectedForOneZeroAndAllowedForDrafts() throws {
        let oneZero = """
        {"credential_issuer":"\(identifier)",
         "credential_configurations_supported":{"PidSdJwt":{"format":"dc+sd-jwt"}}}
        """
        XCTAssertThrowsError(try validate(oneZero))

        let draft = """
        {"credential_issuer":"\(identifier)",
         "credentials_supported":[{"format":"jwt_vc","types":["VerifiableCredential"]}]}
        """
        _ = try validate(draft, version: .draft)
    }

    func testACredentialEndpointOnADisallowedSchemeIsRejected() {
        let json = """
        {"credential_issuer":"\(identifier)","credential_endpoint":"file:///etc/passwd",
         "credential_configurations_supported":{"PidSdJwt":{"format":"dc+sd-jwt"}}}
        """
        XCTAssertThrowsError(try validate(json)) { error in
            XCTAssertTrue((error as? DiscoveryError)?.errorDescription?.contains("unsupported scheme") == true)
        }
    }

    /// Section 12.2.4 states the https requirement separately for each of these, not only for the
    /// credential endpoint.
    func testTheOtherEndpointsAreSchemeCheckedToo() {
        for field in ["nonce_endpoint", "deferred_credential_endpoint", "notification_endpoint"] {
            let json = conformant(extra: ",\"\(field)\":\"file:///etc/passwd\"")
            XCTAssertThrowsError(try validate(json), "expected \(field) to be rejected") { error in
                XCTAssertTrue(
                    (error as? DiscoveryError)?.errorDescription?.contains("unsupported scheme") == true,
                    "for \(field)"
                )
            }
        }
    }

    func testAnHttpEndpointPassesByDefaultAndFailsUnderStrict() throws {
        let json = """
        {"credential_issuer":"\(identifier)","credential_endpoint":"http://localhost:8080/credential",
         "credential_configurations_supported":{"PidSdJwt":{"format":"dc+sd-jwt"}}}
        """
        _ = try validate(json)
        XCTAssertThrowsError(try validate(json, policy: .strict))
    }
}
