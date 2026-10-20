import XCTest
@testable import eudiWalletOidcIos

/// Queries are given as JSON and decoded with JSONDecoder, exactly as the SDK decodes a
/// `dcql_query` parameter or request object payload, so the tests exercise the same model
/// the live path validates. Shapes that `DCQLQuery` cannot represent fail at decode time;
/// those are covered at the end through `VerificationService`, which reports them with the
/// same error code.
/// The by-value request path never touches the key handler, so the shared `StubKeyHandler` in
/// `Credential/` serves here too.

final class DcqlQueryValidatorTests: XCTestCase {

    private func decode(_ json: String) throws -> DCQLQuery {
        try JSONDecoder().decode(DCQLQuery.self, from: Data(json.utf8))
    }

    private func validate(_ json: String) throws -> [String] {
        DcqlQueryValidator.validate(try decode(json))
    }

    private func assertValid(_ json: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let errors = try validate(json)
        XCTAssertTrue(errors.isEmpty, "expected no violations but got \(errors)", file: file, line: line)
    }

    private func assertViolation(_ json: String, _ expected: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let errors = try validate(json)
        XCTAssertTrue(errors.contains { $0.contains(expected) },
                      "expected a violation containing '\(expected)' but got \(errors)", file: file, line: line)
    }

    private let sdJwtPid = #"{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}"#

    // MARK: valid queries

    func testSdJwtQueryWithVctValuesAndClaimsIsValid() throws {
        try assertValid(#"""
        {"credentials":[{"id":"pid","format":"dc+sd-jwt",
          "meta":{"vct_values":["urn:eudi:pid:1"]},
          "claims":[{"path":["given_name"]},{"path":["address","street_address"]}]}]}
        """#)
    }

    func testMdocQueryWithDoctypeAndTwoComponentPathsIsValid() throws {
        try assertValid(#"""
        {"credentials":[{"id":"mdl","format":"mso_mdoc",
          "meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
          "claims":[{"path":["org.iso.18013.5.1","family_name"],"intent_to_retain":false}]}]}
        """#)
    }

    func testJwtVcJsonQueryWithTypeValuesIsValid() throws {
        try assertValid(#"""
        {"credentials":[{"id":"vc","format":"jwt_vc_json",
          "meta":{"type_values":[["VerifiableCredential","IDCredential"]]},
          "claims":[{"path":["credentialSubject","family_name"]}]}]}
        """#)
    }

    func testLdpVcQueryWithTypeValuesIsValid() throws {
        try assertValid(#"{"credentials":[{"id":"vc","format":"ldp_vc","meta":{"type_values":[["VerifiableCredential"]]}}]}"#)
    }

    func testQueryWithClaimSetsAndCredentialSetsIsValid() throws {
        try assertValid(#"""
        {"credentials":[
           {"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
            "claims":[{"id":"a","path":["given_name"]},{"id":"b","path":["family_name"]},{"id":"c","path":["age_over_18"]}],
            "claim_sets":[["a","b"],["c"]]},
           {"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
            "claims":[{"path":["org.iso.18013.5.1","family_name"]}]}],
         "credential_sets":[{"options":[["pid"],["mdl"]],"required":true,"purpose":"Identification"}]}
        """#)
    }

    func testQueryWithoutClaimsIsValid() throws {
        try assertValid(#"{"credentials":[\#(sdJwtPid)]}"#)
    }

    func testValuesWithStringsIntegersAndBooleansAreValid() throws {
        try assertValid(#"""
        {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
          "claims":[{"path":["nationalities"],"values":["DE","SE"]},
                    {"path":["age"],"values":[18,21]},
                    {"path":["age_over_18"],"values":[true]}]}]}
        """#)
    }

    func testNullPathComponentIsValidForSdJwt() throws {
        try assertValid(#"""
        {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
          "claims":[{"path":["nationalities",null]}]}]}
        """#)
    }

    func testTrustedAuthoritiesWithKnownTypesAreValid() throws {
        try assertValid(#"""
        {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
          "trusted_authorities":[{"type":"aki","values":["s9tIpPmhxdiuNkHMEWNpYim8S8Y"]},
                                 {"type":"etsi_tl","values":["https://lotl.example/eu-lotl.xml"]},
                                 {"type":"openid_federation","values":["https://federation.example"]}]}]}
        """#)
    }

    func testUnknownMembersAreIgnored() throws {
        try assertValid(#"""
        {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
          "require_cryptographic_holder_binding":false,"future_member":{"x":1},
          "claims":[{"path":["given_name"],"another_member":true}]}],
         "something_else":[]}
        """#)
    }

    // MARK: top level

    func testNilQueryIsRejected() {
        XCTAssertEqual(DcqlQueryValidator.validate(nil), ["dcql_query is missing"])
    }

    func testEmptyCredentialsIsRejected() throws {
        try assertViolation(#"{"credentials":[]}"#, "credentials must be a non-empty array")
    }

    func testEmptyCredentialSetsIsRejected() throws {
        try assertViolation(#"{"credentials":[\#(sdJwtPid)],"credential_sets":[]}"#,
                            "credential_sets must be a non-empty array when present")
    }

    // MARK: credential query

    func testEmptyCredentialIdIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"","format":"dc+sd-jwt","meta":{"vct_values":["v"]}}]}"#,
                            "credentials[0].id is required")
    }

    func testCredentialIdWithIllegalCharactersIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"my credential","format":"dc+sd-jwt","meta":{"vct_values":["v"]}}]}"#,
                            "credentials[0].id must contain only letters, digits, '_' or '-'")
    }

    func testDuplicateCredentialIdsAreRejected() throws {
        try assertViolation(#"""
        {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]}},
                        {"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"d"}}]}
        """#, "credentials[1].id 'pid' is not unique")
    }

    func testEmptyFormatIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"","meta":{"vct_values":["v"]}}]}"#,
                            "credentials[0].format is required")
    }

    func testUnsupportedFormatIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"vc+sd-jwt","meta":{"vct_values":["v"]}}]}"#,
                            "credentials[0].format 'vc+sd-jwt' is not supported")
    }

    func testSdJwtWithEmptyVctValuesIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":[]}}]}"#,
                            "credentials[0].meta.vct_values must be a non-empty array of strings")
    }

    func testSdJwtWithMdocMetaIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"doctype_value":"d"}}]}"#,
                            "credentials[0].meta.vct_values must be a non-empty array of strings")
    }

    func testMdocWithSdJwtMetaIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"vct_values":["v"]}}]}"#,
                            "credentials[0].meta.doctype_value is required")
    }

    func testMdocWithBlankDoctypeIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":" "}}]}"#,
                            "credentials[0].meta.doctype_value is required")
    }

    func testJwtVcJsonWithEmptyInnerTypeArrayIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"vc","format":"jwt_vc_json","meta":{"type_values":[[]]}}]}"#,
                            "credentials[0].meta.type_values must be a non-empty array of non-empty string arrays")
    }

    func testJwtVcJsonWithSdJwtMetaIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"vc","format":"jwt_vc_json","meta":{"vct_values":["v"]}}]}"#,
                            "credentials[0].meta.type_values must be a non-empty array of non-empty string arrays")
    }

    func testEmptyClaimsArrayIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[]}]}"#,
                            "credentials[0].claims must be a non-empty array when present")
    }

    func testEmptyTrustedAuthoritiesIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"trusted_authorities":[]}]}"#,
                            "credentials[0].trusted_authorities must be a non-empty array when present")
    }

    func testTrustedAuthorityWithUnknownTypeIsRejected() throws {
        try assertViolation(#"""
        {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},
          "trusted_authorities":[{"type":"x509_san_dns","values":["verifier.example"]}]}]}
        """#, "credentials[0].trusted_authorities[0].type 'x509_san_dns' is not supported")
    }

    func testTrustedAuthorityWithoutTypeIsRejected() throws {
        try assertViolation(#"""
        {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},
          "trusted_authorities":[{"values":["x"]}]}]}
        """#, "credentials[0].trusted_authorities[0].type is required")
    }

    func testTrustedAuthorityWithoutValuesIsRejected() throws {
        try assertViolation(#"""
        {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},
          "trusted_authorities":[{"type":"aki","values":[]}]}]}
        """#, "credentials[0].trusted_authorities[0].values must be a non-empty array of strings")
    }

    // MARK: claims query

    func testClaimWithEmptyPathIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"path":[]}]}]}"#,
                            "credentials[0].claims[0].path must be a non-empty array")
    }

    func testLegacyMdocNamespaceAndClaimNameWithoutPathIsRejected() throws {
        try assertViolation(#"""
        {"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
          "claims":[{"namespace":"org.iso.18013.5.1","claim_name":"family_name"}]}]}
        """#, "credentials[0].claims[0].path must be a non-empty array")
    }

    func testMdocPathWithOneComponentIsRejected() throws {
        try assertViolation(#"""
        {"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"d"},
          "claims":[{"path":["family_name"]}]}]}
        """#, "credentials[0].claims[0].path must have exactly two string components")
    }

    func testMdocPathWithThreeComponentsIsRejected() throws {
        try assertViolation(#"""
        {"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"d"},
          "claims":[{"path":["org.iso.18013.5.1","address","street"]}]}]}
        """#, "credentials[0].claims[0].path must have exactly two string components")
    }

    func testMdocPathWithNullComponentIsRejected() throws {
        try assertViolation(#"""
        {"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"d"},
          "claims":[{"path":["org.iso.18013.5.1",null]}]}]}
        """#, "credentials[0].claims[0].path must have exactly two string components")
    }

    func testClaimIdWithIllegalCharactersIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"id":"a.b","path":["x"]}]}]}"#,
                            "credentials[0].claims[0].id must contain only letters, digits, '_' or '-'")
    }

    func testDuplicateClaimIdsAreRejected() throws {
        try assertViolation(#"""
        {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},
          "claims":[{"id":"a","path":["x"]},{"id":"a","path":["y"]}]}]}
        """#, "credentials[0].claims[1].id 'a' is not unique")
    }

    func testEmptyValuesArrayIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"path":["x"],"values":[]}]}]}"#,
                            "credentials[0].claims[0].values must be a non-empty array when present")
    }

    // MARK: claim_sets

    func testClaimSetsWithoutClaimsIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claim_sets":[["a"]]}]}"#,
                            "credentials[0].claim_sets must not be present when claims is absent")
    }

    func testEmptyClaimSetsIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"id":"a","path":["x"]}],"claim_sets":[]}]}"#,
                            "credentials[0].claim_sets must be a non-empty array when present")
    }

    func testClaimIdIsRequiredWhenClaimSetsIsPresent() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"path":["x"]}],"claim_sets":[["a"]]}]}"#,
                            "credentials[0].claims[0].id is required when claim_sets is present")
    }

    func testClaimSetsReferencingUnknownClaimIdIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"id":"a","path":["x"]}],"claim_sets":[["a","b"]]}]}"#,
                            "credentials[0].claim_sets[0] references unknown claim id 'b'")
    }

    func testEmptyClaimSetOptionIsRejected() throws {
        try assertViolation(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"id":"a","path":["x"]}],"claim_sets":[[]]}]}"#,
                            "credentials[0].claim_sets[0] must be a non-empty array")
    }

    // MARK: credential_sets

    func testCredentialSetWithEmptyOptionsIsRejected() throws {
        try assertViolation(#"{"credentials":[\#(sdJwtPid)],"credential_sets":[{"options":[]}]}"#,
                            "credential_sets[0].options must be a non-empty array")
    }

    func testCredentialSetWithAnEmptyOptionIsRejected() throws {
        try assertViolation(#"{"credentials":[\#(sdJwtPid)],"credential_sets":[{"options":[[]]}]}"#,
                            "credential_sets[0].options[0] must be a non-empty array")
    }

    func testCredentialSetReferencingUnknownCredentialIdIsRejected() throws {
        try assertViolation(#"{"credentials":[\#(sdJwtPid)],"credential_sets":[{"options":[["pid","mdl"]]}]}"#,
                            "credential_sets[0].options[0] references unknown credential id 'mdl'")
    }

    // MARK: reporting

    func testAllViolationsAreReportedInDocumentOrder() throws {
        let errors = try validate(#"""
        {"credentials":[{"id":"bad id","format":"unknown","meta":{"vct_values":["v"]}},
                        {"id":"","format":"mso_mdoc","meta":{"doctype_value":"d"},"claims":[{"path":["one"]}]}],
         "credential_sets":[{"options":[["nope"]]}]}
        """#)
        XCTAssertEqual(errors, [
            "credentials[0].id must contain only letters, digits, '_' or '-'",
            "credentials[0].format 'unknown' is not supported",
            "credentials[1].id is required",
            "credentials[1].claims[0].path must have exactly two string components (namespace, element identifier) for mso_mdoc",
            "credential_sets[0].options[0] references unknown credential id 'nope'",
        ])
    }

    // MARK: shapes the model cannot represent fail at decode time

    func testMissingMetaFailsToDecode() {
        XCTAssertThrowsError(try decode(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}"#))
    }

    func testEmptyMetaFailsToDecode() {
        XCTAssertThrowsError(try decode(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{}}]}"#))
    }

    func testValuesWithAnObjectFailToDecode() {
        XCTAssertThrowsError(try decode(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"path":["x"],"values":[{"a":1}]}]}]}"#))
    }

    func testDecodingMessageNamesTheFailingMember() {
        do {
            _ = try decode(#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{}}]}"#)
            XCTFail("expected a decoding error")
        } catch {
            let message = DcqlQueryValidator.decodingMessage(error)
            XCTAssertTrue(message.contains("credentials[0].meta"), message)
            XCTAssertTrue(message.contains("Unknown meta type"), message)
        }
    }

    // MARK: the by-value request path refuses an invalid query with the SDK error code

    private func byValueRequest(dcqlQuery: String) -> String {
        let encoded = dcqlQuery.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? ""
        return "openid4vp://?client_id=x509_san_dns%3Averifier.example&response_type=vp_token&response_mode=direct_post&nonce=n1&state=s1&response_uri=https%3A%2F%2Fverifier.example%2Fcb&dcql_query=\(encoded)"
    }

    func testByValueRequestWithInvalidIdIsRefused() async {
        let (request, error) = await VerificationService(keyhandler: StubKeyHandler()).processAuthorisationRequest(
            data: byValueRequest(dcqlQuery: #"{"credentials":[{"id":"my pid","format":"dc+sd-jwt","meta":{"vct_values":["v"]}}]}"#))
        XCTAssertNil(request)
        XCTAssertEqual(error?.code, ErrorCodes.invalidDcqlQuery)
        XCTAssertTrue(error?.message?.contains("credentials[0].id must contain only letters") ?? false, error?.message ?? "nil")
    }

    func testByValueRequestWithUndecodableQueryIsRefused() async {
        let (request, error) = await VerificationService(keyhandler: StubKeyHandler()).processAuthorisationRequest(
            data: byValueRequest(dcqlQuery: #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{}}]}"#))
        XCTAssertNil(request)
        XCTAssertEqual(error?.code, ErrorCodes.invalidDcqlQuery)
    }

    func testByValueRequestWithMalformedJsonIsRefused() async {
        let (request, error) = await VerificationService(keyhandler: StubKeyHandler()).processAuthorisationRequest(
            data: byValueRequest(dcqlQuery: #"{"credentials":[{"#))
        XCTAssertNil(request)
        XCTAssertEqual(error?.code, ErrorCodes.invalidDcqlQuery)
    }

    func testByValueRequestWithValidQueryIsAccepted() async {
        let (request, error) = await VerificationService(keyhandler: StubKeyHandler()).processAuthorisationRequest(
            data: byValueRequest(dcqlQuery: #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]}]}]}"#))
        XCTAssertNil(error)
        XCTAssertEqual(request?.dcqlQuery?.credentials.first?.id, "pid")
    }
}
