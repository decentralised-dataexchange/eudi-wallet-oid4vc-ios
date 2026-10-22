//
//  DcqlCredentialMatcherTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
import CryptoKit
@testable import eudiWalletOidcIos

/// One test or more per row of the leg 3 case matrix (VERIFICATION_REVAMP_PLAN_IOS.md), named
/// after it. Credentials are built in the test: SD-JWTs with placeholder signatures (matching reads
/// only the payload and header) and mdocs from `VerificationFixtures.mdoc`. Queries are decoded
/// from JSON, so the decoder is exercised as the request would exercise it.
final class DcqlCredentialMatcherTests: XCTestCase {

    private typealias F = VerificationFixtures

    private let holderKey = P256.Signing.PrivateKey()

    // MARK: Fixtures

    private func jwt(_ header: [String: Any], _ payload: [String: Any]) -> String {
        (try! JSONSerialization.data(withJSONObject: header)).b64url + "."
            + (try! JSONSerialization.data(withJSONObject: payload)).b64url + ".c2lnbmF0dXJl"
    }

    /// An SD-JWT VC: `claims` in the payload, `disclosed` as disclosures, `cnf` unless told otherwise.
    private func sdJwt(vct: String = F.vct, _ claims: [String: Any] = [:], disclosed: [String: Any] = [:],
                       cnf: Bool = true, header: [String: Any] = ["alg": "ES256", "kid": "issuer"]) -> String {
        var payload: [String: Any] = ["vct": vct, "iss": "https://issuer.example"].merging(claims) { _, new in new }
        if cnf {
            let raw = holderKey.publicKey.rawRepresentation
            payload["cnf"] = ["jwk": ["kty": "EC", "crv": "P-256", "x": raw.prefix(32).b64url, "y": raw.suffix(32).b64url]]
        }
        var disclosures: [String] = []
        for (name, value) in disclosed.sorted(by: { $0.key < $1.key }) {
            disclosures.append((try! JSONSerialization.data(withJSONObject: ["salt-\(name)", name, value])).b64url)
        }
        if !disclosures.isEmpty { payload["_sd"] = disclosures.map(F.sha256) }
        return ([jwt(header, payload)] + disclosures).joined(separator: "~") + "~"
    }

    private func jwtVc(types: [String], subject: String? = "did:key:zHolder") -> String {
        var vc: [String: Any] = ["type": types, "credentialSubject": ["given_name": "Alice"]]
        if let subject { vc["credentialSubject"] = ["id": subject, "given_name": "Alice"] }
        return jwt(["alg": "ES256", "kid": "issuer"], ["iss": "https://issuer.example", "vc": vc])
    }

    private func mdoc(docType: String = F.docType, _ elements: [String: String] = ["family_name": "Doe"], bound: Bool = true) -> String {
        F.mdoc(deviceKey: bound ? holderKey.publicKey : nil, docType: docType, nameSpaces: ["org.iso.18013.5.1": elements])
    }

    private func query(_ json: String) throws -> DCQLQuery {
        try JSONDecoder().decode(DCQLQuery.self, from: Data(json.utf8))
    }

    private func match(_ json: String, _ credentials: [String?]) async throws -> CredentialMatches {
        await PresentationQueryMatcher().match(.dcql(try query(json)), credentials)
    }

    private func pid(_ extra: String = "") -> String {
        #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}\#(extra)}]}"#
    }

    // MARK: 3.1 to 3.5: metadata and claims

    func test3_1_aMatchingVctWithNoClaimsIsACandidateDisclosingNothing() async throws {
        let matches = try await match(pid(), [sdJwt()])
        XCTAssertEqual(matches.candidatesFor("pid").count, 1)
        XCTAssertEqual(matches.candidatesFor("pid").first?.claims.isEmpty, true)
        XCTAssertTrue(matches.satisfiable)
    }

    func test3_2_aVctMismatchIsExcluded() async throws {
        let matches = try await match(pid(), [sdJwt(vct: "urn:other")])
        XCTAssertTrue(matches.candidatesFor("pid").isEmpty)
        XCTAssertFalse(matches.satisfiable)
        XCTAssertEqual(matches.unsatisfied, ["pid"])
    }

    func test3_3_claimsPresentInThePayloadOrDisclosedMakeACandidateWithTheirPaths() async throws {
        let credential = sdJwt(["family_name": "Doe"], disclosed: ["given_name": "Alice"])
        let matches = try await match(pid(#","claims":[{"path":["family_name"]},{"path":["given_name"]}]"#), [credential])
        XCTAssertEqual(matches.candidatesFor("pid").first?.claims, [["family_name"], ["given_name"]])
    }

    func test3_4_aMissingClaimExcludesTheCredential() async throws {
        let matches = try await match(pid(#","claims":[{"path":["family_name"]},{"path":["birthdate"]}]"#), [sdJwt(["family_name": "Doe"])])
        XCTAssertTrue(matches.candidatesFor("pid").isEmpty)
    }

    func test3_5_valuesMustMatchByTypeAndValue() async throws {
        let credential = sdJwt(["age_over_18": true, "nationality": "DE"])
        let wrong = try await match(pid(#","claims":[{"path":["nationality"],"values":["FR"]}]"#), [credential])
        XCTAssertTrue(wrong.candidatesFor("pid").isEmpty)
        let right = try await match(pid(#","claims":[{"path":["nationality"],"values":["FR","DE"]}]"#), [credential])
        XCTAssertEqual(right.candidatesFor("pid").count, 1)
        let bool = try await match(pid(#","claims":[{"path":["age_over_18"],"values":[true]}]"#), [credential])
        XCTAssertEqual(bool.candidatesFor("pid").count, 1)
        let intForBool = try await match(pid(#","claims":[{"path":["age_over_18"],"values":[1]}]"#), [credential])
        XCTAssertTrue(intForBool.candidatesFor("pid").isEmpty, "true is not the integer 1")
    }

    // MARK: 3.6 to 3.9: claim sets, credential sets, multiple

    func test3_6_theFirstSatisfiableClaimSetOptionIsChosen() async throws {
        let extra = #","claims":[{"id":"a","path":["birthdate"]},{"id":"b","path":["family_name"]},{"id":"c","path":["given_name"]}],"claim_sets":[["a"],["b","c"]]"#
        let matches = try await match(pid(extra), [sdJwt(["family_name": "Doe", "given_name": "Alice"])])
        XCTAssertEqual(matches.candidatesFor("pid").first?.claims, [["family_name"], ["given_name"]])
    }

    func test3_6b_noSatisfiableOptionExcludesTheCredential() async throws {
        let extra = #","claims":[{"id":"a","path":["birthdate"]},{"id":"b","path":["address"]}],"claim_sets":[["a"],["b"]]"#
        let matches = try await match(pid(extra), [sdJwt(["family_name": "Doe"])])
        XCTAssertTrue(matches.candidatesFor("pid").isEmpty)
    }

    func test3_7_anUnmetRequiredCredentialSetMakesTheRequestUnsatisfiable() async throws {
        let json = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}},{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}],"credential_sets":[{"options":[["pid","mdl"]]}]}"#
        let matches = try await match(json, [sdJwt()])
        XCTAssertEqual(matches.candidatesFor("pid").count, 1, "candidates are still reported")
        XCTAssertFalse(matches.satisfiable)
        XCTAssertEqual(matches.unsatisfied, ["credential_sets[0]"])
    }

    func test3_8_anUnmetOptionalCredentialSetLeavesTheRequestSatisfiable() async throws {
        let json = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}},{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}],"credential_sets":[{"options":[["pid"]]},{"required":false,"options":[["mdl"]]}]}"#
        let matches = try await match(json, [sdJwt()])
        XCTAssertTrue(matches.satisfiable)
        XCTAssertEqual(matches.entries.map(\.entry.required), [true, false])
    }

    func test3_9_multipleIsExposedOnTheEntry() async throws {
        let matches = try await match(pid(#","multiple":true"#), [sdJwt(), sdJwt()])
        XCTAssertTrue(matches.entries.first?.entry.multiple == true)
        XCTAssertEqual(matches.candidatesFor("pid").count, 2)
    }

    // MARK: 3.10 to 3.12: formats

    private let mdlQuery = #"{"credentials":[{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[{"path":["org.iso.18013.5.1","family_name"]}]}]}"#

    func test3_10_anMdocMatchesByDoctypeAndNamespaceElement() async throws {
        let matches = try await match(mdlQuery, [mdoc()])
        XCTAssertEqual(matches.candidatesFor("mdl").first?.claims, [["org.iso.18013.5.1", "family_name"]])
    }

    func test3_10b_anMdocOfAnotherDoctypeIsExcludedEvenWithTheClaim() async throws {
        let matches = try await match(mdlQuery, [mdoc(docType: "eu.europa.ec.eudi.pid.1")])
        XCTAssertTrue(matches.candidatesFor("mdl").isEmpty)
    }

    func test3_11_anMdocMissingTheElementIsExcluded() async throws {
        let matches = try await match(mdlQuery, [mdoc(["given_name": "Alice"])])
        XCTAssertTrue(matches.candidatesFor("mdl").isEmpty)
    }

    func test3_12_typeValuesNeedEveryTypeOfOneOption() async throws {
        let json = #"{"credentials":[{"id":"vc","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential","Diploma"]]}}]}"#
        let full = try await match(json, [jwtVc(types: ["VerifiableCredential", "Diploma"])])
        XCTAssertEqual(full.candidatesFor("vc").count, 1)
        let partial = try await match(json, [jwtVc(types: ["VerifiableCredential", "Passport"])])
        XCTAssertTrue(partial.candidatesFor("vc").isEmpty, "one shared type is not enough")
    }

    // MARK: 3.14 and 3.15: trusted authorities

    func test3_14_akiMatchesTheAuthorityKeyIdentifierOfTheIssuerChain() async throws {
        let credential = sdJwt(header: ["alg": "ES256", "x5c": [CertificateFixtures.leaf]])
        let hit = try await match(pid(#","trusted_authorities":[{"type":"aki","values":["\#(CertificateFixtures.leafAuthorityKeyId)"]}]"#), [credential])
        XCTAssertEqual(hit.candidatesFor("pid").count, 1)
        let miss = try await match(pid(#","trusted_authorities":[{"type":"aki","values":["c29tZXRoaW5nLWVsc2U"]}]"#), [credential])
        XCTAssertTrue(miss.candidatesFor("pid").isEmpty)
    }

    func test3_15_anUnsupportedTrustedAuthorityTypeMatchesNothing() async throws {
        let credential = sdJwt(header: ["alg": "ES256", "x5c": [CertificateFixtures.leaf]])
        let matches = try await match(pid(#","trusted_authorities":[{"type":"openid_federation","values":["https://fed.example"]}]"#), [credential])
        XCTAssertTrue(matches.candidatesFor("pid").isEmpty)
    }

    // MARK: 3.16 and 3.17: holder binding

    func test3_16_anSdJwtWithoutCnfIsExcludedByDefault() async throws {
        let matches = try await match(pid(), [sdJwt(cnf: false)])
        XCTAssertTrue(matches.candidatesFor("pid").isEmpty)
        let unboundMdoc = try await match(mdlQuery, [mdoc(bound: false)])
        XCTAssertTrue(unboundMdoc.candidatesFor("mdl").isEmpty)
    }

    func test3_16b_aJwtVcIsHolderBoundByItsDidSubject() async throws {
        let json = #"{"credentials":[{"id":"vc","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}"#
        let bound = try await match(json, [jwtVc(types: ["VerifiableCredential"])])
        XCTAssertEqual(bound.candidatesFor("vc").count, 1)
        let unbound = try await match(json, [jwtVc(types: ["VerifiableCredential"], subject: nil)])
        XCTAssertTrue(unbound.candidatesFor("vc").isEmpty)
    }

    func test3_17_holderBindingFalseAcceptsACredentialWithoutCnf() async throws {
        let matches = try await match(pid(#","require_cryptographic_holder_binding":false"#), [sdJwt(cnf: false)])
        XCTAssertEqual(matches.candidatesFor("pid").count, 1)
    }

    // MARK: 3.18: claims path pointers

    func test3_18_nullSelectsEveryElementAndAnIntegerSelectsAnIndex() async throws {
        let credential = sdJwt(["nationalities": ["DE", "FR"]])
        let all = try await match(pid(#","claims":[{"path":["nationalities",null],"values":["FR"]}]"#), [credential])
        XCTAssertEqual(all.candidatesFor("pid").first?.claims, [["nationalities", nil]])
        let first = try await match(pid(#","claims":[{"path":["nationalities",0],"values":["DE"]}]"#), [credential])
        XCTAssertEqual(first.candidatesFor("pid").first?.claims, [["nationalities", "0"]])
        let second = try await match(pid(#","claims":[{"path":["nationalities",1],"values":["DE"]}]"#), [credential])
        XCTAssertTrue(second.candidatesFor("pid").isEmpty)
        let outOfRange = try await match(pid(#","claims":[{"path":["nationalities",5]}]"#), [credential])
        XCTAssertTrue(outOfRange.candidatesFor("pid").isEmpty)
    }

    func test3_18b_aKeyAppliedToAnArrayAborts() {
        XCTAssertNil(ClaimsPathPointer.select(["nationalities": ["DE"]], ["nationalities", "first"]))
        XCTAssertNil(ClaimsPathPointer.select(["name": "Alice"], ["name", nil]))
    }

    func test3_18c_aNegativeIndexFailsDecoding() {
        XCTAssertThrowsError(try query(pid(#","claims":[{"path":["nationalities",-1]}]"#)))
    }

    func test3_18d_aRequestWithAnIntegerPathIsNoLongerRefused() async {
        let data = "openid4vp://?client_id=redirect_uri%3Ahttps%3A%2F%2Fverifier.example%2Fcb&response_type=vp_token&response_mode=direct_post&nonce=n1&dcql_query="
            + (pid(#","claims":[{"path":["nationalities",0]}]"#).addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "")
        guard case .resolved = await PresentationRequestResolver().resolve(data) else { return XCTFail("refused") }
    }

    // MARK: 3.19 to 3.24

    func test3_19_aWalletMixingFormatsAndNilsReturnsTheRightCredentials() async throws {
        let json = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}},{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]}"#
        let pidCredential = sdJwt(), mdlCredential = mdoc()
        let matches = try await match(json, [nil, mdlCredential, "", pidCredential])
        XCTAssertEqual(matches.candidatesFor("pid").map(\.credential), [pidCredential])
        XCTAssertEqual(matches.candidatesFor("mdl").map(\.credential), [mdlCredential])
    }

    func test3_20_aPresentationDefinitionStillGoesThroughPexAndANilNoLongerShiftsTheResult() async throws {
        let definition = try VerificationService.processPresentationDefinition(F.json([
            "id": "pd-1",
            "input_descriptors": [["id": "pid", "format": ["vc+sd-jwt": ["alg": ["ES256"]]],
                                   "constraints": ["fields": [["path": ["$.vct"], "filter": ["type": "string", "const": F.vct]]]]]]]))
        let wanted = sdJwt(), other = sdJwt(vct: "urn:other")
        let matches = await PresentationQueryMatcher().match(.presentationDefinition(definition), [nil, other, wanted])
        XCTAssertEqual(matches.candidatesFor("pid").map(\.credential), [wanted])
    }

    func test3_21_anEmptyWalletIsUnsatisfiable() async throws {
        let matches = try await match(pid(), [])
        XCTAssertEqual(matches.entries.count, 1)
        XCTAssertFalse(matches.satisfiable)
    }

    func test3_22_aCredentialWithoutX5cKidOrDidIsACandidate() async throws {
        let credential = sdJwt(header: ["alg": "ES256"])
        let lists = await FilterCredentialService().filterCredentials(credentialList: [credential], queryItems: try query(pid()))
        XCTAssertEqual(lists, [[credential]])
    }

    func test3_23_aStringHoldingJsonIsEnteredLikeAnObject() async throws {
        let credential = sdJwt(["address": #"{"country":"DE"}"#])
        let matches = try await match(pid(#","claims":[{"path":["address","country"],"values":["DE"]}]"#), [credential])
        XCTAssertEqual(matches.candidatesFor("pid").count, 1)
    }

    func test3_24_candidatesKeepTheWalletOrder() async throws {
        let credentials = (1...4).map { sdJwt(["n": $0]) }
        let matches = try await match(pid(), credentials)
        XCTAssertEqual(matches.candidatesFor("pid").map(\.credential), credentials)
    }

    // MARK: Adapter and API

    func testTheDeprecatedFilterKeepsItsShapeAndRefusesAnUnknownQueryType() async throws {
        let json = #"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}},{"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]}"#
        let pidCredential = sdJwt()
        let service = FilterCredentialService()
        let lists = await service.filterCredentials(credentialList: [pidCredential], queryItems: try query(json))
        XCTAssertEqual(lists, [[pidCredential], []])
        let none = await service.filterCredentials(credentialList: [pidCredential], queryItems: "not a query")
        XCTAssertEqual(none, [])
    }

    func testMatchCredentialsReadsTheRequestQuery() async throws {
        var request = F.dcqlRequest(F.dcqlSdJwt("pid"))
        request.dcqlQuery = try query(pid())
        let matches = await VerificationService(keyhandler: CryptoKitHandler()).matchCredentials(request: request, credentials: [sdJwt()])
        XCTAssertEqual(matches.candidatesFor("pid").count, 1)
    }
}
