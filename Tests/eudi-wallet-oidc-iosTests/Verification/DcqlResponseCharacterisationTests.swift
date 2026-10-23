//
//  DcqlResponseCharacterisationTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
import SwiftCBOR
@testable import eudiWalletOidcIos

/// Characterisation of the DCQL response path as it behaves today. See
/// `PexResponseCharacterisationTests` for the purpose of these tests.
final class DcqlResponseCharacterisationTests: ResponseCharacterisationTestCase {

    private typealias F = VerificationFixtures

    private func vpToken(_ params: [String: Any]?) -> [String: Any] {
        F.object(params?["vp_token"]) as? [String: Any] ?? [:]
    }

    private let familyName = Claim.pathClaim(PathClaim(path: ["org.iso.18013.5.1", "family_name"], id: nil))

    func testA10VerifierGetsOneListPerCredentialIdAndNoPresentationSubmission() async throws {
        let params = await respond(F.dcqlRequest(F.dcqlSdJwt("pid")), [[F.sdJwt()]])

        XCTAssertEqual(Set(params?.keys.map { $0 } ?? []), ["vp_token", "state"])
        let presented = try XCTUnwrap(vpToken(params)["pid"] as? [String])
        XCTAssertEqual(presented.count, 1)
        XCTAssertTrue(F.verifies(F.keyBindingJwt(presented[0]), with: holder.publicKey))
        XCTAssertEqual(params?["state"] as? String, F.state)
    }

    func testADraft23VerifierGetsABareStringPerCredentialId() async throws {
        let request = F.dcqlRequest(F.dcqlSdJwt("pid"), clientMetadata: F.encryptionMetadata(VerifierKey(), version: "draft_23"))
        let params = await respond(request, [[F.sdJwt()]])

        let presented = try XCTUnwrap(vpToken(params)["pid"] as? String)
        XCTAssertTrue(F.verifies(F.keyBindingJwt(presented), with: holder.publicKey))
    }

    func testAnEntryAnsweredWithTwoCredentialsMapsToATwoElementList() async {
        let params = await respond(F.dcqlRequest(F.dcqlSdJwt("a", vct: "urn:a"), F.dcqlSdJwt("b", vct: "urn:b")),
                                   [[F.sdJwt(vct: "urn:a")], [F.sdJwt(vct: "urn:b"), F.sdJwt(vct: "urn:b")]])

        XCTAssertEqual((vpToken(params)["a"] as? [String])?.count, 1)
        XCTAssertEqual((vpToken(params)["b"] as? [String])?.count, 2)
    }

    func testEachPresentedCredentialIsBoundWithItsOwnKey() async throws {
        let k1 = SoftwareKey(), k2 = SoftwareKey()
        storedKeys["k1"] = k1
        storedKeys["k2"] = k2
        let params = await respond(F.dcqlRequest(F.dcqlSdJwt("pid")), [[F.sdJwt(), F.sdJwt()]], keyIds: [["k1", "k2"]])

        let presented = try XCTUnwrap(vpToken(params)["pid"] as? [String]).map(F.keyBindingJwt)
        XCTAssertTrue(F.verifies(presented[0], with: k1.publicKey))
        XCTAssertTrue(F.verifies(presented[1], with: k2.publicKey))
        XCTAssertFalse(F.verifies(presented[1], with: k1.publicKey))
    }

    func testAnMdocEntryYieldsASignedBase64UrlDeviceResponse() async throws {
        let params = await respond(F.dcqlRequest(F.dcqlMdoc("mdl", claims: [familyName])),
                                   [[F.mdoc(deviceKey: holder.publicKey, nameSpaces: ["org.iso.18013.5.1": ["family_name": "Doe"]])]])

        let presented = try XCTUnwrap((vpToken(params)["mdl"] as? [String])?.first)
        guard case .map(let deviceResponse)? = F.decodeCbor(presented) else { return XCTFail("not a CBOR map") }
        XCTAssertEqual(deviceResponse.count, 3) // version, documents, status
        XCTAssertNotNil(deviceResponse["documents"]?[0]?["deviceSigned"]?["deviceAuth"]?["deviceSignature"])
    }

    func testAnMdocEntryWithNoClaimsIsSignedLikeAnyOther() async throws {
        var entry = F.dcqlMdoc("mdl")
        entry.claims = nil
        let params = await respond(F.dcqlRequest(entry), [[F.mdoc(deviceKey: holder.publicKey)]])

        // Leg 0 pinned this branch going out with no deviceSigned at all; leg 4 signs it.
        let presented = try XCTUnwrap((vpToken(params)["mdl"] as? [String])?.first)
        let document = F.decodeCbor(presented)?["documents"]?[0]
        XCTAssertNotNil(document?["issuerSigned"])
        XCTAssertNotNil(document?["deviceSigned"]?["deviceAuth"]?["deviceSignature"])
    }

    func testAnMdocWithNoKeyIdFallsBackToTheWalletKeyAndLeavesNothingToSend() async {
        let params = await respond(F.dcqlRequest(F.dcqlMdoc("mdl", claims: [familyName])),
                                   [[F.mdoc(deviceKey: holder.publicKey)]], keyIds: [[]])

        // The wallet's DID key handler exposes no SecKey, so no device signature can be made.
        XCTAssertNil(params, "leg 5: refused rather than sent with an empty deviceAuth")
    }

    func testAJwtVcJsonEntryYieldsAW3CPresentation() async throws {
        let params = await respond(F.dcqlRequest(F.dcqlJwt("vc")), [[F.jwtVc()]])

        let vp = try XCTUnwrap((vpToken(params)["vc"] as? [String])?.first)
        XCTAssertNotNil((JWTParts.claims(vp)?["vp"] as? [String: Any])?["verifiableCredential"])
    }

    func testACredentialCountThatDiffersFromTheQueryCountLeavesNothingToSend() async {
        let params = await respond(F.dcqlRequest(F.dcqlSdJwt("a"), F.dcqlSdJwt("b")), [[F.sdJwt()]])
        XCTAssertNil(params)
    }

    func testAnEntryWithNoSelectedCredentialIsLeftOutOfTheToken() async {
        let params = await respond(F.dcqlRequest(F.dcqlSdJwt("a"), F.dcqlSdJwt("b")), [[F.sdJwt()], []])

        XCTAssertNotNil(vpToken(params)["a"])
        XCTAssertNil(vpToken(params)["b"])
    }
}
