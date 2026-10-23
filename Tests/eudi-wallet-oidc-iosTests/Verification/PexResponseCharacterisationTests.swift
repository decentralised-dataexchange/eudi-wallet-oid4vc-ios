//
//  PexResponseCharacterisationTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
import CryptoKit
import SwiftCBOR
@testable import eudiWalletOidcIos

/// Characterisation of the Presentation Exchange response path **as it behaves today**, through
/// the entry point the wallet calls. These tests pin current behaviour, defects included, so the
/// response rewrite in later legs is a refactor with a safety net. A test that documents a defect
/// says so in its name. Case names follow the Android SDK's `PexResponseCharacterisationTest`.
final class PexResponseCharacterisationTests: ResponseCharacterisationTestCase {

    private typealias F = VerificationFixtures

    private func descriptorMap(_ params: [String: Any]?) -> [[String: Any]] {
        let submission = F.object(params?["presentation_submission"]) as? [String: Any]
        return submission?["descriptor_map"] as? [[String: Any]] ?? []
    }

    func testOneSdJwtDescriptorYieldsASingleBoundTokenAndARootPath() async throws {
        let params = await respond(F.pexRequest(F.sdJwtDescriptor("pid")), [[F.sdJwt()]])

        let vpToken = try XCTUnwrap(params?["vp_token"] as? String, "single token is sent bare, not as an array")
        let kb = F.keyBindingJwt(vpToken)
        XCTAssertTrue(F.verifies(kb, with: holder.publicKey))
        let claims = try XCTUnwrap(JWTParts.claims(kb))
        XCTAssertEqual(claims["aud"] as? String, F.clientId)
        XCTAssertEqual(claims["nonce"] as? String, F.nonce)
        XCTAssertEqual(JWTParts.header(kb)?["typ"] as? String, "kb+jwt")
        XCTAssertNil(claims["response_mode"], "no SCA: no response_mode in the KB-JWT")
        XCTAssertNil(claims["amr"])

        let submission = try XCTUnwrap(F.object(params?["presentation_submission"]) as? [String: Any])
        XCTAssertEqual(submission["definition_id"] as? String, "pd-1")
        let entry = try XCTUnwrap(descriptorMap(params).first)
        XCTAssertEqual(descriptorMap(params).count, 1)
        XCTAssertEqual(entry["id"] as? String, "pid")
        XCTAssertEqual(entry["path"] as? String, "$")
        XCTAssertEqual(entry["format"] as? String, "vc+sd-jwt")
        XCTAssertEqual(params?["state"] as? String, F.state)
    }

    func testTwoSdJwtDescriptorsYieldAnArrayWithIndexedPaths() async {
        let params = await respond(F.pexRequest(F.sdJwtDescriptor("a"), F.sdJwtDescriptor("b")),
                                   [[F.sdJwt(vct: "urn:a")], [F.sdJwt(vct: "urn:b")]])

        XCTAssertEqual((F.object(params?["vp_token"]) as? [String])?.count, 2, "several presentations go as a JSON array")
        XCTAssertEqual(descriptorMap(params).map { $0["path"] as? String }, ["$[0]", "$[1]"])
    }

    func testOneJwtVpDescriptorYieldsOneW3CPresentationWithANestedPath() async throws {
        let params = await respond(F.pexRequest(F.jwtDescriptor("vc")), [[F.jwtVc()]])

        let vp = try XCTUnwrap(params?["vp_token"] as? String)
        XCTAssertTrue(F.verifies(vp, with: walletKey.publicKey))
        let claims = try XCTUnwrap(JWTParts.claims(vp))
        XCTAssertEqual(claims["aud"] as? String, F.clientId)
        XCTAssertEqual(((claims["vp"] as? [String: Any])?["verifiableCredential"] as? [Any])?.count, 1)
        XCTAssertEqual(claims["iss"] as? String, F.did, "holder is the DID passed in, not derived from the credential key")

        let entry = try XCTUnwrap(descriptorMap(params).first)
        XCTAssertEqual(entry["path"] as? String, "$")
        XCTAssertEqual(entry["format"] as? String, "jwt_vp")
        XCTAssertEqual((entry["path_nested"] as? [String: Any])?["path"] as? String, "$.vp.verifiableCredential[0]")
    }

    func testTwoJwtVpDescriptorsAreAggregatedIntoOneW3CPresentation() async throws {
        let params = await respond(F.pexRequest(F.jwtDescriptor("x"), F.jwtDescriptor("y")), [[F.jwtVc()], [F.jwtVc()]])

        let vp = try XCTUnwrap(params?["vp_token"] as? String)
        let claims = try XCTUnwrap(JWTParts.claims(vp))
        XCTAssertEqual(((claims["vp"] as? [String: Any])?["verifiableCredential"] as? [Any])?.count, 2)
        XCTAssertEqual(claims["iss"] as? String, F.did)
        let entries = descriptorMap(params)
        XCTAssertEqual(entries.map { $0["path"] as? String }, ["$", "$"])
        XCTAssertEqual(entries.map { ($0["path_nested"] as? [String: Any])?["path"] as? String },
                       ["$.vp.verifiableCredential[0]", "$.vp.verifiableCredential[1]"])
    }

    func testSdJwtPlusMdocDescriptorsYieldABoundSdJwtAndADeviceResponse() async throws {
        let params = await respond(F.pexRequest(F.sdJwtDescriptor("pid"), F.mdocDescriptor("mdl")),
                                   [[F.sdJwt()], [F.mdoc(deviceKey: holder.publicKey)]])

        let tokens = try XCTUnwrap(F.object(params?["vp_token"]) as? [String])
        XCTAssertEqual(tokens.count, 2)
        XCTAssertTrue(F.verifies(F.keyBindingJwt(tokens[0]), with: holder.publicKey))
        let deviceResponse = try XCTUnwrap(F.decodeCbor(tokens[1]))
        XCTAssertEqual(deviceResponse["version"], .utf8String("1.0"))
        XCTAssertNotNil(deviceResponse["documents"]?[0]?["deviceSigned"]?["deviceAuth"]?["deviceSignature"])
        let entries = descriptorMap(params)
        XCTAssertEqual(entries.map { $0["format"] as? String }, ["vc+sd-jwt", "mso_mdoc"])
        XCTAssertEqual(entries.map { $0["path"] as? String }, ["$[0]", "$[1]"])
    }

    func testAnMdocWhoseKeyCannotSignLeavesNothingToSend() async {
        let params = await respond(F.pexRequest(F.mdocDescriptor("mdl")), [[F.mdoc(deviceKey: nil)]], keyIds: [["missing"]])
        XCTAssertNil(params, "leg 5: an mdoc without its device signature is never sent")
    }

    func testAnSdJwtWhoseKeyCannotSignLeavesNothingToSend() async {
        let params = await respond(F.pexRequest(F.sdJwtDescriptor("pid")), [[F.sdJwt()]], keyIds: [["missing"]])
        XCTAssertNil(params, "leg 5: an SD-JWT without its key binding JWT is never sent")
    }

    func testIdTokenResponseTypeYieldsOnlyAnIdTokenAndState() async throws {
        let params = await respond(F.pexRequest(responseType: "id_token"), [])

        XCTAssertEqual(Set(params?.keys.map { $0 } ?? []), ["id_token", "state"])
        let idToken = try XCTUnwrap(params?["id_token"] as? String)
        XCTAssertTrue(F.verifies(idToken, with: walletKey.publicKey))
        let claims = try XCTUnwrap(JWTParts.claims(idToken))
        XCTAssertEqual(claims["iss"] as? String, F.did)
        XCTAssertEqual(claims["sub"] as? String, F.did)
        XCTAssertEqual(claims["aud"] as? String, F.clientId)
        XCTAssertEqual(claims["nonce"] as? String, F.nonce)
    }

    func testVpTokenPlusIdTokenResponseTypeYieldsBoth() async throws {
        let params = await respond(F.pexRequest(F.sdJwtDescriptor("pid"), responseType: "vp_token id_token"), [[F.sdJwt()]])

        XCTAssertEqual(Set(params?.keys.map { $0 } ?? []), ["vp_token", "id_token", "presentation_submission", "state"])
        XCTAssertTrue(F.verifies(F.keyBindingJwt(try XCTUnwrap(params?["vp_token"] as? String)), with: holder.publicKey))
    }

    func testAnUnknownResponseTypeLeavesNothingToSend() async {
        let params = await respond(F.pexRequest(F.sdJwtDescriptor("pid"), responseType: "code"), [[F.sdJwt()]])
        XCTAssertNil(params, "leg 5: a response carrying only the state is not sent")
    }

    func testANullStateIsLeftOut() async {
        var request = F.pexRequest(F.sdJwtDescriptor("pid"))
        request.state = nil
        let params = await respond(request, [[F.sdJwt()]])
        XCTAssertNil(params?["state"])
    }
}
