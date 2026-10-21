//
//  ResponseModeCharacterisationTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
import JOSESwift
@testable import eudiWalletOidcIos

/// Characterisation of how each response mode packages the response today. See
/// `PexResponseCharacterisationTests` for the purpose of these tests.
final class ResponseModeCharacterisationTests: ResponseCharacterisationTestCase {

    private typealias F = VerificationFixtures

    private let verifierKey = VerifierKey()

    private func respond(_ request: PresentationRequest) async -> [String: Any]? {
        await respond(request, [[F.sdJwt()]])
    }

    func testDirectPostJwtEncryptsTheResponseWithTheEncTheVerifierNames() async throws {
        let request = F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "direct_post.jwt",
                                    clientMetadata: F.encryptionMetadata(verifierKey, encValues: ["A128GCM"]))
        let params = await respond(request)

        XCTAssertEqual(Set(params?.keys.map { $0 } ?? []), ["response"])
        let jwe = try verifierKey.decrypt(try XCTUnwrap(params?["response"] as? String))
        XCTAssertEqual(jwe.header.keyManagementAlgorithm, .ECDH_ES)
        XCTAssertEqual(jwe.header.contentEncryptionAlgorithm, .A128GCM)
        XCTAssertEqual(jwe.header.kid, "verifier-enc")
        XCTAssertEqual(jwe.header.apv, Data(F.nonce.utf8).b64url)
        XCTAssertEqual(jwe.header.apu, Data(F.clientId.utf8).b64url)
        XCTAssertNotNil(jwe.payload["vp_token"] as? [String: Any], "encrypted: vp_token is an object, not a string")
        XCTAssertNotNil(jwe.payload["state"])
    }

    func testDirectPostJwtPrefersA128CbcHs256WhenTheVerifierListsSeveral() async throws {
        let request = F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "direct_post.jwt",
                                    clientMetadata: F.encryptionMetadata(verifierKey, encValues: ["A256GCM", "A128CBC-HS256"]))
        let params = await respond(request)

        let jwe = try verifierKey.decrypt(try XCTUnwrap(params?["response"] as? String))
        XCTAssertEqual(jwe.header.contentEncryptionAlgorithm, .A128CBCHS256)
    }

    func testDefectDirectPostJwtWithoutEncValuesSupportedYieldsNilEvenWhenTheDraftEncNamesOne() async {
        // Android defaults to A128GCM and honours authorization_encrypted_response_enc; iOS reads
        // only encrypted_response_enc_values_supported and drops the response without a reason.
        let request = F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "direct_post.jwt",
                                    clientMetadata: F.encryptionMetadata(verifierKey, encValues: nil, enc: "A128GCM"))
        let params = await respond(request)
        XCTAssertNil(params)
    }

    func testDefectAnEncTheSdkDoesNotSupportYieldsNil() async {
        let request = F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "direct_post.jwt",
                                    clientMetadata: F.encryptionMetadata(verifierKey, encValues: ["A256CBC-HS512"]))
        let params = await respond(request)
        XCTAssertNil(params)
    }

    func testDefectAnAlgOtherThanEcdhEsIsIgnoredAndEcdhEsUsed() async throws {
        let request = F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "direct_post.jwt",
                                    clientMetadata: F.encryptionMetadata(verifierKey, alg: "ECDH-ES+A128KW"))
        let params = await respond(request)

        let jwe = try verifierKey.decrypt(try XCTUnwrap(params?["response"] as? String))
        XCTAssertEqual(jwe.header.keyManagementAlgorithm, .ECDH_ES)
    }

    func testDcApiYieldsAnEmptyParameterSet() async {
        let params = await respond(F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "dc_api"))
        XCTAssertEqual(params?.isEmpty, true)
    }

    func testIarPostWrapsThePresentationInAuthSessionAndOpenid4vpPresentation() async throws {
        var request = F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "iar-post")
        request.authSession = "as-1"
        let params = await respond(request)

        XCTAssertEqual(Set(params?.keys.map { $0 } ?? []), ["auth_session", "openid4vp_presentation"])
        XCTAssertEqual(params?["auth_session"] as? String, "as-1")
        let inner = try XCTUnwrap(F.object(params?["openid4vp_presentation"]) as? [String: Any])
        XCTAssertNotNil(inner["vp_token"])
        XCTAssertNotNil(inner["state"])
    }

    func testIarPostJwtWrapsAnEncryptedResponseTheSameWay() async throws {
        var request = F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "iar-post.jwt",
                                    clientMetadata: F.encryptionMetadata(verifierKey))
        request.authSession = "as-2"
        let params = await respond(request)

        XCTAssertEqual(params?["auth_session"] as? String, "as-2")
        let inner = try XCTUnwrap(params?["openid4vp_presentation"] as? [String: Any], "an object here, a string on iar-post")
        _ = try verifierKey.decrypt(try XCTUnwrap(inner["response"] as? String))
    }

    func testDefectAnAbsentResponseModeYieldsNil() async {
        // OpenID4VP 1.0 section 5.1 defaults response_mode to fragment; Android treats it as direct_post.
        let params = await respond(F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: nil))
        XCTAssertNil(params)
    }

    func testDefectAnUnsupportedResponseModeYieldsNilRatherThanAnError() async {
        let params = await respond(F.dcqlRequest(F.dcqlSdJwt("pid"), responseMode: "fragment"))
        XCTAssertNil(params)
    }
}
