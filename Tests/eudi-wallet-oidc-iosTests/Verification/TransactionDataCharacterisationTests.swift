//
//  TransactionDataCharacterisationTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
@testable import eudiWalletOidcIos

/// Characterisation of transaction data and SCA claims in the key binding JWT as they behave
/// today. See `PexResponseCharacterisationTests` for the purpose of these tests.
final class TransactionDataCharacterisationTests: ResponseCharacterisationTestCase {

    private typealias F = VerificationFixtures

    private func kbClaims(_ request: PresentationRequest, isSca: Bool = false, inherence: String? = nil,
                          knowledge: String? = nil) async throws -> [String: Any] {
        let params = await respond(request, [[F.sdJwt()]], isSca: isSca, inherence: inherence, knowledge: knowledge)
        let presented: String
        if request.dcqlQuery != nil {
            presented = try XCTUnwrap((F.object(params?["vp_token"]) as? [String: Any])?["pid"] as? [String]).first ?? ""
        } else {
            presented = try XCTUnwrap(params?["vp_token"] as? String)
        }
        return try XCTUnwrap(JWTParts.claims(F.keyBindingJwt(presented)))
    }

    private let sca = F.transactionData("urn:eudi:sca:payment", "pid")

    func testScaFlagPutsResponseModeAndTheGivenAmrFactorsInTheKbJwt() async throws {
        let claims = try await kbClaims(F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [sca]), isSca: true,
                                        inherence: "fingerprint_device", knowledge: "other")

        XCTAssertEqual(claims["response_mode"] as? String, "direct_post")
        XCTAssertNotNil(claims["jti"])
        XCTAssertEqual(claims["amr"] as? [[String: String]], [["possession": "key_in_local_native_wscd"],
                                                             ["inherence": "fingerprint_device"],
                                                             ["knowledge": "other"]])
    }

    func testScaFlagWithoutFactorsSendsPossessionAlone() async throws {
        let claims = try await kbClaims(F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [sca]), isSca: true)
        XCTAssertEqual(claims["amr"] as? [[String: String]], [["possession": "key_in_local_native_wscd"]])
    }

    func testScaFlagWithoutTransactionDataStillAddsTheScaClaims() async throws {
        // Leg 6, as Android: passing the authentication factors is the statement that this is SCA.
        let claims = try await kbClaims(F.dcqlRequest(F.dcqlSdJwt("pid")), isSca: true, inherence: "fingerprint_device")
        XCTAssertEqual(claims["response_mode"] as? String, "direct_post")
        XCTAssertNotNil(claims["amr"])
    }

    func testAUrnEudiScaTransactionTypeIsScaWithTheFlagOff() async throws {
        // Leg 6, as Android: SCA is detected from the type; with no factors only possession is claimed.
        let claims = try await kbClaims(F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [sca]), inherence: "fingerprint_device")
        XCTAssertEqual(claims["response_mode"] as? String, "direct_post")
        XCTAssertEqual(claims["amr"] as? [[String: String]], [["possession": "key_in_local_native_wscd"]])
    }

    func testAPaymentDataTransactionTypeIsNotSca() async throws {
        let request = F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [F.transactionData("payment_data", "pid")])
        let claims = try await kbClaims(request)
        XCTAssertNil(claims["response_mode"])
        XCTAssertNil(claims["amr"])
    }

    func testATransactionEntryNamingThisCredentialIdIsHashedIntoTheKbJwt() async throws {
        let claims = try await kbClaims(F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [sca]))

        XCTAssertEqual(claims["transaction_data_hashes"] as? [String], [F.sha256(sca)])
        XCTAssertEqual(claims["transaction_data_hashes_alg"] as? String, "sha-256")
    }

    func testATransactionEntryNamingAnInputDescriptorIdIsHashedOnThePexPathToo() async throws {
        let claims = try await kbClaims(F.pexRequest(F.sdJwtDescriptor("pid"), transactionData: [sca]))
        XCTAssertEqual(claims["transaction_data_hashes"] as? [String], [F.sha256(sca)])
    }

    func testThePexPathHonoursTheScaFlag() async throws {
        let params = await respond(F.pexRequest(F.sdJwtDescriptor("pid"), transactionData: [sca]), [[F.sdJwt()]],
                                   isSca: true, inherence: "fingerprint_device")
        let claims = try XCTUnwrap(JWTParts.claims(F.keyBindingJwt(try XCTUnwrap(params?["vp_token"] as? String))))
        XCTAssertEqual(claims["response_mode"] as? String, "direct_post")
        XCTAssertNotNil(claims["amr"])
    }

    func testATransactionEntryNamingAnotherRequestedIdAddsNoHashesHere() async throws {
        let entry = F.transactionData("urn:eudi:sca:payment", "other")
        let params = await respond(F.dcqlRequest(F.dcqlSdJwt("pid"), F.dcqlSdJwt("other"), transactionData: [entry]),
                                   [[F.sdJwt()], []])
        let presented = try XCTUnwrap((F.object(params?["vp_token"]) as? [String: Any])?["pid"] as? [String]).first ?? ""
        let claims = try XCTUnwrap(JWTParts.claims(F.keyBindingJwt(presented)))

        XCTAssertNil(claims["transaction_data_hashes"])
        XCTAssertNil(claims["transaction_data_hashes_alg"])
    }

    func testATransactionEntryNamingAnIdTheQueryDoesNotRequestLeavesNothingToSend() async {
        let entry = F.transactionData("urn:eudi:sca:payment", "someone-else")
        let params = await respond(F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [entry]), [[F.sdJwt()]])
        XCTAssertNil(params, "leg 6: invalid_transaction_data")
    }

    func testEveryTransactionEntryNamingTheCredentialIsHashedInOrder() async throws {
        let second = F.transactionData("urn:eudi:sca:emandate", "pid")
        let claims = try await kbClaims(F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [sca, second]))
        XCTAssertEqual(claims["transaction_data_hashes"] as? [String], [F.sha256(sca), F.sha256(second)])
    }

    func testATransactionEntryThatIsNotBase64UrlJsonLeavesNothingToSend() async {
        let params = await respond(F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: ["not base64url!"]), [[F.sdJwt()]])
        XCTAssertNil(params, "leg 6: invalid_transaction_data")
    }
}
