import XCTest
@testable import eudiWalletOidcIos

/// The batch key-attestation request body and the wallet clock.
final class KeyAttestationRequestTests: XCTestCase {

    private let keyA: [String: Any] = ["kty": "EC", "crv": "P-256", "x": "a", "y": "b"]
    private let keyB: [String: Any] = ["kty": "EC", "crv": "P-256", "x": "c", "y": "d"]
    private let evidenceA = IosAppAttestEvidence(attestationObject: "objA", keyId: "idA")
    private let evidenceB = IosAppAttestEvidence(attestationObject: "objB", keyId: "idB")

    func testOneKeyKeepsTheSingleObjectShape() {
        let body = KeyAttestationRequest(attestedKeys: [keyA], iosAppAttest: [evidenceA]).toDictionary()
        let appAttest = body["ios_app_attest"] as? [String: String]
        XCTAssertEqual(appAttest?["attestation_object"], "objA")
        XCTAssertEqual(appAttest?["key_id"], "idA")
    }

    func testSeveralKeysSendAnIndexAlignedList() {
        let body = KeyAttestationRequest(attestedKeys: [keyA, keyB], iosAppAttest: [evidenceA, evidenceB]).toDictionary()
        let appAttest = body["ios_app_attest"] as? [[String: String]]
        XCTAssertEqual(appAttest?.map { $0["key_id"] }, ["idA", "idB"])
        XCTAssertEqual((body["attested_keys"] as? [[String: Any]])?.count, 2)
    }

    func testTheSoftwareTierSendsKeyPopsAndNoAppAttest() {
        let body = KeyAttestationRequest(attestedKeys: [keyA, keyB], keyPops: ["p1", "p2"]).toDictionary()
        XCTAssertEqual(body["key_pops"] as? [String], ["p1", "p2"])
        XCTAssertNil(body["ios_app_attest"])
    }

    func testTheResponseReadsAttestedKeysCount() throws {
        let json = #"{"keyAttestation":"ka","attestationType":"ios_app_attest","keyStorage":["iso_18045_high"],"attestedKeysCount":2}"#
        let response = try JSONDecoder().decode(KeyAttestationResponse.self, from: Data(json.utf8))
        XCTAssertEqual(response.attestedKeysCount, 2)
        XCTAssertTrue(KeyAttestationOutcome(httpCode: 200, response: response, errorBody: nil).isSuccessful)
        XCTAssertFalse(KeyAttestationOutcome(httpCode: 400, response: nil, errorBody: "invalid_key_evidence").isSuccessful)
    }

    func testIssuedAtIsBackdatedAndNeverPostDated() {
        WalletClock.configure(skewBackdate: 60)
        XCTAssertEqual(WalletClock.now().timeIntervalSince(WalletClock.issuedAt()), 60, accuracy: 1)
        WalletClock.configure(skewBackdate: -5)
        XCTAssertEqual(WalletClock.skewBackdate, 0)
        WalletClock.configure(skewBackdate: WalletClock.defaultSkewBackdate)
    }
}
