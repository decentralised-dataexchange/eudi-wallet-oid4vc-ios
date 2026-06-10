import XCTest
@testable import eudiWalletOidcIos

final class SessionTranscriptTests: XCTestCase {

    // Fixed inputs shared with the Android + Python oracle cross-check.
    let clientId = "x509_san_dns:verifier.example.com"
    let nonce = "abc123nonce"
    let responseUri = "https://verifier.example.com/response"

    // Expected hex from cbor2 (Python) reference oracle for ISO/IEC TS 18013-7 §B.4.4.
    let expectedAnnexB =
        "83f6f68358209931fddd7d5a6be54343f3cbf96ade069322940201e993a003b4e187aa4e929a582000bc1a24fd8af2240ff62f365a22a2706a3cab9647e78a23f433458c7b73e77a6b6162633132336e6f6e6365"

    func testAnnexB18013_7Transcript() {
        let (_, bytes) = buildSessionTranscriptForAnnexB18013_7(
            clientId: clientId,
            nonce: nonce,
            responseUri: responseUri
        )
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        print("iOS ANNEXB \(hex)")
        XCTAssertEqual(hex, expectedAnnexB, "Annex B session transcript must match the reference oracle")
    }

    func testOpenID4VPTranscriptStructure() {
        // Sanity: the OpenID4VP handover stays distinct (labelled) and decodes to [null,null,[label,hash]].
        let (_, bytes) = buildSessionTranscriptForOpenID4VP(
            clientId: clientId,
            nonce: nonce,
            responseUri: responseUri,
            jwkThumbprint: nil,
            responseMode: nil
        )
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        print("iOS OID4VP \(hex)")
        // Must contain the "OpenID4VPHandover" label and NOT be identical to Annex B.
        XCTAssertNotEqual(hex, expectedAnnexB)
        XCTAssertTrue(hex.hasPrefix("83f6f6"), "SessionTranscript = [null,null,handover]")
    }
}
