import XCTest
import SwiftCBOR
@testable import eudiWalletOidcIos

/// The device key of an mdoc, read from the MSO, pairs a batch of mdocs with
/// the keys they were requested for (the SD-JWT `cnf.jwk` counterpart).
final class MdocDeviceKeyTests: XCTestCase {

    private func issuerSigned(x: [UInt8], y: [UInt8]) -> String {
        let deviceKey: CBOR = .map([.unsignedInt(1): .unsignedInt(2), .negativeInt(0): .unsignedInt(1),
                                    .negativeInt(1): .byteString(x), .negativeInt(2): .byteString(y)])
        let mso: CBOR = .map([.utf8String("docType"): .utf8String("eu.europa.ec.eudi.pid.1"),
                              .utf8String("deviceKeyInfo"): .map([.utf8String("deviceKey"): deviceKey])])
        let payload: CBOR = .tagged(CBOR.Tag(rawValue: 24), .byteString(mso.encode()))
        let issuerAuth: CBOR = .array([.byteString([0xA0]), .map([:]), .byteString(payload.encode()), .byteString([1, 2, 3])])
        let issuerSigned: CBOR = .map([.utf8String("issuerAuth"): issuerAuth])
        return Data(issuerSigned.encode()).base64URLEncodedString()
    }

    func testTheDeviceKeyIsReadFromTheMso() {
        let x = [UInt8](repeating: 1, count: 32), y = [UInt8](repeating: 2, count: 32)
        let key = MDocVpTokenBuilder().extractDeviceKeyFromIssuerSigned(credential: issuerSigned(x: x, y: y))
        XCTAssertEqual(key?["x"], Data(x).base64URLEncodedString())
        XCTAssertEqual(key?["y"], Data(y).base64URLEncodedString())
    }

    func testAnUnreadableCredentialHasNoDeviceKey() {
        XCTAssertNil(MDocVpTokenBuilder().extractDeviceKeyFromIssuerSigned(credential: "not-cbor"))
    }
}
