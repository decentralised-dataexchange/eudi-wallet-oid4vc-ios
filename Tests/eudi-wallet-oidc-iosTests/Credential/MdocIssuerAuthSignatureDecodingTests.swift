import XCTest
import SwiftCBOR
@testable import eudiWalletOidcIos

/// The readers of an mdoc `issuerAuth` try every byte string of the COSE_Sign1
/// as CBOR, the signature included. A signature is random bytes, and roughly
/// one in eighty starts like a CBOR array that declares a huge item count.
/// SwiftCBOR reserves that count before reading anything, the allocation fails
/// and the process aborts; `try?` cannot catch it.
///
/// Each test hands a reader a valid mdoc carrying such a signature. While the
/// reader decodes unguarded the test process crashes instead of failing.
final class MdocIssuerAuthSignatureDecodingTests: XCTestCase {

    private let docType = "eu.europa.ec.eudi.pid.1"
    private let statusIndex = 5
    private let statusUri = "https://issuer.example/status/1"

    /// 64 bytes that begin with the header of an array of 2^48 items.
    private let hugeArraySignature: [UInt8] =
        [0x9B, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] + [UInt8](repeating: 0x11, count: 55)

    /// 64 bytes that fail to decode as CBOR, as most signatures do.
    private let ordinarySignature = [UInt8](repeating: 0x1C, count: 64)

    private func issuerAuth(signature: [UInt8]) -> CBOR {
        let statusList: CBOR = .map([.utf8String("idx"): .unsignedInt(UInt64(statusIndex)),
                                     .utf8String("uri"): .utf8String(statusUri)])
        let mso: CBOR = .map([.utf8String("docType"): .utf8String(docType),
                              .utf8String("status"): .map([.utf8String("status_list"): statusList])])
        let payload: CBOR = .tagged(CBOR.Tag(rawValue: 24), .byteString(mso.encode()))
        return .array([.byteString([0xA1, 0x01, 0x26]), .map([:]),
                       .byteString(payload.encode()), .byteString(signature)])
    }

    private func assertStatus(_ status: [String: Any]?, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(status?["idx"] as? Int, statusIndex, file: file, line: line)
        XCTAssertEqual(status?["uri"] as? String, statusUri, file: file, line: line)
    }

    // MARK: - An ordinary signature

    func testTheStatusIsReadWithAnOrdinarySignature() {
        assertStatus(MDOCRevocationHelper().getStatusFromIssuerAuth(cborData: issuerAuth(signature: ordinarySignature)))
    }

    // MARK: - A signature that starts like a huge array

    func testTheRevocationStatusIsReadWhenTheSignatureStartsLikeAHugeArray() {
        assertStatus(MDOCRevocationHelper().getStatusFromIssuerAuth(cborData: issuerAuth(signature: hugeArraySignature)))
    }

    func testTheStatusListItemsAreReadWhenTheSignatureStartsLikeAHugeArray() {
        let service = VerificationService(keyhandler: StubKeyHandler())
        let (index, uri) = service.getStatusListItemsFromCbor(cborData: issuerAuth(signature: hugeArraySignature))
        XCTAssertEqual(index, statusIndex)
        XCTAssertEqual(uri, statusUri)
    }
}
