import XCTest
import CryptoKit
@testable import eudiWalletOidcIos

/// The request binding that App Attest signs on a wallet-unit request:
/// base64url(SHA-256(UTF-8(nonce + "." + base64url(SHA-256(UTF-8(thumbprint)))))).
final class WalletUnitRequestBindingTests: XCTestCase {

    // RFC 7638 section 3.1 RSA key.
    private let rsaCanonical = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}"

    func testRfc7638VectorGivesTheExpectedBinding() {
        let thumbprint = Data(SHA256.hash(data: Data(rsaCanonical.utf8))).base64URLEncodedString()
        XCTAssertEqual(thumbprint, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
        XCTAssertEqual(BatchRequestHash.requestBinding(nonce: "nonce-1", thumbprint: thumbprint),
                       "8SKGVXFzPQN7a43xJf2yXahnsGotUBNsc7ZUkFEp11M")
    }

    func testBindingChangesWithTheNonce() {
        XCTAssertNotEqual(BatchRequestHash.requestBinding(nonce: "a", thumbprint: "t"),
                          BatchRequestHash.requestBinding(nonce: "b", thumbprint: "t"))
    }

    func testAttestationIsSentAsBase64Url() {
        let bytes = Data([0xfb, 0xff, 0xfe, 0x00])
        XCTAssertEqual(WalletUnitAttestationService.base64URL(fromBase64: bytes.base64EncodedString()), "-__-AA")
    }

    func testRequestsRunOneAfterTheOther() async throws {
        let queue = WalletUnitRequestQueue()
        let log = Log()
        async let first: Void = queue.run { await log.add("start 1"); try await Task.sleep(nanoseconds: 50_000_000); await log.add("end 1") }
        try await Task.sleep(nanoseconds: 5_000_000)
        async let second: Void = queue.run { await log.add("start 2"); await log.add("end 2") }
        _ = try await (first, second)
        let entries = await log.entries
        XCTAssertEqual(entries, ["start 1", "end 1", "start 2", "end 2"])
    }

    private actor Log {
        var entries: [String] = []
        func add(_ entry: String) { entries.append(entry) }
    }
}
