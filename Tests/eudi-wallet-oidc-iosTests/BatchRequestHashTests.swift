import XCTest
import CryptoKit
@testable import eudiWalletOidcIos

/// The batch wallet-unit request hash:
/// base64url(SHA-256(concat(sorted(RFC 7638 thumbprints)))), no padding.
/// The wallet provider recomputes it, so every detail here (thumbprint
/// canonical form, sort order, no separator, no padding) is wire contract.
/// Same vectors as the Android BatchRequestHashTest.
final class BatchRequestHashTests: XCTestCase {

    // RFC 7515 Appendix A.3 P-256 public key.
    let keyA: [String: Any] = ["kty": "EC", "crv": "P-256",
                               "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                               "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"]
    // RFC 7517 Appendix A.1 P-256 public key.
    let keyB: [String: Any] = ["kty": "EC", "crv": "P-256",
                               "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                               "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"]

    private func sha256B64Url(_ input: String) -> String {
        Data(SHA256.hash(data: Data(input.utf8))).base64URLEncodedString()
    }

    private func rfc7638(_ key: [String: Any]) -> String {
        sha256B64Url("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(key["x"]!)\",\"y\":\"\(key["y"]!)\"}")
    }

    func testThumbprintMatchesTheRfc7638CanonicalForm() {
        XCTAssertEqual(Data(computeJwkThumbprintBytes(jwk: keyA)).base64URLEncodedString(), rfc7638(keyA))
        XCTAssertEqual(Data(computeJwkThumbprintBytes(jwk: keyB)).base64URLEncodedString(), rfc7638(keyB))
    }

    func testHashIsIndependentOfKeyOrder() {
        XCTAssertEqual(BatchRequestHash.compute(jwks: [keyA, keyB]), BatchRequestHash.compute(jwks: [keyB, keyA]))
    }

    func testHashEqualsSha256OfTheSortedThumbprintsJoinedWithNoSeparator() {
        let expected = sha256B64Url([rfc7638(keyA), rfc7638(keyB)].sorted().joined())
        XCTAssertEqual(BatchRequestHash.compute(jwks: [keyA, keyB]), expected)
    }

    func testSingleKeyHashIsSha256OfItsThumbprint() {
        XCTAssertEqual(BatchRequestHash.compute(jwks: [keyA]), sha256B64Url(rfc7638(keyA)))
    }

    func testOutputIsBase64UrlWithoutPadding() {
        let hash = BatchRequestHash.compute(jwks: [keyA, keyB])
        XCTAssertEqual(hash.count, 43)
        XCTAssertNotNil(hash.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression))
    }

    func testThumbprintsAreSortedByCodePoint() {
        // '-' (0x2D) < 'A' (0x41) < '_' (0x5F) < 'b' (0x62)
        XCTAssertEqual(BatchRequestHash.computeFromThumbprints(["b", "A", "_", "-"]), sha256B64Url("-A_b"))
    }

    func testDifferentKeySetsGiveDifferentHashes() {
        XCTAssertNotEqual(BatchRequestHash.compute(jwks: [keyA]), BatchRequestHash.compute(jwks: [keyA, keyB]))
    }
}
