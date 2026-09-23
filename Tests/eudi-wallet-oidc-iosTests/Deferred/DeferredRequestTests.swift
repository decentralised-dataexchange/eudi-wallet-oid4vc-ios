//
//  DeferredRequestTests.swift
//

import XCTest
import CryptoKit
@testable import eudiWalletOidcIos

/// The deferred credential request, section 9.
///
/// None of these could have passed before: the request went out through `NetworkLogger`'s default
/// `URLSession.shared` and every failure became a bare `nil`, so `issuance_pending` — the credential
/// is still coming — was indistinguishable from `invalid_transaction_id`, the transaction is dead.
///
/// Mirrors `DeferredRequestResolverTest` in the Android SDK.
final class DeferredRequestTests: XCTestCase {

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    private func session(deferredEndpoint: String? = "https://issuer.example.com/deferred") -> IssuanceSession {
        let json = """
        {
          "credentialIssuer": "https://issuer.example.com",
          "declaresAuthorizationServers": false,
          "credentialEndpoint": "https://issuer.example.com/credential"
          \(deferredEndpoint.map { ", \"deferredCredentialEndpoint\": \"\($0)\"" } ?? "")
        }
        """
        let config = try! JSONDecoder().decode(IssuerWellKnownConfiguration.self, from: Data(json.utf8))
        return IssuanceSession(credentialOffer: nil, issuerConfig: config, authConfig: nil)
    }

    private func token(tokenType: String? = "Bearer") -> TokenResponse {
        var token = TokenResponse()
        token.accessToken = "at-1"
        token.tokenType = tokenType
        return token
    }

    @discardableResult
    private func resolve(
        transaction: DeferredTransaction = .transactionId("txn-1"),
        token: TokenResponse? = nil,
        attestation: WalletAttestation? = nil,
        policy: DeferredRequestPolicy = .standard,
        status: Int = 200,
        responseHeaders: [String: String] = ["Content-Type": "application/json"],
        responseBody: String = #"{"credential":"vc-1"}"#
    ) async -> (body: [String: Any], headers: [String: String], outcome: CredentialOutcome) {
        var seen: [String: Any] = [:]
        var seenHeaders: [String: String] = [:]
        StubURLProtocol.handler = { request in
            seen = Self.body(of: request)
            seenHeaders = request.allHTTPHeaderFields ?? [:]
            let response = HTTPURLResponse(
                url: request.url!, statusCode: status, httpVersion: nil, headerFields: responseHeaders
            )!
            return (response, Data(responseBody.utf8))
        }
        let outcome = await DeferredRequestResolver(policy: policy).resolve(
            session: session(),
            token: token ?? self.token(),
            transaction: transaction,
            attestation: attestation,
            urlSession: StubURLProtocol.session()
        )
        return (seen, seenHeaders, outcome)
    }

    static func body(of request: URLRequest) -> [String: Any] {
        guard let stream = request.httpBodyStream else {
            guard let data = request.httpBody else { return [:] }
            return ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any]) ?? [:]
        }
        stream.open()
        defer { stream.close() }
        var data = Data()
        let size = 4096
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
        defer { buffer.deallocate() }
        while stream.hasBytesAvailable {
            let read = stream.read(buffer, maxLength: size)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any]) ?? [:]
    }

    // MARK: - the request

    func testTheTransactionIdIsSentInTheBody() async {
        let (body, _, _) = await resolve()
        XCTAssertEqual(body["transaction_id"] as? String, "txn-1")
    }

    func testACredentialIdentifierIsSentAlongsideItWhenThereIsOne() async {
        let (body, _, _) = await resolve(
            transaction: .transactionId("txn-1", credentialIdentifier: "cred-a")
        )
        XCTAssertEqual(body["credential_identifier"] as? String, "cred-a")
    }

    func testThePolicyCanWithholdTheCredentialIdentifier() async {
        let (body, _, _) = await resolve(
            transaction: .transactionId("txn-1", credentialIdentifier: "cred-a"),
            policy: .legacy
        )
        XCTAssertNil(body["credential_identifier"])
    }

    /// The draft form carries its handle as the bearer token and sends nothing. The whole reason
    /// the old function branched on a stored version string.
    func testTheDraftAcceptanceTokenAuthenticatesWithTheHandleAndSendsAnEmptyBody() async {
        let (body, headers, _) = await resolve(transaction: .legacyAcceptanceToken("acc-1"))
        XCTAssertEqual(headers["Authorization"], "Bearer acc-1")
        XCTAssertTrue(body.isEmpty)
    }

    func testADPoPBoundTokenStaysDPoPBoundOnTheDeferredEndpoint() async {
        let (_, headers, _) = await resolve(
            token: token(tokenType: "DPoP"),
            attestation: WalletAttestation(
                attestationJwt: nil, proofOfPossession: nil, dpopKey: P256.Signing.PrivateKey()
            )
        )
        XCTAssertEqual(headers["Authorization"], "DPoP at-1")
        XCTAssertFalse(headers["DPoP"]?.isEmpty ?? true)
    }

    // MARK: - reading the answer

    func testACredentialEndsThePolling() async {
        let (_, _, outcome) = await resolve(
            responseBody: #"{"credentials":[{"credential":"vc-1"},{"credential":"vc-2"}]}"#
        )
        guard case let .issued(credentials, _, _) = outcome else {
            return XCTFail("expected issued, got \(outcome)")
        }
        XCTAssertEqual(credentials, ["vc-1", "vc-2"])
    }

    /// Section 9.3. The whole point of the pass: still-pending is not a failure, and the issuer's
    /// own `interval` replaces the fixed one the wallet used to guess.
    func testIssuancePendingComesBackAsDeferredWithTheIssuersInterval() async {
        let (_, _, outcome) = await resolve(
            status: 400,
            responseBody: #"{"error":"issuance_pending","interval":42}"#
        )
        guard case let .deferred(transactionId, interval) = outcome else {
            return XCTFail("expected deferred, got \(outcome)")
        }
        XCTAssertEqual(transactionId, "txn-1")
        XCTAssertEqual(interval, 42)
    }

    func testIssuancePendingWithoutAnIntervalStillDefers() async {
        let (_, _, outcome) = await resolve(
            status: 400, responseBody: #"{"error":"issuance_pending"}"#
        )
        guard case let .deferred(_, interval) = outcome else {
            return XCTFail("expected deferred, got \(outcome)")
        }
        XCTAssertNil(interval)
    }

    /// A dead transaction must stop the polling, which a nil could never say.
    func testInvalidTransactionIdIsAFailureCarryingTheCodeAndTheStatus() async {
        let (_, _, outcome) = await resolve(
            status: 400,
            responseBody: #"{"error":"invalid_transaction_id","error_description":"expired"}"#
        )
        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        XCTAssertEqual(error.errorCode, "invalid_transaction_id")
        XCTAssertEqual(error.httpStatus, 400)
        XCTAssertEqual(error.message, "expired")
    }

    /// Section 9.2: the deferred response may itself be deferred again.
    func testAResponseThatDefersAgainYieldsTheNewHandle() async {
        let (_, _, outcome) = await resolve(
            responseBody: #"{"transaction_id":"txn-2","interval":5}"#
        )
        guard case let .deferred(transactionId, interval) = outcome else {
            return XCTFail("expected deferred, got \(outcome)")
        }
        XCTAssertEqual(transactionId, "txn-2")
        XCTAssertEqual(interval, 5)
    }

    /// Some issuers answer a still-pending poll with 200 and an `interval`, naming no transaction
    /// id at all, rather than section 9.3's 400 + `issuance_pending`. Read strictly that is
    /// "neither a credential nor a transaction id" and the polling stops; the handle we are already
    /// polling with is the one the issuer still means, so it is reused.
    func testA200CarryingOnlyAnIntervalKeepsPollingWithTheHandleWeAlreadyHold() async {
        let (_, _, outcome) = await resolve(responseBody: #"{"interval":7}"#)

        guard case let .deferred(transactionId, interval) = outcome else {
            return XCTFail("expected deferred, got \(outcome)")
        }
        XCTAssertEqual(transactionId, "txn-1")
        XCTAssertEqual(interval, 7)
    }

    /// The accommodation is opt-out: an issuer can be held to section 9.3 instead.
    func testStrictRefusesTheIntervalOnlyResponseTheSpecificationDoesNotDefine() async {
        let (_, _, outcome) = await resolve(policy: .strict, responseBody: #"{"interval":7}"#)

        guard case .failed = outcome else { return XCTFail("expected failure, got \(outcome)") }
    }

    /// The interval is what distinguishes "come back later" from a malformed body. Without it the
    /// response really is unreadable, and saying so beats polling something that will never arrive.
    func testA200WithNoIntervalAndNoIdsIsStillAFailure() async {
        let (_, _, outcome) = await resolve(responseBody: "{}")

        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        XCTAssertTrue(
            error.message?.contains("neither a credential nor a transaction id") == true,
            error.message ?? ""
        )
    }

    /// iOS-only: the exact `Content-Type` compare this replaces missed a charset parameter.
    func testAnEncryptedResponseWithACharsetParameterIsStillRecognised() async {
        let (_, _, outcome) = await resolve(
            responseHeaders: ["Content-Type": "application/jwt; charset=utf-8"],
            responseBody: "eyJhbGciOiJFQ0RILUVTIn0..aaa.bbb.ccc"
        )
        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        XCTAssertTrue(error.message?.contains("decryption key") == true, error.message ?? "")
    }

    /// iOS-only: a 4xx with nothing in it must not read as success.
    func testAnEmptyErrorBodyIsStillAFailure() async {
        let (_, _, outcome) = await resolve(status: 500, responseBody: "")
        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        XCTAssertEqual(error.httpStatus, 500)
    }

    func testAnIssuerWithNoDeferredEndpointIsANamedFailure() async {
        let outcome = await DeferredRequestResolver().resolve(
            session: session(deferredEndpoint: nil),
            token: token(),
            transaction: .transactionId("txn-1"),
            urlSession: StubURLProtocol.session()
        )
        guard case let .failed(error) = outcome else { return XCTFail("expected failure") }
        XCTAssertTrue(
            error.message?.contains("deferred credential endpoint") == true, error.message ?? ""
        )
    }
}
