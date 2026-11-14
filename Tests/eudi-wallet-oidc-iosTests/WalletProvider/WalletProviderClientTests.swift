import XCTest
import DeviceCheck
import CryptoKit
@testable import eudiWalletOidcIos

/// The wallet provider protocol 2 client against a stubbed wallet provider.
///
/// Every signed request the stub receives is checked the way the wallet
/// provider checks it: the Content-Digest against the body, and the RFC 9421
/// signature rebuilt from the headers and verified with the request key. App
/// Attest and the Secure Enclave are replaced by fakes (the test host has
/// neither).
final class WalletProviderClientTests: XCTestCase {

    private let base = "https://wp.example/organisation/org-1/service/wallet-provider"
    private var keys: FakeRequestKeys!
    private var attester: FakeAttester!
    private var server: StubWalletProvider!

    override func setUp() {
        super.setUp()
        keys = FakeRequestKeys()
        attester = FakeAttester()
        let server = StubWalletProvider()
        self.server = server
        StubURLProtocol.handler = { request in try server.handle(request) }
    }

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    private func client(baseUrl: String? = nil) -> WalletProviderClient {
        WalletProviderClient(baseUrl: baseUrl ?? base, appVersion: "2026.12.0", appBuild: "7",
                             urlSession: StubURLProtocol.session(), requestKeys: keys, attester: attester,
                             clock: { Date(timeIntervalSince1970: 1_794_556_860) })
    }

    private func registered() throws {
        _ = try keys.make()
        attester.registeredKeyId = "registered-key"
    }

    private static let wiaAnswer = #"{"walletUnitAttestation":"wia.jwt","credentialIssuer":"https://wp.example/organisation/org-1/service/version-01"}"#

    // MARK: - Registration and assertions

    func testTheFirstWiaRequestRegistersTheUnit() async throws {
        server.answers["/wallet-unit/request"] = [(200, #"{"walletUnitAttestation":"wia.jwt","revocationCode":"7KQ2 M9XA H4TD 0RWE 5BNC"}"#)]
        let cnf = StubKeyHandler()

        let outcome = await client().requestWalletUnitAttestation(cnfKey: cnf, clientId: "did:key:unit")

        guard case .success(let response) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(response.walletUnitAttestation, "wia.jwt")
        XCTAssertEqual(response.revocationCode, "7KQ2 M9XA H4TD 0RWE 5BNC")
        XCTAssertEqual(attester.attestCount, 1)
        XCTAssertEqual(attester.registeredKeyId, "key-1")

        let request = try XCTUnwrap(server.signed.last)
        let key = try XCTUnwrap(keys.key)
        try server.verify(request, with: key)
        XCTAssertNotNil(request.headers["X-Wallet-Unit-Request-Key"])
        XCTAssertEqual(request.components.last, "x-wallet-unit-request-key")
        XCTAssertEqual(request.headers["X-Wallet-Unit-Integrity-Token"], Data("attestation-1".utf8).base64URLEncodedString())
        XCTAssertEqual(request.headers["X-Wallet-Unit-KeyID"], "key-1")
        XCTAssertEqual(request.headers["X-Wallet-Unit-Platform"], "ios")
        XCTAssertEqual(request.headers["X-Wallet-App-Version"], "2026.12.0")
        XCTAssertEqual(request.headers["X-Wallet-App-Build"], "7")
        XCTAssertEqual(request.headers["Content-Type"], "application/json")

        // The attestation covers the nonce, the cnf key and the request key.
        let binding = BatchRequestHash.requestBinding(nonce: server.lastNonce, jwks: [cnf.publicJWK, key.publicJWK])!
        XCTAssertEqual(attester.lastClientDataHash, BatchRequestHash.clientDataHash(binding: binding))

        let body = try XCTUnwrap(request.json)
        XCTAssertEqual(body["client_assertion_type"] as? String, WalletProviderClient.clientAssertionType)
        XCTAssertEqual(body["profile"] as? String, "ts3")
        let claims = try XCTUnwrap(JWTParts.claims(body["client_assertion"] as! String))
        XCTAssertEqual(claims["client_id"] as? String, "did:key:unit")
        XCTAssertEqual(claims["aud"] as? String, base)
    }

    func testALaterRequestSendsAnAssertionOfTheRegisteredKey() async throws {
        try registered()
        server.answers["/wallet-unit/request"] = [(200, Self.wiaAnswer)]
        let cnf = StubKeyHandler()

        let outcome = await client().requestWalletUnitAttestation(cnfKey: cnf, clientId: "did:key:unit")

        guard case .success = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(attester.attestCount, 0)
        let request = try XCTUnwrap(server.signed.last)
        try server.verify(request, with: try XCTUnwrap(keys.key))
        XCTAssertNil(request.headers["X-Wallet-Unit-Request-Key"])
        XCTAssertEqual(request.components, WalletProviderClient.components)
        XCTAssertEqual(request.headers["X-Wallet-Unit-Integrity-Token"], Data("assertion-1".utf8).base64URLEncodedString())
        XCTAssertEqual(request.headers["X-Wallet-Unit-KeyID"], "registered-key")
        let binding = BatchRequestHash.requestBinding(nonce: server.lastNonce, jwks: [cnf.publicJWK])!
        XCTAssertEqual(attester.lastClientDataHash, BatchRequestHash.clientDataHash(binding: binding))
    }

    func testABatchBindsEveryCnfKeyAndSharesTheClientId() async throws {
        try registered()
        server.answers["/wallet-unit/request/batch"] = [(200, #"{"walletUnitAttestations":["w1","w2"]}"#)]
        let cnfKeys = [StubKeyHandler(), StubKeyHandler()]

        let outcome = await client().requestWalletUnitAttestations(cnfKeys: cnfKeys, clientId: "did:key:unit")

        guard case .success(let batch) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(batch.attestations, ["w1", "w2"])
        XCTAssertEqual(batch.units.count, 2)
        let body = try XCTUnwrap(server.signed.last?.json)
        let assertions = try XCTUnwrap(body["client_assertions"] as? [String])
        XCTAssertEqual(assertions.compactMap { JWTParts.claims($0)?["client_id"] as? String }, ["did:key:unit", "did:key:unit"])
        let binding = BatchRequestHash.requestBinding(nonce: server.lastNonce, jwks: cnfKeys.map { $0.publicJWK })!
        XCTAssertEqual(attester.lastClientDataHash, BatchRequestHash.clientDataHash(binding: binding))
    }

    func testTwoRequestsAtOnceRegisterOnlyOnce() async throws {
        server.answers["/wallet-unit/request"] = [(200, Self.wiaAnswer), (200, Self.wiaAnswer)]
        let client = client()

        async let first = client.requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "did:key:unit")
        async let second = client.requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "did:key:unit")
        let outcomes = await [first, second]

        for outcome in outcomes { guard case .success = outcome else { return XCTFail("\(outcome)") } }
        XCTAssertEqual(attester.attestCount, 1)
        XCTAssertEqual(attester.assertCount, 1)
        XCTAssertEqual(server.signed.filter { $0.headers["X-Wallet-Unit-Request-Key"] != nil }.count, 1)
    }

    // MARK: - Refusals the client fixes itself

    func testARefusedSignatureIsSentAgainOnceWithANewNonce() async throws {
        try registered()
        server.answers["/wallet-unit/request"] = [
            (401, #"{"error":"invalid_client","error_id":"individual_wallet_unit.request_signature_invalid"}"#),
            (200, Self.wiaAnswer)
        ]

        let outcome = await client().requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "did:key:unit")

        guard case .success = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(server.nonceCount, 2)
        XCTAssertEqual(server.signed.count, 2)
        XCTAssertNotEqual(server.signed[0].headers["X-Wallet-Unit-Nonce"], server.signed[1].headers["X-Wallet-Unit-Nonce"])
    }

    func testASecondRefusedSignatureComesBack() async throws {
        try registered()
        let refusal = (401, #"{"error":"invalid_client","error_id":"individual_wallet_unit.request_signature_invalid"}"#)
        server.answers["/wallet-unit/request"] = [refusal, refusal]

        let outcome = await client().requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "did:key:unit")

        guard case .failed(let error) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(error.errorId, "individual_wallet_unit.request_signature_invalid")
        XCTAssertEqual(error.httpStatus, 401)
        XCTAssertEqual(server.signed.count, 2)
    }

    func testRegisteredBeforeMarksTheKeyAndSendsAnAssertion() async throws {
        server.answers["/wallet-unit/request"] = [
            (400, #"{"error":"invalid_request","error_id":"individual_wallet_unit.device_registered_before"}"#),
            (200, Self.wiaAnswer)
        ]

        let outcome = await client().requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "did:key:unit")

        guard case .success = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(attester.registeredKeyId, "key-1")
        XCTAssertNotNil(server.signed[0].headers["X-Wallet-Unit-Request-Key"])
        XCTAssertNil(server.signed[1].headers["X-Wallet-Unit-Request-Key"])
        XCTAssertEqual(server.signed[1].headers["X-Wallet-Unit-Integrity-Token"], Data("assertion-1".utf8).base64URLEncodedString())
    }

    func testARequestKeyInUseIsReplacedAndTheUnitRegistersAgain() async throws {
        server.answers["/wallet-unit/request"] = [
            (409, #"{"error":"invalid_client","error_id":"individual_wallet_unit.request_key_in_use"}"#),
            (200, Self.wiaAnswer)
        ]

        let outcome = await client().requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "did:key:unit")

        guard case .success = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(keys.makeCount, 2)
        XCTAssertEqual(attester.attestCount, 2)
        XCTAssertNotEqual(server.signed[0].keyId, server.signed[1].keyId)
    }

    // MARK: - Refusals for the app

    func testARefusalComesBackWithItsErrorIdAndReason() async throws {
        try registered()
        server.answers["/wallet-unit/request"] = [
            (403, #"{"error":"unauthorized_client","error_description":"revoked","error_id":"individual_wallet_unit.revoked","reason":"user_request"}"#)
        ]

        let outcome = await client().requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "did:key:unit")

        guard case .failed(let error) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(error.errorId, WalletProviderErrorId.revoked)
        XCTAssertEqual(error.reason, "user_request")
        XCTAssertEqual(error.httpStatus, 403)
        XCTAssertEqual(server.signed.count, 1)
    }

    func testAnEmptyNonceStopsTheRequest() async throws {
        try registered()
        server.nonceBody = #"{"c_nonce":""}"#

        let outcome = await client().requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "did:key:unit")

        guard case .failed(let error) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(error.code, ErrorCodes.walletProviderRequestFailed)
        XCTAssertTrue(server.signed.isEmpty)
    }

    func testAnUnreachableWalletProviderIsReportedAsSuch() async throws {
        try registered()
        // The nonce comes; the signed request is lost.
        let server = self.server!
        StubURLProtocol.handler = { request in
            guard request.url!.path.hasSuffix("/nonce") else { throw URLError(.notConnectedToInternet) }
            return try server.handle(request)
        }

        let outcome = await client().requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "did:key:unit")

        guard case .failed(let error) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(error.code, ErrorCodes.walletProviderUnreachable)
        XCTAssertNil(error.httpStatus)
    }

    func testNoNonceMeansNoRequest() async throws {
        try registered()
        StubURLProtocol.handler = { _ in throw URLError(.notConnectedToInternet) }

        let outcome = await client().requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "did:key:unit")

        guard case .failed(let error) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(error.code, ErrorCodes.walletProviderRequestFailed)
    }

    func testALostRequestKeyIsReported() async throws {
        attester.registeredKeyId = "registered-key"

        let outcome = await client().requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "did:key:unit")

        guard case .failed(let error) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(error.code, ErrorCodes.walletUnitKeyLost)
        let isKeyLost = await client().isKeyLost
        XCTAssertTrue(isKeyLost)
    }

    func testALostAppAttestKeyIsReported() async throws {
        try registered()
        attester.assertionThrowsKeyLost = true

        let outcome = await client().requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "did:key:unit")

        guard case .failed(let error) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(error.code, ErrorCodes.walletUnitKeyLost)
    }

    // MARK: - Status

    func testStatusOfAnUnregisteredUnitNeedsNoRequest() async {
        let outcome = await client().status(withEvidence: true)

        guard case .notRegistered = outcome else { return XCTFail("\(outcome)") }
        XCTAssertEqual(server.nonceCount, 0)
    }

    func testStatusWithoutEvidenceIsSignedOnly() async throws {
        try registered()
        server.answers["/wallet-unit/status"] = [(200, #"{"status":"suspended","reason":"wallet_provider","revokedAt":null,"deviceCheckDue":true,"revocationCodeIssued":false}"#)]

        let outcome = await client().status(withEvidence: false)

        guard case .known(let status) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertTrue(status.isSuspended)
        XCTAssertEqual(status.reason, "wallet_provider")
        XCTAssertTrue(status.deviceCheckDue)
        XCTAssertFalse(status.revocationCodeIssued)
        let request = try XCTUnwrap(server.signed.last)
        try server.verify(request, with: try XCTUnwrap(keys.key))
        XCTAssertEqual(request.body, Data("{}".utf8))
        XCTAssertNil(request.headers["X-Wallet-Unit-Integrity-Token"])
        XCTAssertNil(request.headers["X-Wallet-Unit-KeyID"])
    }

    func testStatusWithEvidenceAssertsOverTheEmptyKeyList() async throws {
        try registered()
        server.answers["/wallet-unit/status"] = [(200, #"{"status":"active"}"#)]

        let outcome = await client().status(withEvidence: true)

        guard case .known(let status) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertTrue(status.isActive)
        XCTAssertTrue(status.revocationCodeIssued)
        XCTAssertEqual(server.signed.last?.headers["X-Wallet-Unit-KeyID"], "registered-key")
        let binding = BatchRequestHash.requestBinding(nonce: server.lastNonce, jwks: [])!
        XCTAssertEqual(attester.lastClientDataHash, BatchRequestHash.clientDataHash(binding: binding))
    }

    func testAnUnknownUnitMustRegisterAgain() async throws {
        try registered()
        server.answers["/wallet-unit/status"] = [(404, #"{"error":"invalid_client","error_id":"individual_wallet_unit.unit_not_found"}"#)]

        let outcome = await client().status(withEvidence: false)

        guard case .notRegistered = outcome else { return XCTFail("\(outcome)") }
        XCTAssertNil(attester.registeredKeyId)
    }

    func testAWalletProviderWithoutProtocol2IsNotSupported() async throws {
        try registered()
        server.answers["/wallet-unit/status"] = [(404, #"{"detail":"Not Found"}"#)]

        let outcome = await client().status(withEvidence: false)

        guard case .notSupported = outcome else { return XCTFail("\(outcome)") }
    }

    func testARevokedRefusalOfTheStatusReadIsAStatus() async throws {
        try registered()
        server.answers["/wallet-unit/status"] = [(403, #"{"error":"unauthorized_client","error_id":"individual_wallet_unit.revoked","reason":"key_compromise"}"#)]

        let outcome = await client().status(withEvidence: false)

        guard case .known(let status) = outcome else { return XCTFail("\(outcome)") }
        XCTAssertTrue(status.isRevoked)
        XCTAssertEqual(status.reason, "key_compromise")
    }

    // MARK: - Revocation code

    func testTheRevocationCodeIsIssuedOnce() async throws {
        try registered()
        server.answers["/wallet-unit/revocation-code"] = [
            (201, #"{"revocationCode":"Q8ZD 2MXK 7HTA W0RN 5CEB"}"#),
            (409, #"{"error":"invalid_request","error_id":"individual_wallet_unit.revocation_code_exists"}"#)
        ]
        let client = client()

        let first = await client.revocationCode()
        let second = await client.revocationCode()

        guard case .issued(let code) = first else { return XCTFail("\(first)") }
        XCTAssertEqual(code, "Q8ZD 2MXK 7HTA W0RN 5CEB")
        guard case .alreadyIssued = second else { return XCTFail("\(second)") }
        XCTAssertNil(server.signed.first?.headers["X-Wallet-Unit-Integrity-Token"])
    }

    // MARK: - Key attestation

    func testKeyAttestationUsesTheIssuerNonceAndAssertsOverTheAttestedKeys() async throws {
        try registered()
        server.answers["/key-attestation"] = [(200, #"{"keyAttestation":"ka.jwt"}"#)]
        let attested = StubKeyHandler().publicJWK

        let result = await client().keyAttestation(body: ["attested_keys": [attested]], cNonce: "issuer-nonce",
                                                   attestedKeys: [attested],
                                                   headers: ["OAuth-Client-Attestation": "wia.jwt"])

        guard case .success = result else { return XCTFail("\(result)") }
        XCTAssertEqual(server.nonceCount, 0)
        let request = try XCTUnwrap(server.signed.last)
        try server.verify(request, with: try XCTUnwrap(keys.key))
        XCTAssertEqual(request.headers["X-Wallet-Unit-Nonce"], "issuer-nonce")
        XCTAssertEqual(request.headers["OAuth-Client-Attestation"], "wia.jwt")
        let binding = BatchRequestHash.requestBinding(nonce: "issuer-nonce", jwks: [attested])!
        XCTAssertEqual(attester.lastClientDataHash, BatchRequestHash.clientDataHash(binding: binding))
    }

    func testTheKeyAttestationServiceSendsProtocol2ForARegisteredUnit() async throws {
        try registered()
        server.answers["/key-attestation"] = [(200, #"{"keyAttestation":"ka.jwt","attestationType":"ios_app_attest","attestedKeysCount":1}"#)]
        let attested = StubKeyHandler().publicJWK

        let outcome = await KeyAttestationService.requestBatchKeyAttestation(
            baseUrl: "https://wp.example/organisation/org-1/service",
            walletUnitAttestationJWT: "wia.jwt~",
            walletUnitProofOfPossession: "pop.jwt",
            nonce: "issuer-nonce",
            attestedKeys: [attested],
            iosAppAttest: [IosAppAttestEvidence(attestationObject: "att", keyId: "kid")],
            walletProvider: client()
        )

        XCTAssertTrue(outcome.isSuccessful)
        XCTAssertEqual(outcome.response?.keyAttestation, "ka.jwt")
        let request = try XCTUnwrap(server.signed.last)
        try server.verify(request, with: try XCTUnwrap(keys.key))
        XCTAssertEqual(request.headers["OAuth-Client-Attestation"], "wia.jwt")
        XCTAssertEqual(request.headers["OAuth-Client-Attestation-PoP"], "pop.jwt")
        XCTAssertEqual(request.headers["X-Wallet-Unit-Nonce"], "issuer-nonce")
        XCTAssertEqual(request.headers["X-Wallet-Unit-KeyID"], "registered-key")
        // The body is unchanged: the per-key App Attest evidence stays.
        let body = try XCTUnwrap(request.json)
        XCTAssertNotNil(body["ios_app_attest"])
        XCTAssertNotNil(body["attested_keys"])
    }

    func testARefusedProtocol2KeyAttestationKeepsTheErrorId() async throws {
        try registered()
        server.answers["/key-attestation"] = [(403, #"{"error":"unauthorized_client","error_id":"individual_wallet_unit.device_refused","reason":"properties_changed"}"#)]

        let outcome = await KeyAttestationService.requestBatchKeyAttestation(
            baseUrl: "https://wp.example/organisation/org-1/service",
            walletUnitAttestationJWT: "wia.jwt", walletUnitProofOfPossession: "pop.jwt",
            nonce: "issuer-nonce", attestedKeys: [StubKeyHandler().publicJWK], walletProvider: client()
        )

        XCTAssertFalse(outcome.isSuccessful)
        XCTAssertEqual(outcome.httpCode, 403)
        XCTAssertEqual(outcome.error?.errorId, WalletProviderErrorId.deviceRefused)
        XCTAssertEqual(outcome.error?.reason, "properties_changed")
    }

    // MARK: - Logging

    func testTheRevocationCodeIsNeverLogged() {
        let body = #"{"walletUnitAttestation":"wia.jwt","revocationCode" : "ABCD-EFGH-1234","credentialIssuer":"x"}"#
        let logged = NetworkLogger.hidingSecrets(body)
        XCTAssertFalse(logged.contains("ABCD-EFGH-1234"))
        XCTAssertTrue(logged.contains(#""revocationCode":"<hidden>""#))
        XCTAssertTrue(logged.contains(#""walletUnitAttestation":"wia.jwt""#))
    }

    // MARK: - App Attest errors

    func testAnAssertionKeyGoneAfterAReinstallIsALostKey() {
        // App Attest answers invalidInput for a key id it no longer has.
        XCTAssertTrue(AppAttestRetry.isLostAssertionKey(DCError(.invalidInput)))
        XCTAssertTrue(AppAttestRetry.isLostAssertionKey(DCError(.invalidKey)))
        XCTAssertFalse(AppAttestRetry.isLostAssertionKey(DCError(.serverUnavailable)))
        XCTAssertFalse(AppAttestRetry.isLostAssertionKey(URLError(.notConnectedToInternet)))
    }

    // MARK: - Address

    func testTheBaseAddressAlwaysEndsInWalletProvider() async {
        XCTAssertEqual(WalletProviderClient.walletProviderBase("https://wp.example/o/1/service"), "https://wp.example/o/1/service/wallet-provider")
        XCTAssertEqual(WalletProviderClient.walletProviderBase("https://wp.example/o/1/service/wallet-provider/"), "https://wp.example/o/1/service/wallet-provider")
    }
}

// MARK: - Fakes

private final class FakeRequestKeys: WalletUnitRequestKeys {
    var key: SoftwareRequestKey?
    var makeCount = 0

    func current() -> RequestSigningKey? { key }

    func make() throws -> RequestSigningKey {
        makeCount += 1
        let made = SoftwareRequestKey(privateKey: P256.Signing.PrivateKey())
        key = made
        return made
    }

    func remove() { key = nil }
}

private final class FakeAttester: WalletUnitAttester {
    var registeredKeyId: String?
    var attestCount = 0
    var assertCount = 0
    var lastClientDataHash: Data?
    var assertionThrowsKeyLost = false

    func attestation(clientDataHash: Data) async throws -> (attestation: Data, keyId: String) {
        attestCount += 1
        lastClientDataHash = clientDataHash
        return (Data("attestation-\(attestCount)".utf8), "key-\(attestCount)")
    }

    func assertion(keyId: String, clientDataHash: Data) async throws -> Data {
        if assertionThrowsKeyLost { throw WalletUnitAttesterError.keyLost }
        assertCount += 1
        lastClientDataHash = clientDataHash
        return Data("assertion-\(assertCount)".utf8)
    }

    func markRegistered(keyId: String) { registeredKeyId = keyId }

    func reset() { registeredKeyId = nil }
}

/// A wallet provider that hands out nonces, answers each route from a queue,
/// and records every signed request.
private final class StubWalletProvider {

    struct SignedRequest {
        let url: String
        let headers: [String: String]
        let body: Data

        var json: [String: Any]? { try? JSONSerialization.jsonObject(with: body) as? [String: Any] }

        var params: String { String(headers["Signature-Input"]?.dropFirst("wp=".count) ?? "") }

        var components: [String] {
            let list = params.split(separator: ")").first.map(String.init) ?? ""
            return list.dropFirst().split(separator: " ").map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "\"")) }
        }

        var keyId: String? {
            params.components(separatedBy: "keyid=\"").dropFirst().first?.components(separatedBy: "\"").first
        }
    }

    var answers: [String: [(Int, String)]] = [:]
    var nonceBody: String?
    private(set) var nonceCount = 0
    private(set) var lastNonce = ""
    private(set) var signed: [SignedRequest] = []

    func handle(_ request: URLRequest) throws -> (HTTPURLResponse, Data) {
        let url = request.url!
        let path = url.path.components(separatedBy: "/wallet-provider").last ?? ""
        if path == "/nonce" {
            nonceCount += 1
            lastNonce = "n+\(nonceCount)/=="
            return reply(url, 200, nonceBody ?? #"{"nonce":"\#(lastNonce)","c_nonce":"\#(lastNonce)"}"#)
        }
        let headers = request.allHTTPHeaderFields ?? [:]
        signed.append(SignedRequest(url: url.absoluteString, headers: headers, body: Self.body(of: request)))
        var queue = answers[path] ?? []
        guard !queue.isEmpty else { return reply(url, 404, #"{"detail":"Not Found"}"#) }
        let (status, body) = queue.removeFirst()
        answers[path] = queue
        return reply(url, status, body)
    }

    /// The wallet provider's checks: the digest of the body, the signature over
    /// the rebuilt base, and the keyid of the request key.
    func verify(_ request: SignedRequest, with key: RequestSigningKey) throws {
        XCTAssertEqual(request.headers["Content-Digest"], HTTPMessageSignature.contentDigest(body: request.body))
        XCTAssertEqual(request.keyId, key.keyId)
        let base = try XCTUnwrap(HTTPMessageSignature.signatureBase(
            method: "POST", targetURI: request.url, headers: request.headers,
            components: request.components, signatureParams: request.params))
        let signatureHeader = try XCTUnwrap(request.headers["Signature"])
        let raw = try XCTUnwrap(Data(base64Encoded: String(signatureHeader.dropFirst("wp=:".count).dropLast())))
        let jwk = key.publicJWK
        let publicKey = try P256.Signing.PublicKey(rawRepresentation:
            Data(base64URLEncoded: jwk["x"] as! String)! + Data(base64URLEncoded: jwk["y"] as! String)!)
        XCTAssertTrue(publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: raw), for: Data(base.utf8)))
    }

    private func reply(_ url: URL, _ status: Int, _ body: String) -> (HTTPURLResponse, Data) {
        (HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!,
         Data(body.utf8))
    }

    /// URLProtocol moves the body into a stream.
    private static func body(of request: URLRequest) -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            guard read > 0 else { break }
            data.append(buffer, count: read)
        }
        return data
    }
}
