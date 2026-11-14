//
//  Protocol1WalletProviderClientTests.swift
//  eudi-wallet-oidc-iosTests
//
//  The protocol 1 client behind the provider interface: the old service's
//  answers become outcomes, and protocol 2 only requests answer notSupported.
//

import XCTest
@testable import eudiWalletOidcIos

final class Protocol1WalletProviderClientTests: XCTestCase {

    private var fake: FakeProtocol1Service!
    private var client: Protocol1WalletProviderClient!

    override func setUp() {
        super.setUp()
        fake = FakeProtocol1Service()
        let fake = fake!
        client = Protocol1WalletProviderClient(baseUrl: "https://wp.example/o/1/service", service: { fake })
    }

    // MARK: - Single

    func testASingleWiaComesBackAndGoesToTheGivenAddress() async throws {
        fake.single = .success(WalletUnitAttestationResponse(credentialOffer: nil, walletUnitAttestation: "wia.jwt", credentialIssuer: "https://issuer"))
        let key = StubKeyHandler()

        let outcome = await client.requestWalletUnitAttestation(cnfKey: key, clientId: "did:key:z1", profile: "ts3")

        guard case .success(let response) = outcome else { return XCTFail("expected success, got \(outcome)") }
        XCTAssertEqual(response.walletUnitAttestation, "wia.jwt")
        XCTAssertNil(response.revocationCode)
        XCTAssertEqual(fake.calls, ["single https://wp.example/o/1/service ts3"])
        XCTAssertTrue(fake.lastKey === key)
    }

    func testAnEmptyAnswerOrAThrowIsARequestFailureWithoutErrorId() async {
        fake.single = .success(WalletUnitAttestationResponse(credentialOffer: nil, walletUnitAttestation: "", credentialIssuer: nil))
        assertFailed(await client.requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "c", profile: nil))

        fake.single = .failure(URLError(.notConnectedToInternet))
        assertFailed(await client.requestWalletUnitAttestation(cnfKey: StubKeyHandler(), clientId: "c", profile: nil))
    }

    // MARK: - Batch

    func testABatchPassesTheClientIdAndComesBack() async {
        fake.batch = batchResult(httpCode: 200, wias: ["a", "b"])

        let outcome = await client.requestWalletUnitAttestations(cnfKeys: [StubKeyHandler(), StubKeyHandler()], clientId: "did:key:z1", profile: "ts3")

        guard case .success(let result) = outcome else { return XCTFail("expected success, got \(outcome)") }
        XCTAssertEqual(result.units.map(\.walletUnitAttestation), ["a", "b"])
        XCTAssertEqual(fake.calls, ["batch https://wp.example/o/1/service ts3 did:key:z1 keys=2"])
    }

    func testARefusedBatchKeepsItsHttpStatusSoTheAppCanFallBack() async {
        fake.batch = batchResult(httpCode: 404, wias: [nil])

        let outcome = await client.requestWalletUnitAttestations(cnfKeys: [StubKeyHandler()], clientId: "c", profile: nil)

        guard case .failed(let error) = outcome else { return XCTFail("expected failed, got \(outcome)") }
        XCTAssertEqual(error.httpStatus, 404)
        XCTAssertNil(error.errorId)
        XCTAssertEqual(error.code, ErrorCodes.walletProviderRequestFailed)
    }

    func testABatchThatCouldNotBeMadeFails() async {
        fake.batch = nil
        assertFailed(await client.requestWalletUnitAttestations(cnfKeys: [StubKeyHandler()], clientId: "c", profile: nil))
    }

    // MARK: - Protocol 2 only

    func testStatusAndRevocationCodeAreNotSupported() async {
        guard case .notSupported = await client.status(withEvidence: true) else { return XCTFail("status") }
        guard case .notSupported = await client.revocationCode() else { return XCTFail("revocation code") }
        let keyLost = await client.isKeyLost
        XCTAssertFalse(keyLost)
    }

    func testKeyAttestationWithAProtocol1ClientGoesAsBefore() async {
        // The old route: plain POST to {base}/wallet-provider/key-attestation,
        // which here cannot be reached, so the outcome is a transport failure
        // and nothing was signed.
        let outcome = await KeyAttestationService.requestBatchKeyAttestation(
            baseUrl: "https://wp.invalid/o/1/service",
            walletUnitAttestationJWT: "wia.jwt", walletUnitProofOfPossession: "pop.jwt",
            nonce: "n", attestedKeys: [StubKeyHandler().publicJWK], walletProvider: client
        )
        XCTAssertFalse(outcome.isSuccessful)
        XCTAssertNil(outcome.error, "the protocol 2 path sets error; the old one does not")
    }

    // MARK: - Helpers

    private func assertFailed<T>(_ outcome: WalletProviderOutcome<T>, file: StaticString = #filePath, line: UInt = #line) {
        guard case .failed(let error) = outcome else { return XCTFail("expected failed, got \(outcome)", file: file, line: line) }
        XCTAssertNil(error.errorId, file: file, line: line)
        XCTAssertEqual(error.code, ErrorCodes.walletProviderRequestFailed, file: file, line: line)
    }

    private func batchResult(httpCode: Int?, wias: [String?]) -> BatchWalletAttestationResult {
        BatchWalletAttestationResult(
            clientId: "c", requestHash: nil, httpCode: httpCode, errorBody: nil,
            credentialOffer: nil, credentialIssuer: nil,
            units: wias.enumerated().map { index, wia in
                BatchWalletUnit(index: index, did: "did:\(index)", keyHandler: StubKeyHandler(),
                                clientAssertion: "ca", walletUnitAttestation: wia)
            }
        )
    }
}

private final class FakeProtocol1Service: Protocol1WalletUnitAttestation {
    var single: Result<WalletUnitAttestationResponse, Error> = .failure(URLError(.badURL))
    var batch: BatchWalletAttestationResult?
    var calls: [String] = []
    var lastKey: SecureKeyProtocol?

    func initiateWalletUnitAttestation(walletProviderUrl: String, profile: String?, keyHandler: SecureKeyProtocol?) async throws -> (String, WalletUnitAttestationResponse?) {
        calls.append("single \(walletProviderUrl) \(profile ?? "-")")
        lastKey = keyHandler
        return ("assertion", try single.get())
    }

    func initiateBatchWalletUnitAttestation(walletProviderUrl: String, keyHandlers: [SecureKeyProtocol], profile: String?, clientId: String?) async -> BatchWalletAttestationResult? {
        calls.append("batch \(walletProviderUrl) \(profile ?? "-") \(clientId ?? "-") keys=\(keyHandlers.count)")
        return batch
    }
}
