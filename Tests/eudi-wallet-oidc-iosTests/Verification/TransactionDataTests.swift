//
//  TransactionDataTests.swift
//  eudiWalletOidcIosTests
//

import XCTest
import CryptoKit
@testable import eudiWalletOidcIos

/// Leg 6, transaction data and SCA: the rows of the case matrix in `VERIFICATION_REVAMP_PLAN_IOS.md`,
/// numbered as there. Case names follow the Android SDK's `TransactionDataTest`.
final class TransactionDataTests: ResponseCharacterisationTestCase {

    private typealias F = VerificationFixtures

    private func entry(_ object: [String: Any]) -> String { Data(F.json(object).utf8).b64url }

    private func invalid(_ block: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try block(), file: file, line: line) { error in
            XCTAssertTrue(error is TransactionDataRules.InvalidTransactionData, "\(error)", file: file, line: line)
        }
    }

    func test6_1And6_2EveryEntryNamingTheIdIsHashedInOrderAndOnlyThose() throws {
        let first = F.transactionData("urn:eudi:sca:payment", "pid")
        let other = F.transactionData("urn:eudi:sca:payment", "mdl")
        let second = F.transactionData("urn:eudi:sca:emandate", "pid", "mdl")
        let request = F.dcqlRequest(F.dcqlSdJwt("pid"), F.dcqlMdoc("mdl"), transactionData: [first, other, second])

        let hashes = try TransactionDataRules.hashesByEntry(try TransactionDataRules.entries(request))
        XCTAssertEqual(hashes["pid"], TransactionDataHashes(algorithm: "sha-256", hashes: [F.sha256(first), F.sha256(second)]))
        XCTAssertEqual(hashes["mdl"]?.hashes, [F.sha256(other), F.sha256(second)])
    }

    func test6_4AnIdTheQueryDoesNotRequestIsInvalid() {
        let request = F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [F.transactionData("urn:eudi:sca:payment", "pid", "nobody")])
        invalid { _ = try TransactionDataRules.entries(request) }
    }

    func test6_5AMalformedEntryOrOneMissingTypeOrCredentialIdsIsInvalid() {
        for value in ["not base64url!", entry(["credential_ids": ["pid"]]), entry(["type": "urn:eudi:sca:payment"]),
                      entry(["type": "urn:eudi:sca:payment", "credential_ids": []])] {
            invalid { _ = try TransactionDataRules.entries(F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [value])) }
        }
    }

    func test6_6TransactionDataHashesAlgSelectsAndEchoesTheAlgorithm() throws {
        let sha512 = entry(["type": "urn:eudi:sca:payment", "credential_ids": ["pid"], "transaction_data_hashes_alg": ["sha-512", "sha-384"]])
        let request = F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [sha512])
        let hashes = try XCTUnwrap(try TransactionDataRules.hashes(try TransactionDataRules.entries(request), entryId: "pid"))
        XCTAssertEqual(hashes.algorithm, "sha-384", "the first supported one in the SDK's preference order")
        XCTAssertEqual(hashes.hashes, [Data(SHA384.hash(data: Data(sha512.utf8))).b64url])

        let unknown = entry(["type": "urn:eudi:sca:payment", "credential_ids": ["pid"], "transaction_data_hashes_alg": ["md5"]])
        invalid { _ = try TransactionDataRules.entries(F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [unknown])) }

        // An entry naming no algorithm allows only sha-256, so it and a sha-512-only entry share none.
        let plain = F.transactionData("urn:eudi:sca:payment", "pid")
        let only512 = entry(["type": "urn:eudi:sca:payment", "credential_ids": ["pid"], "transaction_data_hashes_alg": "sha-512"])
        let entries = try TransactionDataRules.entries(F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [plain, only512]))
        invalid { _ = try TransactionDataRules.hashes(entries, entryId: "pid") }
    }

    func test6_6TheChosenAlgorithmReachesTheKeyBindingJwt() async throws {
        let sha384 = entry(["type": "urn:eudi:sca:payment", "credential_ids": ["pid"], "transaction_data_hashes_alg": ["sha-384"]])
        let params = await respond(F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [sha384]), [[F.sdJwt()]])
        let presented = try XCTUnwrap((F.object(params?["vp_token"]) as? [String: Any])?["pid"] as? [String]).first ?? ""
        XCTAssertEqual(JWTParts.claims(F.keyBindingJwt(presented))?["transaction_data_hashes_alg"] as? String, "sha-384")
    }

    func test6_8ScaIsDetectedFromAnyEntryAndNotFromPaymentData() throws {
        let payment = F.transactionData("payment_data", "pid")
        let sca = F.transactionData("https://example.com/transaction-data-type/login_risk", "pid")
        XCTAssertFalse(StrongCustomerAuthentication.requested(try TransactionDataRules.entries(F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [payment]))))
        XCTAssertTrue(StrongCustomerAuthentication.requested(try TransactionDataRules.entries(F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [payment, sca]))))
        XCTAssertFalse(StrongCustomerAuthentication.isScaType("http://uri.etsi.org/19560/qes"))
    }

    func test6_9TransactionDataOnACredentialRequestedWithoutHolderBindingIsInvalid() {
        let unbound = CredentialItems(id: "pid", format: "dc+sd-jwt", meta: .dcSDJWT(DCSDJWTMeta(vctValues: [F.vct])), claims: [],
                                      multiple: nil, claimSets: nil, requireCryptographicHolderBinding: false)
        invalid { _ = try TransactionDataRules.entries(F.dcqlRequest(unbound, transactionData: [F.transactionData("urn:eudi:sca:payment", "pid")])) }
    }

    func test6_10ThePresentationDefinitionPathHashesByInputDescriptorId() throws {
        let value = F.transactionData("urn:eudi:sca:payment", "pid")
        let hashes = try TransactionDataRules.hashesByEntry(try TransactionDataRules.entries(F.pexRequest(F.sdJwtDescriptor("pid"), transactionData: [value])))
        XCTAssertEqual(hashes["pid"]?.hashes, [F.sha256(value)])
    }

    func test6_14UnrecognisedTypesAreRefusedOnlyWhenTheHostListsTheTypesItKnows() throws {
        let request = F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: [F.transactionData("urn:eudi:sca:payment", "pid")])
        XCTAssertEqual(try TransactionDataRules.entries(request).count, 1)
        XCTAssertEqual(try TransactionDataRules.entries(request, recognisedTypes: ["urn:eudi:sca:payment"]).count, 1)
        invalid { _ = try TransactionDataRules.entries(request, recognisedTypes: ["payment_data"]) }
    }

    // MARK: Resolver and submitter

    private let clientId = "redirect_uri:https://verifier.example/response"
    private var dcql: String {
        F.json(["credentials": [["id": "pid", "format": "dc+sd-jwt", "meta": ["vct_values": ["urn:eudi:pid:1"]],
                                 "claims": [["path": ["family_name"]]]]]])
    }

    private func byValue(_ transactionData: String) -> String {
        let params = [("client_id", clientId), ("response_type", "vp_token"), ("response_mode", "direct_post"),
                      ("nonce", "n-1"), ("dcql_query", dcql), ("transaction_data", transactionData)]
        return "openid4vp://?" + params.map { "\($0.0)=\($0.1.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? $0.1)" }
            .joined(separator: "&")
    }

    func test6_12And6_13TheResolverReadsByValueTransactionDataCarriesTheEntriesAndRefusesInvalidOnes() async throws {
        let value = F.transactionData("urn:eudi:sca:payment", "pid")
        let resolver = PresentationRequestResolver(session: StubURLProtocol.session())

        guard case .resolved(let resolved) = await resolver.resolve(byValue(F.json([value]))) else { return XCTFail("expected resolved") }
        XCTAssertEqual(resolved.request.transactionData, [value])
        XCTAssertEqual(resolved.transactionData.map { $0.type }, ["urn:eudi:sca:payment"])

        guard case .failed(let error) = await resolver.resolve(byValue(F.json([F.transactionData("urn:eudi:sca:payment", "nobody")]))) else {
            return XCTFail("expected failed")
        }
        XCTAssertEqual(error.errorCode, "invalid_transaction_data")

        guard case .failed(let unreadable) = await resolver.resolve(byValue("not a JSON array")) else { return XCTFail("expected failed") }
        XCTAssertEqual(unreadable.errorCode, "invalid_transaction_data")
    }

    func testTheSubmitterRefusesInvalidTransactionDataWithInvalidTransactionData() async {
        let request = F.dcqlRequest(F.dcqlSdJwt("pid"), transactionData: ["not base64url!"])
        let outcome = await PresentationSubmitter().submit(request, selected: [SelectedCredential(entryId: "pid", credential: F.sdJwt(), keyId: "holder")],
                                                           identity: WalletIdentity(did: F.did), holderKey: walletKeyHandler,
                                                           attestation: nil, authentication: nil)
        guard case .refused(let error) = outcome else { return XCTFail("expected refused") }
        XCTAssertEqual(error.errorCode, "invalid_transaction_data")
    }
}
