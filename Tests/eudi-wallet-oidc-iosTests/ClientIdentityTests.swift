import XCTest
@testable import eudiWalletOidcIos

final class ClientIdentityTests: XCTestCase {

    let walletId = "did:key:zWalletUnit"

    func testAnonymousPreAuthorizedAccessHasNoClientIdentity() {
        XCTAssertNil(IssueService.clientIdentity(isPreAuthorisedCodeFlow: true, preAuthorizedGrantAnonymousAccessSupported: true, version: "v2", clientId: walletId))
    }

    func testPreAuthorizedWithoutTheFlagOrWithItFalseUsesTheWalletIdentity() {
        XCTAssertEqual(IssueService.clientIdentity(isPreAuthorisedCodeFlow: true, preAuthorizedGrantAnonymousAccessSupported: nil, version: "v2", clientId: walletId), walletId)
        XCTAssertEqual(IssueService.clientIdentity(isPreAuthorisedCodeFlow: true, preAuthorizedGrantAnonymousAccessSupported: false, version: "v2", clientId: walletId), walletId)
    }

    func testAuthorizationCodeAlwaysUsesTheWalletIdentity() {
        XCTAssertEqual(IssueService.clientIdentity(isPreAuthorisedCodeFlow: false, preAuthorizedGrantAnonymousAccessSupported: true, version: "v2", clientId: walletId), walletId)
    }

    func testDraftPreAuthorizedOffersSendNoClientIdAsBefore() {
        XCTAssertNil(IssueService.clientIdentity(isPreAuthorisedCodeFlow: true, preAuthorizedGrantAnonymousAccessSupported: nil, version: "v1", clientId: walletId))
    }

    // MARK: - the proof's iss

    private func proofClaims(issuer: String?) async throws -> [String: Any] {
        let offer = try JSONDecoder().decode(CredentialOffer.self, from: Data("{}".utf8))
        let config = try JSONDecoder().decode(IssuerWellKnownConfiguration.self, from: Data("{}".utf8))
        let jwt = await ProofService.generateProof(nonce: "nonce", credentialOffer: offer, issuerConfig: config, did: "did:key:zBindingKey", issuer: issuer, keyHandler: CryptoKitHandler(), credentialTypes: [])
        let segment = try XCTUnwrap(jwt?.split(separator: ".").dropFirst().first)
        var base64 = segment.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        let data = try XCTUnwrap(Data(base64Encoded: base64))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    func testIssCanDifferFromTheDidTheProofIsBoundWith() async throws {
        let claims = try await proofClaims(issuer: walletId)
        XCTAssertEqual(claims["iss"] as? String, walletId)
    }

    func testANilIssuerOmitsIss() async throws {
        let claims = try await proofClaims(issuer: nil)
        XCTAssertNil(claims["iss"])
    }
    // MARK: - the proof's iss, for issuance and reissuance

    private func offer(preAuthorised: Bool, version: String) throws -> CredentialOffer {
        let grants = preAuthorised ? #","grants":{"urnIETFParamsOauthGrantTypePreAuthorizedCode":{"preAuthorizedCode":"code"}}"# : ""
        var offer = try JSONDecoder().decode(CredentialOffer.self, from: Data("{\"credentialIssuer\":\"https://issuer.example\"\(grants)}".utf8))
        offer.version = version
        return offer
    }

    func testTheProofOmitsIssForAnAnonymousPreAuthorizedGrant() throws {
        XCTAssertNil(IssueService.proofIssuer(credentialOffer: try offer(preAuthorised: true, version: "v2"), preAuthorizedGrantAnonymousAccessSupported: true, clientId: walletId, did: "did:key:zBinding"))
    }

    func testTheProofCarriesTheClientIdentityNotTheBindingDid() throws {
        XCTAssertEqual(IssueService.proofIssuer(credentialOffer: try offer(preAuthorised: true, version: "v2"), preAuthorizedGrantAnonymousAccessSupported: nil, clientId: walletId, did: "did:key:zBinding"), walletId)
        XCTAssertEqual(IssueService.proofIssuer(credentialOffer: try offer(preAuthorised: false, version: "v2"), preAuthorizedGrantAnonymousAccessSupported: true, clientId: walletId, did: "did:key:zBinding"), walletId)
    }

    func testTheProofKeepsTheDidForDraftPreAuthorizedOffersOrWithoutAClientIdentity() throws {
        XCTAssertEqual(IssueService.proofIssuer(credentialOffer: try offer(preAuthorised: true, version: "v1"), preAuthorizedGrantAnonymousAccessSupported: nil, clientId: walletId, did: "did:key:zBinding"), "did:key:zBinding")
        XCTAssertEqual(IssueService.proofIssuer(credentialOffer: try offer(preAuthorised: false, version: "v2"), preAuthorizedGrantAnonymousAccessSupported: nil, clientId: nil, did: "did:key:zBinding"), "did:key:zBinding")
    }
}
