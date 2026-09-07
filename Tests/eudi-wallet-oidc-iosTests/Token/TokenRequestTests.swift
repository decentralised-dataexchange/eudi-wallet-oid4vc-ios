//
//  TokenRequestTests.swift
//

import XCTest
import CryptoKit
@testable import eudiWalletOidcIos

/// The token request body and the answers it reads.
///
/// Several of these could not have passed before: the old implementation used
/// `URLSession.shared` inside `NetworkLogger`'s default, so the request could not be stubbed at all.
///
/// Mirrors `TokenRequestParametersTest` and `TokenRequestResolverTest` in the Android SDK.
final class TokenRequestTests: XCTestCase {

    override func tearDown() {
        StubURLProtocol.handler = nil
        super.tearDown()
    }

    // MARK: - Fixtures

    /// Built by decoding, because these models have no memberwise init.
    ///
    /// Note the key names: `CredentialOffer` and its children declare no `CodingKeys`, so they
    /// decode by **Swift property name** — the snake_case wire mapping lives in the separate
    /// `CredentialOfferResponse` types. An empty `txCode: {}` must survive as a non-nil object,
    /// which is precisely what section 6.1 keys the rule on.
    private func offer(version: String = "v2", txCode: String? = nil) -> CredentialOffer {
        let json = """
        {
          "credentialIssuer": "https://issuer.example.com",
          "version": "\(version)",
          "grants": {
            "urnIETFParamsOauthGrantTypePreAuthorizedCode": {
              "preAuthorizedCode": "pre-1"\(txCode.map { ", \"txCode\": \($0)" } ?? "")
            }
          }
        }
        """
        return try! JSONDecoder().decode(CredentialOffer.self, from: Data(json.utf8))
    }

    private func session(version: String = "v2", txCode: String? = nil) -> IssuanceSession {
        var authConfig = AuthorisationServerWellKnownConfiguration()
        authConfig.tokenEndpoint = "https://as.example.com/token"
        return IssuanceSession(
            credentialOffer: offer(version: version, txCode: txCode),
            issuerConfig: nil,
            authConfig: authConfig
        )
    }

    private func attestationWithKey() -> WalletAttestation {
        WalletAttestation(
            attestationJwt: nil,
            proofOfPossession: nil,
            dpopKey: P256.Signing.PrivateKey()
        )
    }

    private func resolve(
        grant: TokenGrant = .preAuthorized(code: "pre-1"),
        session: IssuanceSession? = nil,
        attestation: WalletAttestation? = nil
    ) async -> TokenResponse {
        await TokenRequestResolver().resolve(
            session: session ?? self.session(),
            wallet: WalletIdentity(did: "did:key:zabc"),
            attestation: attestation,
            grant: grant,
            urlSession: StubURLProtocol.session()
        )
    }

    private func body(
        grant: TokenGrant,
        session: IssuanceSession? = nil,
        policy: TokenRequestPolicy = .standard
    ) -> [String: String] {
        TokenRequestParameters.build(
            session: session ?? self.session(),
            wallet: WalletIdentity(did: "did:key:zabc"),
            attestation: nil,
            grant: grant,
            authorizationDetails: "[{\"type\":\"openid_credential\"}]",
            policy: policy
        ).asDictionary()
    }

    // MARK: - The body

    func testThePreAuthorizedGrantNamesTheCodeAsPreAuthorizedCode() {
        let out = body(grant: .preAuthorized(code: "pre-1"))

        XCTAssertEqual(out["grant_type"], TokenGrant.preAuthorizedGrantType)
        XCTAssertEqual(out["pre-authorized_code"], "pre-1")
        XCTAssertNil(out["code"])
        // Section 6.1: client authentication is OPTIONAL for this grant.
        XCTAssertNil(out["client_id"])
    }

    func testTheAuthorizationCodeGrantSendsTheCodeVerifierAndRedirect() {
        let out = body(grant: .authorizationCode(
            code: "abc", codeVerifier: "verifier", redirectUri: "datawallet://callback"
        ))

        XCTAssertEqual(out["grant_type"], TokenGrant.authorizationCodeGrantType)
        XCTAssertEqual(out["code"], "abc")
        XCTAssertEqual(out["code_verifier"], "verifier")
        XCTAssertEqual(out["redirect_uri"], "datawallet://callback")
        XCTAssertNil(out["pre-authorized_code"])
    }

    /// The old implementation sent `user_pin: ""` on the draft branch when no code was supplied.
    func testBlankValuesAreOmittedRatherThanSentEmpty() {
        let out = body(grant: .authorizationCode(code: "abc", codeVerifier: nil, redirectUri: nil))

        XCTAssertNil(out["code_verifier"])
        XCTAssertNil(out["redirect_uri"])

        let preAuth = body(grant: .preAuthorized(code: "pre-1", txCode: ""))
        XCTAssertNil(preAuth["tx_code"])
        XCTAssertNil(preAuth["user_pin"])
    }

    /// 1.0 calls it `tx_code`; the pre-1.0 drafts called it `user_pin`.
    func testTheTransactionCodeParameterIsNamedForTheOffersRevision() {
        let draft = body(grant: .preAuthorized(code: "pre-1", txCode: "1234"), session: session(version: "v1"))
        XCTAssertEqual(draft["user_pin"], "1234")
        XCTAssertNil(draft["tx_code"])

        let v1_0 = body(grant: .preAuthorized(code: "pre-1", txCode: "1234"))
        XCTAssertEqual(v1_0["tx_code"], "1234")
        XCTAssertNil(v1_0["user_pin"])
    }

    /// An unrecognised version used to POST an empty body with no `grant_type` at all.
    func testAnUnrecognisedVersionStillSendsAGrantType() {
        let out = body(grant: .preAuthorized(code: "pre-1", txCode: "1234"), session: session(version: "v9"))

        XCTAssertEqual(out["grant_type"], TokenGrant.preAuthorizedGrantType)
        XCTAssertEqual(out["pre-authorized_code"], "pre-1")
        // Anything that is not the draft gets the 1.0 name, as Android does.
        XCTAssertEqual(out["tx_code"], "1234")
    }

    /// Section 6.1: required "including if the object was empty".
    func testAnEmptyTxCodeObjectStillObligesTheWalletToSendOne() {
        // An empty object is still an obligation.
        XCTAssertTrue(session(txCode: "{}").requiresTransactionCode)
        XCTAssertTrue(session(txCode: #"{"length": 4, "input_mode": "numeric"}"#).requiresTransactionCode)
        XCTAssertFalse(session(txCode: nil).requiresTransactionCode)
    }

    // MARK: - The exchange

    func testAnAccessTokenIsReturned() async {
        StubURLProtocol.respond(body: #"{"access_token":"at-1","token_type":"bearer"}"#)

        let result = await resolve()

        XCTAssertEqual(result.accessToken, "at-1")
        XCTAssertNil(result.error)
    }

    /// The status and the OAuth code both used to be lost before the caller saw them.
    func testARejectionReportsTheOauthCodeTheDescriptionAndTheStatus() async {
        StubURLProtocol.respond(
            status: 400,
            body: #"{"error":"invalid_grant","error_description":"PIN is wrong"}"#
        )

        let result = await resolve()

        XCTAssertEqual(result.error?.errorCode, "invalid_grant")
        XCTAssertEqual(result.error?.message, "PIN is wrong")
        XCTAssertEqual(result.error?.httpStatus, 400)
        XCTAssertNil(result.accessToken)
    }

    /// A 4xx with an empty body used to fall into the success branch and be JSON-decoded.
    func testAnEmptyErrorBodyIsStillAFailure() async {
        StubURLProtocol.respond(status: 400, contentType: nil, body: "")

        let result = await resolve()

        XCTAssertNil(result.accessToken)
        XCTAssertNotNil(result.error)
        XCTAssertEqual(result.error?.httpStatus, 400)
    }

    /// Section 6.1: failing here saves spending a one-time code on a request that cannot succeed.
    func testAMissingTransactionCodeFailsBeforeTheRequestIsMade() async {
        let result = await resolve(session: session(txCode: "{}"))

        XCTAssertTrue(result.error?.message?.contains("transaction code") == true)
    }

    /// RFC 9449 section 8: 400 + use_dpop_nonce + a DPoP-Nonce header. Exactly once.
    func testADPoPNonceChallengeIsRetriedOnce() async {
        var responses = 0
        StubURLProtocol.handler = { request in
            responses += 1
            let headers = responses == 1
                ? ["DPoP-Nonce": "nonce-1", "Content-Type": "application/json"]
                : ["Content-Type": "application/json"]
            let status = responses == 1 ? 400 : 200
            let body = responses == 1 ? #"{"error":"use_dpop_nonce"}"# : #"{"access_token":"at-2"}"#
            let response = HTTPURLResponse(
                url: request.url!, statusCode: status, httpVersion: nil, headerFields: headers
            )!
            return (response, Data(body.utf8))
        }

        let result = await resolve(attestation: attestationWithKey())

        XCTAssertEqual(responses, 2)
        XCTAssertEqual(result.accessToken, "at-2")
    }

    func testASecondNonceChallengeGivesUpRatherThanLooping() async {
        var responses = 0
        StubURLProtocol.handler = { request in
            responses += 1
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 400,
                httpVersion: nil,
                headerFields: ["DPoP-Nonce": "nonce-\(responses)", "Content-Type": "application/json"]
            )!
            return (response, Data(#"{"error":"use_dpop_nonce"}"#.utf8))
        }

        let result = await resolve(attestation: attestationWithKey())

        XCTAssertEqual(responses, 2)
        XCTAssertEqual(result.error?.errorCode, "use_dpop_nonce")
    }

    /// RFC 9449 section 8.2: a nonce can rotate on a success, and must be used from then on.
    func testANonceSuppliedOnASuccessIsCarriedBack() async {
        StubURLProtocol.handler = { request in
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: ["DPoP-Nonce": "nonce-next", "Content-Type": "application/json"]
            )!
            return (response, Data(#"{"access_token":"at-3"}"#.utf8))
        }

        let result = await resolve(attestation: attestationWithKey())

        XCTAssertEqual(result.dpopNonce, "nonce-next")
    }
}
